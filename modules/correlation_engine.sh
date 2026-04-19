#!/bin/bash
# ============================================================================
# correlation_engine.sh — Module 6: Multi-signal correlation
# ============================================================================
# The correlation engine is what separates a good HIDS from a bad one.
# Individual modules alert on isolated events. Correlation finds patterns
# ACROSS events that together constitute a much stronger attack signal.
#
# Principle: "weak signals → strong alert"
#   - A process in /tmp alone         = WARNING (could be legitimate)
#   - Root uid alone                  = normal (root does things)
#   - EXECVE alone                    = normal (everything executes)
#   - All three together              = CRITICAL (classic post-exploitation)
#
# This is exactly what correlation rules in Wazuh, Splunk, and Sigma do.
#
# Why this file depends on auditd_parser.sh:
#   The old version checked for EXECVE + uid=0 + /tmp on individual lines
#   of audit.log. That never worked because auditd writes multi-line records —
#   each field lives on a different line. Pattern 1 was structurally broken.
#
#   auditd_parser.sh now assembles those multi-line records and writes ONE
#   structured line per event to raw_events.log:
#     ts|auditd|execve|uid=root|exe=/tmp/payload|cmd=./payload -c id|path=/tmp/payload
#   Pattern 1 below correctly matches against this format.
#
# Data source: logs/raw_events.log
#   Written by: process_network.sh, file_integrity.sh, user_activity.sh,
#               auditd_parser.sh (structured execve and perm_change events)
#
# ============================================================================

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"

RAW_LOG="$HIDS_DIR/logs/raw_events.log"

# If no event log exists yet, nothing to correlate
[[ -f "$RAW_LOG" ]] || exit 0

# Work with the last 100 events — enough to cover a few cycles' worth of
# activity without scanning unbounded log history on every run
recent=$(tail -n 100 "$RAW_LOG")

# ============================================================================
# Pattern 1 — Root execution from a writable staging path
# ============================================================================
# Classic post-exploitation signature:
#   1. Attacker drops a payload into /tmp, /dev/shm, or /var/tmp
#      (world-writable directories that survive reboots or not)
#   2. Sets execute permission
#   3. Runs it as root (via sudo, SUID, or a root-owned cronjob)
#
# Source: auditd|execve lines produced by auditd_parser.sh
# The structured format (one line per event) makes this check reliable —
# the old approach (grep individual audit.log lines) could never fire because
# uid=root, exe=, and the path were always on separate auditd records.
# ============================================================================
echo "$recent" | grep '|auditd|execve|' | while IFS='|' read -r _ _ _ uid_f exe_f _ _; do
  uid_val=$(echo "$uid_f" | grep -oP 'uid=\K.*')
  exe_val=$(echo "$exe_f" | grep -oP 'exe=\K.*')

  if [[ "$uid_val" == "root" || "$uid_val" == "0" ]] && \
     echo "$exe_val" | grep -qE '^(/tmp|/dev/shm|/var/tmp|/run/user)/'; then
    alert "CRITICAL" "correlation" \
      "Root execution from writable staging path: $exe_val"
  fi
done

# ============================================================================
# Pattern 2 — Reverse shell indicators
# ============================================================================
# A reverse shell or interactive shell connected to an outbound socket
# is one of the clearest signs of active compromise.
#
# Two complementary checks:
#   a) process_network.sh blocks 15/16 write shell_socket / interp_socket
#      events when a shell or interpreter is found with an active TCP socket
#   b) auditd_parser.sh writes execve lines whose cmd fields may contain
#      classic reverse shell invocation patterns (/dev/tcp, nc -e, etc.)
#
# Both checks together reduce false negatives from either approach alone.
# ============================================================================

# Check a: structured shell-with-socket events from process_network.sh
if echo "$recent" | grep -qE '\|(process|network)\|(shell_socket|interp_socket)\|'; then
  alert "CRITICAL" "correlation" \
    "Reverse shell indicator: shell or interpreter with active outbound socket"
fi

# Check b: reverse shell command patterns in auditd execve records
if echo "$recent" | grep '|auditd|execve|' | grep -qP 'cmd=.*(bash\s+-i|/dev/tcp|nc\s+-e|ncat\s+-e|socat\s+)'; then
  alert "CRITICAL" "correlation" \
    "Reverse shell command pattern in kernel exec log (bash -i, /dev/tcp, nc -e...)"
fi

# ============================================================================
# Pattern 3 — Download then execute from /tmp
# ============================================================================
# Attackers commonly:
#   1. Use wget or curl to fetch a payload
#   2. Save it to /tmp (or equivalent writable directory)
#   3. Execute it
#
# Seeing a download event and a suspicious-path execution event in the same
# recent window is a weak-signal combination worth escalating.
# ============================================================================
# Look for wget/curl in auditd execve records (user_activity tracks auth, not execs)
has_download=$(echo "$recent" | grep -cE 'auditd\|execve\|.*cmd=.*(wget|curl)')
has_tmp_exec=$(echo "$recent" | grep -cE '\|(process|auditd)\|(suspicious_path|execve)\|.*(exe|path)=/tmp')

if (( has_download > 0 )) && (( has_tmp_exec > 0 )); then
  alert "WARNING" "correlation" \
    "Download + execution from /tmp pattern: wget/curl followed by /tmp execution"
fi

# ============================================================================
# Pattern 4 — New UID 0 account paired with root execution
# ============================================================================
# Creating a hidden root account (UID 0) and then immediately executing
# something as root is a two-step persistence technique.
# Neither event alone is necessarily an attack; together they are.
#
# user_activity Section D writes user_activity|new_uid0 events.
# auditd_parser.sh writes auditd|execve|uid=root events.
# ============================================================================
has_new_uid0=$(echo "$recent" | grep -c 'user_activity|new_uid0')
has_root_exec=$(echo "$recent" | grep -c 'auditd|execve|uid=root')

if (( has_new_uid0 > 0 )) && (( has_root_exec > 0 )); then
  alert "CRITICAL" "correlation" \
    "New UID 0 account detected alongside root execution — possible active attacker"
fi

# ============================================================================
# Pattern 5 — Permission change to a system binary
# ============================================================================
# chmod on a binary in /bin, /usr/bin, /sbin, etc. is almost always malicious.
# Legitimate package managers don't touch binaries this way at runtime.
# SUID set on a system binary = instant privilege escalation vector.
#
# auditd_parser.sh writes auditd|perm_change events for all chmod/chown calls.
# ============================================================================
echo "$recent" | grep '|auditd|perm_change|' | while IFS='|' read -r _ _ _ uid_f path_f _; do
  path_val=$(echo "$path_f" | grep -oP 'path=\K.*')

  if echo "$path_val" | grep -qE '^/(bin|sbin|usr/bin|usr/sbin|usr/local/bin)/'; then
    uid_val=$(echo "$uid_f" | grep -oP 'uid=\K.*')
    alert "CRITICAL" "correlation" \
      "Permission change on system binary: $path_val (by $uid_val)"
  fi
done
