#!/bin/bash
# ============================================================================
# auditd_parser.sh — Kernel audit record assembler
# ============================================================================
# The original version tailed audit.log and wrote individual lines.
# That approach was fundamentally broken because auditd writes events
# as MULTIPLE lines that share the same event ID:
#
#   type=SYSCALL msg=audit(1234:567): uid=root exe="/tmp/payload" ...
#   type=EXECVE  msg=audit(1234:567): a0="./payload" a1="-c" a2="id" ...
#   type=PATH    msg=audit(1234:567): name="/tmp/payload" mode=0755 ...
#
# All three are the SAME execution event. Checking them as individual
# lines means Pattern 1 in the correlation engine (uid=root + /tmp + EXECVE)
# could never match — those fields live on different lines.
#
# This module:
#   1. Calls ausearch to query recent events (handles multi-line assembly)
#   2. Parses the output record by record (events separated by "----")
#   3. Extracts relevant fields from each record type (SYSCALL / EXECVE / PATH)
#   4. Writes ONE structured line per event to raw_events.log
#   5. Deduplicates by audit event ID to avoid re-processing on every cycle
#
# Event types assembled:
#   EXECVE    → who executed what, with what arguments, from which path
#   PERM_CHANGE → chmod / chown — who changed permissions on which file
#
# Output format (pipe-delimited, consistent with all other modules):
#   ts|auditd|execve|uid=USER|exe=/path/binary|cmd=args...|path=/resolved/path
#   ts|auditd|perm_change|uid=USER|path=/file|mode=OCTAL
#
# Deduplication state: run/auditd_parser_seen.txt
# (separate from user_activity Section F's audit_seen.txt to avoid
# cross-contamination — they process different event types)
# ============================================================================

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"
source "$HIDS_DIR/config/auditd.conf"

RAW_LOG="$HIDS_DIR/logs/raw_events.log"

# Dedicated seen file — does NOT share state with user_activity Section F
SEEN_FILE="$HIDS_DIR/run/auditd_parser_seen.txt"

mkdir -p "$HIDS_DIR/run" "$HIDS_DIR/logs"

# ============================================================================
# GUARD: exit cleanly if auditd is disabled or ausearch is unavailable
# ============================================================================
if [[ "$ENABLE_AUDITD" != "true" ]]; then
  exit 0
fi

if ! command -v ausearch &>/dev/null; then
  alert "WARNING" "auditd_parser" "ausearch not found — kernel event assembly disabled"
  exit 0
fi

# Prune seen file to prevent unbounded growth
# Keep the last 2500 entries when over 5000 (same approach as Section F)
if [[ -f "$SEEN_FILE" ]]; then
  count=$(wc -l < "$SEEN_FILE" 2>/dev/null || echo 0)
  if (( count > 5000 )); then
    tail -n 2500 "$SEEN_FILE" > "${SEEN_FILE}.tmp" && mv "${SEEN_FILE}.tmp" "$SEEN_FILE"
  fi
fi

# ============================================================================
# HELPER: emit_if_new
# Writes a structured line to raw_events.log if the event ID has not
# been seen before. Records the ID to prevent re-processing next cycle.
# ============================================================================
emit_if_new() {
  local evid="$1"
  local structured_line="$2"

  # Incomplete events (no ID or no meaningful fields) are silently skipped
  [[ -z "$evid" || -z "$structured_line" ]] && return

  # -F = fixed string, not regex (event IDs contain dots and colons)
  grep -qF "$evid" "$SEEN_FILE" 2>/dev/null && return

  echo "$evid" >> "$SEEN_FILE"
  echo "$(date -Iseconds)|${structured_line}" >> "$RAW_LOG"
}

# ============================================================================
# SECTION 1 — EXECVE events
# Assembles SYSCALL + EXECVE + PATH records for each execution event.
#
# Why three record types?
#   SYSCALL: gives the real uid (even after sudo) and the on-disk binary path
#   EXECVE:  gives the actual command line with all arguments
#   PATH:    gives the canonical resolved path (SYSCALL exe may be a symlink)
# ============================================================================
parse_execve() {
  local evid="" uid="" exe="" cmd="" path=""

  while IFS= read -r line; do

    # "----" marks the boundary between two audit events
    # Flush the current event, then reset for the next one
    if [[ "$line" == "----" ]]; then
      emit_if_new "$evid" \
        "auditd|execve|uid=${uid:-unknown}|exe=${exe:-?}|cmd=${cmd:-?}|path=${path:-?}"
      evid=""; uid=""; exe=""; cmd=""; path=""
      continue
    fi

    # Capture event ID from the msg=audit(TS:SERIAL) field
    # All records in the same event share the same ID
    if [[ -z "$evid" ]]; then
      evid=$(echo "$line" | grep -oP 'msg=audit\(\K[^)]+')
    fi

    # SYSCALL record: extract the real user (uid) and on-disk binary (exe)
    # ausearch -i interprets uid=0 as uid=root automatically
    if echo "$line" | grep -q "^type=SYSCALL"; then
      [[ -z "$uid" ]] && uid=$(echo "$line" | grep -oP '\buid=\K\S+')
      [[ -z "$exe" ]] && exe=$(echo "$line" | grep -oP 'exe="\K[^"]+')
    fi

    # EXECVE record: a0 = program name, a1/a2/a3 = arguments
    # We take up to 3 args — enough to capture dangerous patterns like
    # "bash -c <command>" or "python3 -c <payload>" without bloating the log
    if echo "$line" | grep -q "^type=EXECVE"; then
      cmd=$(echo "$line" | grep -oP 'a0="\K[^"]+')
      local a
      for i in 1 2 3; do
        a=$(echo "$line" | grep -oP 'a'"$i"'="\K[^"]+')
        [[ -n "$a" ]] && cmd="$cmd $a"
      done
    fi

    # PATH record: resolved filesystem path of the binary being executed
    # Only capture the first PATH record (subsequent ones are for shared libs)
    if echo "$line" | grep -q "^type=PATH" && [[ -z "$path" ]]; then
      path=$(echo "$line" | grep -oP 'name="\K[^"]+')
    fi

  done < <(ausearch -i -ts recent -m EXECVE 2>/dev/null)

  # Flush the last event — ausearch does not always end with a "----" separator
  emit_if_new "$evid" \
    "auditd|execve|uid=${uid:-unknown}|exe=${exe:-?}|cmd=${cmd:-?}|path=${path:-?}"
}

# ============================================================================
# SECTION 2 — Permission change events (chmod / chown)
# Records permission changes on files.
#
# Why this matters:
#   chmod u+s /tmp/x → grants SUID to an attacker binary
#   chmod 777 /etc/shadow → makes password hashes world-readable
#   These are logged as SYSCALL events for chmod/fchmod syscalls, tagged
#   with audit key "perm_change" by the rules in install.sh.
#   We query by key (-k perm_change), not by message type, because
#   permission changes are not a separate auditd message type.
# ============================================================================
parse_perm_change() {
  local evid="" uid="" path="" mode=""

  while IFS= read -r line; do

    if [[ "$line" == "----" ]]; then
      emit_if_new "$evid" \
        "auditd|perm_change|uid=${uid:-unknown}|path=${path:-?}|mode=${mode:-?}"
      evid=""; uid=""; path=""; mode=""
      continue
    fi

    if [[ -z "$evid" ]]; then
      evid=$(echo "$line" | grep -oP 'msg=audit\(\K[^)]+')
    fi

    # SYSCALL record: who made the permission change
    if echo "$line" | grep -q "^type=SYSCALL"; then
      [[ -z "$uid" ]] && uid=$(echo "$line" | grep -oP '\buid=\K\S+')
    fi

    # PATH record: which file was changed and its new mode
    # mode is given as an octal string, e.g. "0100755" = executable
    if echo "$line" | grep -q "^type=PATH" && [[ -z "$path" ]]; then
      path=$(echo "$line" | grep -oP 'name="\K[^"]+')
      mode=$(echo "$line" | grep -oP 'mode=\K\S+')
    fi

  done < <(ausearch -i -ts recent -k perm_change 2>/dev/null)

  emit_if_new "$evid" \
    "auditd|perm_change|uid=${uid:-unknown}|path=${path:-?}|mode=${mode:-?}"
}

parse_execve
parse_perm_change
