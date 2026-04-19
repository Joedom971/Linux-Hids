#!/bin/bash
# ============================================================================
# enrichment.sh — Post-detection context enrichment
# ============================================================================
# Detection modules find WHAT happened. Enrichment answers the follow-up
# questions a SOC analyst immediately asks:
#
#   "This process in /tmp was PID 4821 — but who spawned it?"
#   "Port 4444 was opened — but is that IP a known bad actor?"
#   "A connection from 185.220.101.45 — what host is that?"
#
# This module runs AFTER all detection modules each cycle. It reads the
# most recent alerts from alerts.json and adds context that individual
# modules cannot provide (they detect in isolation; enrichment correlates
# across the full picture of the running system).
#
# Three enrichment types:
#
#   1. Process ancestry (for alerts that mention a PID)
#      Walks the /proc PPID chain to reconstruct the execution path:
#        sshd → bash → wget → /tmp/payload
#      Why individual modules cannot do this: they detect a specific anomaly
#      and fire an alert. Tracing the full ancestry of EVERY process on every
#      cycle would be prohibitively expensive.
#
#   2. File attribution (for file_integrity alerts)
#      Queries auditd (ausearch -f PATH) to find WHO modified the file and
#      with which command. Turns "File modified: /etc/passwd" into
#      "File modified: /etc/passwd — by alice via useradd".
#      Why file_integrity.sh already does this inline: it does, but only when
#      auditd has a recent record at detection time. Enrichment retries and
#      adds the result to the enriched.log for cases where auditd lagged or
#      the original alert had "no audit data available".
#
#   3. IP reverse DNS (for alerts that mention a public IP)
#      Resolves the remote hostname for IPs found in alert messages.
#      Private/loopback ranges are skipped — no useful rDNS there.
#      Why individual modules cannot do this: network DNS lookups add latency
#      to time-sensitive detection loops; post-hoc enrichment avoids that.
#
# Output: logs/enriched.log — one line per enriched alert
# Format: ts|enrichment|MODULE|ORIGINAL_MESSAGE|context: ENRICHMENT
#
# Dedup: run/enrichment_seen.txt (alert hash → prevents re-enriching on
# every subsequent cycle once an alert has been enriched)
# ============================================================================

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"
[[ -f "$HIDS_DIR/config/auditd.conf" ]] && source "$HIDS_DIR/config/auditd.conf"

ALERT_LOG="$HIDS_DIR/logs/alerts.json"
ENRICHED_LOG="$HIDS_DIR/logs/enriched.log"
SEEN_FILE="$HIDS_DIR/run/enrichment_seen.txt"

mkdir -p "$HIDS_DIR/run" "$HIDS_DIR/logs"

# Nothing to enrich if no alerts have been generated yet
[[ -f "$ALERT_LOG" ]] || exit 0

# ============================================================================
# HELPER: walk_process_tree PID
# Walks the /proc PPID chain from the given PID up toward init (PID 1).
# Returns a human-readable ancestry string:
#   PID4821(payload,root) → PID4820(bash,alice) → PID1234(sshd,root)
#
# Stops at depth 8 to handle pathological chains (zombie trees, PID 1
# may not always be reachable before /proc entries disappear).
#
# Note: processes that have already exited will have no /proc entry.
# In that case the chain is truncated at the last living ancestor.
# ============================================================================
walk_process_tree() {
  local pid="$1"
  local chain="" current="$pid" depth=0

  while [[ -n "$current" && "$current" != "1" && $depth -lt 8 ]]; do

    # Process may have already exited between alert fire and enrichment run
    [[ -d "/proc/$current" ]] || break

    local exe user ppid
    exe=$(readlink -f "/proc/$current/exe" 2>/dev/null | xargs -r basename)
    user=$(stat -c '%U' "/proc/$current" 2>/dev/null)
    ppid=$(awk '{print $4}' "/proc/$current/stat" 2>/dev/null)

    [[ -z "$exe"  ]] && exe="?"
    [[ -z "$user" ]] && user="?"

    # Prepend each ancestor so the chain reads child → parent → grandparent
    chain="${chain:+$chain → }PID${current}(${exe},${user})"

    current="$ppid"
    (( depth++ ))
  done

  echo "$chain"
}

# ============================================================================
# HELPER: get_file_attribution PATH
# Queries auditd for the last user to write to a given file path.
# Returns "by USER via BINARY" or nothing if auditd has no record.
#
# This complements file_integrity.sh's inline auditd query: that module
# queries at detection time, but auditd may not have indexed the event yet
# (up to a few seconds of lag). Running the same query a cycle later in
# the enrichment pass catches what the original detection missed.
# ============================================================================
get_file_attribution() {
  local filepath="$1"

  [[ "$ENABLE_AUDITD" != "true" ]] && return
  command -v ausearch &>/dev/null || return

  local entry auid user exe
  entry=$(ausearch -f "$filepath" -ts recent -i 2>/dev/null | tail -20)
  [[ -z "$entry" ]] && return

  # auid = audit user ID: the REAL user even across sudo. With -i, it is
  # already interpreted (shows username, not numeric UID).
  auid=$(echo "$entry" | grep -oP 'auid=\K\S+' | grep -v unset | tail -1)
  [[ -z "$auid" ]] && return

  user="$auid"
  exe=$(echo "$entry" | grep -oP 'exe="\K[^"]+' | tail -1)
  exe=$(basename "${exe:-unknown}" 2>/dev/null)

  echo "by $user via $exe"
}

# ============================================================================
# HELPER: get_ip_rdns IP
# Performs a reverse DNS lookup for a public IPv4 address.
# Uses getent (system resolver, no external dependency) with dig as fallback.
# Returns the hostname, or nothing if unresolvable.
#
# Private/loopback ranges are skipped: there is no useful rDNS for
# 10.x, 172.16-31.x, 192.168.x, or 127.x addresses.
# ============================================================================
get_ip_rdns() {
  local ip="$1"
  local result=""

  # Validate: must look like a dotted-quad IPv4 address
  echo "$ip" | grep -qP '^\d{1,3}(\.\d{1,3}){3}$' || return

  # Skip RFC 1918 and loopback — reverse lookup adds no value there
  if echo "$ip" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)'; then
    return
  fi

  # getent hosts is fast and uses the system resolver (no external dependency)
  result=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -1)

  # Fallback: dig with a short timeout (2s, 1 try) to avoid blocking the cycle
  if [[ -z "$result" ]] && command -v dig &>/dev/null; then
    result=$(dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
  fi

  [[ -n "$result" ]] && echo "$result"
}

# ============================================================================
# HELPER: parse_recent_alerts
# Reads alerts.json and outputs the last ~10 complete alert objects as TSV.
# alerts.json uses multi-line JSON (one object per 7 lines: { + 5 fields + }).
# Output format: TIMESTAMP<TAB>MODULE<TAB>MESSAGE
#
# Note: the while loop runs inside a pipe subshell, so internal variables
# are not visible outside. The printf calls write to stdout, which is
# what the caller captures via process substitution.
# ============================================================================
parse_recent_alerts() {
  local in_obj=0 ts="" module="" message=""

  # 70 lines = up to 10 complete 7-line alert objects
  tail -n 70 "$ALERT_LOG" | while IFS= read -r line; do

    # Trim leading whitespace (JSON fields are indented 2 spaces)
    line="${line#"${line%%[! ]*}"}"

    if [[ "$line" == "{" ]]; then
      in_obj=1; ts=""; module=""; message=""
      continue
    fi

    if [[ "$line" == "}" ]] && (( in_obj )); then
      in_obj=0
      # Only output complete objects
      [[ -n "$ts" && -n "$module" && -n "$message" ]] && \
        printf '%s\t%s\t%s\n' "$ts" "$module" "$message"
      continue
    fi

    (( in_obj )) || continue

    # Extract the JSON string value from lines like:  "field": "value"
    local val
    val=$(echo "$line" | grep -oP '": "\K[^"]+')
    [[ -z "$val" ]] && continue

    case "$line" in
      *'"timestamp"'*) ts="$val"      ;;
      *'"module"'*)    module="$val"  ;;
      *'"message"'*)   message="$val" ;;
    esac
  done
}

# ============================================================================
# MAIN: enrich_alert TS MODULE MESSAGE
# For each recent alert that has not been enriched yet:
#   - compute a dedup hash so we only enrich once per unique alert
#   - extract a PID from the message → walk the process tree
#   - extract a public IP from the message → reverse DNS
#   - if any context was found, write one line to enriched.log
# ============================================================================
enrich_alert() {
  local alert_ts="$1" alert_module="$2" alert_msg="$3"
  local context="" hash pid tree ip rdns

  # Dedup: sha256 of (ts + module + message) — same triple = already enriched
  hash=$(printf '%s|%s|%s' "$alert_ts" "$alert_module" "$alert_msg" \
         | sha256sum | awk '{print $1}')
  grep -qF "$hash" "$SEEN_FILE" 2>/dev/null && return
  echo "$hash" >> "$SEEN_FILE"

  # --- Enrichment 1: Process ancestry ---
  # Matches patterns like "PID 4821", "PID: 4821", "pid=4821"
  pid=$(echo "$alert_msg" | grep -oP '\bPID[: ]?\K[0-9]+' | head -1)
  if [[ -n "$pid" ]]; then
    tree=$(walk_process_tree "$pid")
    [[ -n "$tree" ]] && context="${context:+$context | }ancestry: $tree"
  fi

  # --- Enrichment 2: File attribution (file_integrity alerts) ---
  # Extract the file path from the alert message and query auditd for who
  # modified it. Complements the inline query in file_integrity.sh which
  # may miss events due to auditd indexing lag.
  if [[ "$alert_module" == "file_integrity" ]]; then
    local filepath attribution
    # Match absolute paths in messages like "File modified: /etc/passwd (by...)"
    filepath=$(echo "$alert_msg" | grep -oP '/[^\s,()"]+' | head -1)
    if [[ -n "$filepath" ]]; then
      attribution=$(get_file_attribution "$filepath")
      [[ -n "$attribution" ]] && context="${context:+$context | }file-attribution: $attribution"
    fi
  fi

  # --- Enrichment 3: IP reverse DNS ---
  # Extracts the first IPv4 address that looks like a routable address
  # Regex: four groups of 1-3 digits separated by dots
  ip=$(echo "$alert_msg" \
       | grep -oP '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\b' \
       | head -1)
  if [[ -n "$ip" ]]; then
    rdns=$(get_ip_rdns "$ip")
    [[ -n "$rdns" ]] && context="${context:+$context | }rdns($ip): $rdns"
  fi

  # Write to enriched.log only if we found something useful
  [[ -n "$context" ]] || return

  echo "$(date -Iseconds)|enrichment|${alert_module}|${alert_msg}|${context}" \
    >> "$ENRICHED_LOG"
}

# Process all recent alerts
while IFS=$'\t' read -r ts mod msg; do
  [[ -n "$ts" ]] && enrich_alert "$ts" "$mod" "$msg"
done < <(parse_recent_alerts)

# Prune seen file to prevent unbounded growth
if [[ -f "$SEEN_FILE" ]]; then
  count=$(wc -l < "$SEEN_FILE" 2>/dev/null || echo 0)
  if (( count > 2000 )); then
    tail -n 1000 "$SEEN_FILE" > "${SEEN_FILE}.tmp" && mv "${SEEN_FILE}.tmp" "$SEEN_FILE"
  fi
fi
