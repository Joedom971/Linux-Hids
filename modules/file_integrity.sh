#!/bin/bash
# ============================================================================
# file_integrity.sh — Module 4: File integrity + auditd enrichment
# ============================================================================
# The brief asks: "has anything important on this filesystem been touched
# that should not have been?"
#
# Principle: compute the SHA-256 hash of each critical file and compare it
# to the hash stored in the baseline.
# If the hash changed = the file was modified (even a single byte).
#
# AUDITD INTEGRATION:
#   When a change is detected, this module queries auditd logs to find out
#   WHO modified the file and with WHAT command. This turns a generic alert
#   like "File modified: /etc/passwd" into a forensic-quality alert like
#   "File modified: /etc/passwd (by root, cmd: useradd)"
#
#   The auditd rules in /etc/audit/rules.d/hids.rules tag file changes
#   with keys like "user_modify", "priv_escalation", etc. We use ausearch
#   to query by filename and extract the relevant event.
#
# PERMISSION CHECK:
#   Even if a file's content hasn't changed, dangerous permission changes
#   are detected (e.g., /etc/shadow readable by everyone).
#
# Data sources:
#   sha256sum   → cryptographic hash comparison
#   ausearch    → auditd log query (who, when, what command)
#   stat        → file permissions and modification timestamp
# ============================================================================

# --- Stage 2 self-loop wrapper ---
# When HIDS_SELF_LOOP=1 (default) the script re-execs itself every
# $FI_INTERVAL seconds. One scan = one fresh bash process, so memory is
# bounded and config changes are picked up each cycle. Supervisor may set
# HIDS_SELF_LOOP=0 to force a single pass (useful for debugging).
if [[ -z "${__HIDS_INLOOP:-}" ]] && [[ "${HIDS_SELF_LOOP:-1}" == "1" ]]; then
  export __HIDS_INLOOP=1
  _interval="${FI_INTERVAL:-60}"
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
source "$HIDS_DIR/config/file_integrity.conf"
source "$HIDS_DIR/config/auditd.conf"

# ============================================================================
# FUNCTION: query auditd for details about a file modification
# ============================================================================
# Takes a filepath, returns a human-readable string with who/what/when.
# If auditd has no data, falls back to stat info.
# If neither works, returns "no audit data available".

get_audit_context() {
  local filepath="$1"

  # Try ausearch first (requires auditd to be enabled and running)
  # ausearch -f searches audit logs by filename
  # -ts recent limits to the last 10 minutes to avoid old events
  if [[ "$ENABLE_AUDITD" == "true" ]] && command -v ausearch &>/dev/null; then

    local audit_entry
    audit_entry=$(ausearch -f "$filepath" -ts recent 2>/dev/null | tail -20)

    if [[ -n "$audit_entry" ]]; then

      # Extract auid (audit user ID) — this is the REAL user, even after sudo
      # If someone does "sudo useradd backdoor", auid still shows the original user
      local audit_uid
      audit_uid=$(echo "$audit_entry" | grep -oP 'auid=\K[0-9]+' | tail -1)

      # Convert UID to username
      local audit_user="unknown"
      if [[ -n "$audit_uid" && "$audit_uid" != "4294967295" ]]; then
        audit_user=$(getent passwd "$audit_uid" 2>/dev/null | cut -d: -f1)
        [[ -z "$audit_user" ]] && audit_user="uid:$audit_uid"
      fi

      # Extract the command that modified the file
      local audit_cmd
      audit_cmd=$(echo "$audit_entry" | grep -oP 'exe="\K[^"]+' | tail -1)
      [[ -z "$audit_cmd" ]] && audit_cmd="unknown"

      echo "by $audit_user, cmd: $(basename "$audit_cmd")"
      return 0
    fi
  fi

  # Fallback: use stat to get basic info (no auditd data available)
  if [[ -f "$filepath" ]]; then
    local mod_time last_user
    mod_time=$(stat -c '%y' "$filepath" 2>/dev/null | cut -d'.' -f1)
    last_user=$(stat -c '%U' "$filepath" 2>/dev/null)
    echo "owner: $last_user, last modified: $mod_time"
    return 0
  fi

  echo "no audit data available"
}

# ============================================================================
# INTEGRITY CHECK: detect content, permission, and ownership changes
# ============================================================================
# Reads the consolidated baseline (baselines/files.txt) created by --init.
# Each line: <sha256>  <mode>  <owner:group>  <size>  <path>
#
# On every line we compare the current state to the baseline:
#   - hash mismatch  → content was modified
#   - mode mismatch  → chmod attack (e.g. `chmod 644 /etc/shadow` to leak hashes)
#   - owner mismatch → chown attack (e.g. `chown attacker /etc/sudoers`)
#
# IMPORTANT DESIGN CHOICES:
#   - Permissions are adaptive: we compare to what was captured at --init,
#     not hardcoded 640/440/644. Works across distros with different defaults.
#   - The baseline is NEVER auto-updated after an alert. Detecting a change
#     once then going silent is an anti-pattern. To approve a legitimate
#     change, the admin must re-run `sudo bash main.sh --init`.

BASELINE_FILE="$HIDS_DIR/baselines/files.txt"

# Refuse to baseline silently: require an explicit --init.
if [[ ! -f "$BASELINE_FILE" ]]; then
  alert "WARNING" "file_integrity" \
    "No baseline found — run 'sudo bash $HIDS_DIR/main.sh --init' first"
  exit 0
fi

# Read the baseline line by line.
# Field order matches `printf` in baseline.sh:
#   <hash>  <mode>  <owner:group>  <size>  <path>
# Size is captured for the baseline file's readability but we compare by hash
# (content change implies size change, so size is redundant for detection).
while read -r base_hash base_mode base_owner base_size base_path; do

  # Skip empty lines defensively
  [[ -z "$base_hash" ]] && continue

  # A deleted critical file is a serious alert
  if [[ ! -f "$base_path" ]]; then
    alert "CRITICAL" "file_integrity" "Critical file missing: $base_path"
    continue
  fi

  # Capture current state
  current_hash=$(sha256sum "$base_path" 2>/dev/null | awk '{print $1}')
  current_mode=$(stat -c '%a' "$base_path" 2>/dev/null)
  current_owner=$(stat -c '%U:%G' "$base_path" 2>/dev/null)

  # --- Content change → CRITICAL ---
  if [[ "$current_hash" != "$base_hash" ]]; then
    context=$(get_audit_context "$base_path")
    alert "CRITICAL" "file_integrity" "File modified: $base_path ($context)"
    echo "$(date -Iseconds)|file_integrity|modified|$base_path|old=$base_hash|new=$current_hash|$context" \
      >> "$HIDS_DIR/logs/raw_events.log"
    # NOTE: baseline is NOT updated. Re-run --init to approve a change.
  fi

  # --- Permission change → CRITICAL ---
  # Adaptive: we compare to what was there at --init, not a hardcoded value.
  if [[ "$current_mode" != "$base_mode" ]]; then
    context=$(get_audit_context "$base_path")
    alert "CRITICAL" "file_integrity" \
      "Permissions changed on $base_path: $current_mode (baseline: $base_mode) ($context)"
    echo "$(date -Iseconds)|file_integrity|chmod|$base_path|old=$base_mode|new=$current_mode|$context" \
      >> "$HIDS_DIR/logs/raw_events.log"
  fi

  # --- Ownership change → CRITICAL ---
  if [[ "$current_owner" != "$base_owner" ]]; then
    context=$(get_audit_context "$base_path")
    alert "CRITICAL" "file_integrity" \
      "Ownership changed on $base_path: $current_owner (baseline: $base_owner) ($context)"
    echo "$(date -Iseconds)|file_integrity|chown|$base_path|old=$base_owner|new=$current_owner|$context" \
      >> "$HIDS_DIR/logs/raw_events.log"
  fi

done < "$BASELINE_FILE"
