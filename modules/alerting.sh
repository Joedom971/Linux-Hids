#!/bin/bash
# ============================================================================
# alerting.sh — Centralized alerting module (Module 5 from the brief)
# ============================================================================
# All other modules call the alert() function defined here.
# Each alert is written as JSON to logs/alerts.json.
#
# JSON format = SIEM-ready: tools like Splunk, Wazuh, or ELK can directly
# ingest this file. This is a nice-to-have from the brief.
#
# DEDUPLICATION:
#   An alert with the same (severity, module, message) triple is silenced
#   for ALERT_DEDUP_SECONDS after its first emission. Prevents the same
#   condition (e.g. "Unexpected listening port: 2222") from flooding the
#   console every 60-second cycle.
#
#   State is persisted in $HIDS_DIR/run/alert_state.txt — one line per
#   alert hash: "<sha256>|<unix_ts>". Reloaded on every call.
#
# Parameters for alert():
#   $1 = severity  → "INFO", "WARNING", or "CRITICAL"
#   $2 = module    → name of the module that detected the anomaly
#   $3 = message   → description of what was detected
#
# Example call:
#   alert "CRITICAL" "file_integrity" "/etc/passwd changed"
# ============================================================================

# Use the project's absolute path (exported by controller.sh)
# Falls back to current directory if run manually
HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

# Load dedup tunables (falls back to defaults if hids.conf absent)
[[ -f "$HIDS_DIR/config/hids.conf" ]] && source "$HIDS_DIR/config/hids.conf"

LOG="$HIDS_DIR/logs/alerts.json"
CONSOLE_LOG="$HIDS_DIR/logs/alerts.console.log"
DEDUP_STATE="$HIDS_DIR/run/alert_state.txt"
DEDUP_SECONDS="${ALERT_DEDUP_SECONDS:-1800}"
DEDUP_MAX="${ALERT_DEDUP_MAX_ENTRIES:-500}"

# Ensure directories exist (safe to call repeatedly)
mkdir -p "$HIDS_DIR/run" "$HIDS_DIR/logs"

# ----------------------------------------------------------------------------
# _alert_is_duplicate — returns 0 if this (sev, mod, msg) was alerted
# recently and should be silenced; returns 1 otherwise.
# Side-effect: on "not duplicate", records the current timestamp.
# ----------------------------------------------------------------------------
_alert_is_duplicate() {
  local hash="$1"
  local now
  now=$(date +%s)

  # Disabled → never a duplicate
  (( DEDUP_SECONDS <= 0 )) && return 1

  if [[ -f "$DEDUP_STATE" ]]; then
    # Find the last recorded timestamp for this hash (if any)
    local last
    last=$(awk -F'|' -v h="$hash" '$1==h {print $2}' "$DEDUP_STATE" | tail -1)

    if [[ -n "$last" ]]; then
      local age=$(( now - last ))
      if (( age < DEDUP_SECONDS )); then
        return 0  # still within cooldown → silence
      fi
    fi
  fi

  # Not a duplicate: append the new record
  echo "${hash}|${now}" >> "$DEDUP_STATE"

  # Prune the state file if it grew past the cap
  local line_count
  line_count=$(wc -l < "$DEDUP_STATE" 2>/dev/null || echo 0)
  if (( line_count > DEDUP_MAX )); then
    tail -n "$DEDUP_MAX" "$DEDUP_STATE" > "${DEDUP_STATE}.tmp" && \
      mv "${DEDUP_STATE}.tmp" "$DEDUP_STATE"
  fi

  return 1
}

alert() {
  local severity="$1"
  local module="$2"
  local message="$3"

  # Build dedup hash from the full tuple.
  # Volatile fragments (PIDs, timestamps, dynamic counts) WILL produce
  # distinct hashes — that is intentional: a new PID suspected of the
  # same misbehavior deserves a fresh alert.
  local hash
  hash=$(printf '%s|%s|%s' "$severity" "$module" "$message" | sha256sum | awk '{print $1}')

  if _alert_is_duplicate "$hash"; then
    return 0  # silenced
  fi

  # ISO 8601 timestamp — standard format for security logs
  local ts
  ts=$(date -Iseconds)

  # Test-run marker: when the test harness sets HIDS_TEST_RUN (a per-run
  # identifier — typically the run's unix timestamp), every alert emitted
  # during that run carries the tag. Consumers can filter:
  #   jq 'select(.test_run == null)'   alerts.json   # real alerts only
  #   jq 'select(.test_run != null)'   alerts.json   # test alerts only
  local test_field=""
  local test_display=""
  if [[ -n "${HIDS_TEST_RUN:-}" ]]; then
    test_field=",
  \"test_run\": \"${HIDS_TEST_RUN}\""
    test_display="\033[1;35m[TEST]\033[0m "
  fi

  # Build the JSON object
  # hostname identifies the machine in a fleet of servers
  local json
  json=$(cat <<EOF
{
  "timestamp": "$ts",
  "host": "$(hostname)",
  "severity": "$severity",
  "module": "$module",
  "message": "$message"${test_field}
}
EOF
)

  # Write to the persistent log file
  echo "$json" >> "$LOG"

  # Build the color-coded console line once, then send it to both stdout
  # (for anyone running the module directly) AND the central console log
  # that the supervisor tails into main.sh's terminal.
  local console_line
  case "$severity" in
    CRITICAL) console_line=$(printf '%b' "${test_display}\033[1;31m[CRITICAL]\033[0m [$module] $message") ;;
    WARNING)  console_line=$(printf '%b' "${test_display}\033[1;33m[WARNING]\033[0m  [$module] $message") ;;
    INFO)     console_line=$(printf '%b' "${test_display}\033[1;32m[INFO]\033[0m     [$module] $message") ;;
  esac
  # Prepend a short timestamp so the tailed stream is readable.
  # Skip the console log when this alert originated from the test harness
  # (HIDS_TEST_RUN set). Test alerts still land in alerts.json (tagged
  # with "test_run") and in the test terminal's stdout — they just don't
  # bleed into main.sh's live-alert window.
  if [[ -z "${HIDS_TEST_RUN:-}" ]]; then
    local short_ts
    short_ts=$(date '+%H:%M:%S')
    printf '[%s] %s\n' "$short_ts" "$console_line" >> "$CONSOLE_LOG"
  fi
  # Also echo to the caller's stdout (module log file under the supervisor,
  # or the user's terminal if run directly / from tests).
  echo "$console_line"
}
