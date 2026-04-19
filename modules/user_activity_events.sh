#!/bin/bash
# ============================================================================
# user_activity_events.sh — Real-time auditd stream reader (Stage 3a)
# ============================================================================
# user_activity.sh previously polled `ausearch -k <key> -ts recent` every
# $UA_INTERVAL seconds, giving up to 60s of latency between a kernel event
# and the alert. This module replaces that polling with `tail -F` on the
# audit log, so alerts fire within ~1s of the syscall.
#
# Keys watched (posted by install.sh into /etc/audit/rules.d/hids.rules):
#   user_modify      — writes to /etc/passwd, /etc/shadow, /etc/group
#   priv_escalation  — writes to /etc/sudoers
#   account_change   — useradd / usermod / userdel invocations
#   persistence      — writes to /etc/crontab
#   ssh_config       — writes to /etc/ssh/sshd_config
#
# This runs forever: it's a streaming consumer, not a one-shot scan, so the
# Stage 2 re-exec wrapper does not apply. SIGTERM from the supervisor kills
# `tail` via the pipeline and exits cleanly.
#
# Dedup is handled by alerting.sh (sev+module+msg hash with cooldown), so
# repeated identical events within ALERT_DEDUP_SECONDS are silenced.
# ============================================================================

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"
source "$HIDS_DIR/config/auditd.conf"

AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
RAW_LOG="$HIDS_DIR/logs/raw_events.log"

log_raw() {
  echo "$(date -Iseconds)|user_activity|$*" >> "$RAW_LOG"
}

# Gate: if auditd isn't enabled or the log is missing, emit a WARNING and
# exit 0. The supervisor will not restart-loop us (exit 0 is not a crash).
if [[ "$ENABLE_AUDITD" != "true" ]]; then
  alert "INFO" "user_activity_events" "ENABLE_AUDITD=false; event stream disabled"
  exit 0
fi
if [[ ! -r "$AUDIT_LOG" ]]; then
  alert "WARNING" "user_activity_events" \
    "audit log not readable at $AUDIT_LOG — running as root?"
  exit 0
fi

trap 'exit 0' TERM INT

# tail -n 0: start from end of file (don't replay history on startup)
# -F      : follow across log rotation
tail -n 0 -F "$AUDIT_LOG" 2>/dev/null | while IFS= read -r line; do

  # Cheap prefilter: skip anything without one of our keys
  case "$line" in
    *'key="user_modify"'*)      key=user_modify ;;
    *'key="priv_escalation"'*)  key=priv_escalation ;;
    *'key="account_change"'*)   key=account_change ;;
    *'key="persistence"'*)      key=persistence ;;
    *'key="ssh_config"'*)       key=ssh_config ;;
    *) continue ;;
  esac

  # Extract fields from the same record. Most SYSCALL records carry
  # auid/exe/comm alongside the key; if a field is missing we show "?".
  id=$(  echo "$line" | grep -oP 'audit\([0-9.]+:\K[0-9]+')
  auid=$(echo "$line" | grep -oP 'auid=\K[^ ]+')
  exe=$( echo "$line" | grep -oP 'exe="\K[^"]+')
  comm=$(echo "$line" | grep -oP 'comm="\K[^"]+')

  # Resolve auid -> username when possible (auid survives sudo/su)
  user="${auid:-?}"
  if [[ "$auid" =~ ^[0-9]+$ && "$auid" != "4294967295" ]]; then
    name=$(getent passwd "$auid" 2>/dev/null | cut -d: -f1)
    [[ -n "$name" ]] && user="$name"
  fi

  alert "CRITICAL" "user_activity" \
    "auditd[$key] user=$user exe=${exe:-?} comm=${comm:-?}"
  log_raw "audit|key=$key|id=${id:-?}|auid=${auid:-?}|exe=${exe:-?}|comm=${comm:-?}"
done
