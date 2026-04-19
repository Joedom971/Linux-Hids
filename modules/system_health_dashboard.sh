#!/bin/bash
# ============================================================================
# system_health_dashboard.sh — Fast-refresh colored status panel (Stage 4)
# ============================================================================
# Writes a multi-line, ANSI-colored snapshot of the system's health metrics
# to logs/system_health.status every SH_DISPLAY_INTERVAL seconds (default 3).
#
# Each reading is on its own line and the status tag is color-coded:
#     green  [ OK ]   — within normal range
#     yellow [WARN]   — first threshold crossed
#     red    [CRIT]   — critical threshold crossed
#
# To view with colors:
#     watch -n 1 --color cat logs/system_health.status
#     OR
#     tail -f logs/system_health.status   (static; refresh manually)
#
# This module is for display only — no alerts are emitted here. Alerting
# with 2-cycle temporal logic remains in system_health.sh on SH_INTERVAL.
# ============================================================================

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/config/thresholds.conf"

STATUS_FILE="$HIDS_DIR/logs/system_health.status"
PROC_BASELINE_FILE="$HIDS_DIR/baselines/process_count.txt"
DISPLAY_INTERVAL="${SH_DISPLAY_INTERVAL:-3}"

mkdir -p "$HIDS_DIR/logs"

trap 'exit 0' TERM INT

# --- ANSI color codes ------------------------------------------------------
# Using printf-friendly escapes; `watch --color` and `cat` on an ANSI-aware
# terminal both render these correctly.
C_RESET=$'\033[0m'
C_GREEN=$'\033[1;32m'
C_YELLOW=$'\033[1;33m'
C_RED=$'\033[1;31m'
C_BLUE=$'\033[1;34m'
C_DIM=$'\033[2m'
C_BOLD=$'\033[1m'

# tag LEVEL -> fixed-width colored status tag
# LEVEL is one of: ok, warn, crit
tag() {
  case "$1" in
    ok)   printf '%s[ OK ]%s' "$C_GREEN"  "$C_RESET" ;;
    warn) printf '%s[WARN]%s' "$C_YELLOW" "$C_RESET" ;;
    crit) printf '%s[CRIT]%s' "$C_RED"    "$C_RESET" ;;
  esac
}

# format one metric row: label | value | status
# Value column is padded to 28 chars so the status tag aligns.
row() {
  local label="$1" value="$2" level="$3"
  printf '  %-12s : %-28s %s\n' "$label" "$value" "$(tag "$level")"
}

# humanise uptime seconds -> "2d 4h 12m"
fmt_uptime() {
  local s=$1
  local d=$(( s / 86400 ))
  local h=$(( (s % 86400) / 3600 ))
  local m=$(( (s % 3600) / 60 ))
  printf '%dd %dh %dm' "$d" "$h" "$m"
}

snapshot() {
  local ts load cores disk mem_avail swap procs uptime_s
  local failed_svc baseline_proc
  local level_load level_disk level_mem level_swap level_proc level_svc

  ts=$(date -Iseconds)
  load=$(awk '{print $1}' /proc/loadavg)
  cores=$(nproc)
  disk=$(df / | awk 'NR==2 {gsub("%","",$5); print $5}')
  mem_avail=$(awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END{if(t>0) printf "%.0f",(a/t)*100; else print 0}' /proc/meminfo)
  swap=$(awk '/SwapTotal/{t=$2} /SwapFree/{f=$2} END{print t-f}' /proc/meminfo)
  procs=$(ps -e --no-headers | wc -l)
  uptime_s=$(awk '{print int($1)}' /proc/uptime)
  failed_svc=$(systemctl --failed --no-legend 2>/dev/null | grep -c .)

  # --- level: load (adaptive to core count) ---
  # crit >= 100% of cores, warn >= 70%, else ok
  if awk "BEGIN {exit !($load >= $cores)}"; then
    level_load=crit
  elif awk "BEGIN {exit !($load >= $cores * 0.7)}"; then
    level_load=warn
  else
    level_load=ok
  fi

  # --- level: disk ---
  if   (( disk >= DISK_CRIT_PERCENT )); then level_disk=crit
  elif (( disk >= DISK_WARN_PERCENT )); then level_disk=warn
  else                                        level_disk=ok
  fi

  # --- level: memory ---
  # Mirrors system_health.sh's correlation: low avail + swap used = worse
  if   (( mem_avail < MEM_CRIT_PERCENT )) && (( swap >= SWAP_CRIT_KB )); then level_mem=crit
  elif (( mem_avail < MEM_WARN_PERCENT )); then                               level_mem=warn
  else                                                                        level_mem=ok
  fi

  # --- level: swap (standalone) ---
  if   (( swap >= SWAP_CRIT_KB )); then level_swap=crit
  elif (( swap > 0 ));             then level_swap=warn
  else                                   level_swap=ok
  fi

  # --- level: processes (relative to baseline if present) ---
  if [[ -f "$PROC_BASELINE_FILE" ]]; then
    baseline_proc=$(cat "$PROC_BASELINE_FILE")
    local warn_proc crit_proc
    warn_proc=$(( baseline_proc + baseline_proc * PROCESS_WARN_PERCENT / 100 ))
    crit_proc=$(( baseline_proc + baseline_proc * PROCESS_CRIT_PERCENT / 100 ))
    if   (( procs >= crit_proc )); then level_proc=crit
    elif (( procs >= warn_proc )); then level_proc=warn
    else                                 level_proc=ok
    fi
  else
    baseline_proc=""
    level_proc=ok
  fi

  # --- level: failed services ---
  if   (( failed_svc >= FAILED_SERVICES_CRIT )); then level_svc=crit
  else                                                 level_svc=ok
  fi

  # --- render ---
  {
    printf '%s HIDS — system health %s  %s%s%s\n' \
      "$C_BOLD" "$C_RESET" "$C_DIM" "$ts" "$C_RESET"
    printf '%s──────────────────────────────────────────────────%s\n' "$C_BLUE" "$C_RESET"
    row "Load"        "$load  /  $cores cores"                         "$level_load"
    row "Disk /"      "${disk}%  (warn ${DISK_WARN_PERCENT} / crit ${DISK_CRIT_PERCENT})" "$level_disk"
    row "Memory"      "${mem_avail}% available"                        "$level_mem"
    row "Swap"        "${swap} KB used"                                "$level_swap"
    if [[ -n "$baseline_proc" ]]; then
      row "Processes" "${procs}  (baseline ${baseline_proc})"          "$level_proc"
    else
      row "Processes" "${procs}  (no baseline)"                        "$level_proc"
    fi
    row "Failed svc"  "${failed_svc}"                                  "$level_svc"
    printf '  %-12s : %s%s%s\n' "Uptime" "$C_DIM" "$(fmt_uptime "$uptime_s")" "$C_RESET"
    printf '%s──────────────────────────────────────────────────%s\n' "$C_BLUE" "$C_RESET"
    printf '%srefreshes every %ss — view: watch -n 1 --color cat logs/system_health.status%s\n' \
      "$C_DIM" "$DISPLAY_INTERVAL" "$C_RESET"
  }
}

while true; do
  # Atomic overwrite: write to .tmp then mv, so readers never see a partial render
  snapshot > "${STATUS_FILE}.tmp" && mv "${STATUS_FILE}.tmp" "$STATUS_FILE"
  sleep "$DISPLAY_INTERVAL" &
  wait $! 2>/dev/null
done
