#!/bin/bash
# ============================================================================
# system_health.sh — Module 1: System health (by Muza, integrated by Johan)
# ============================================================================
# Answers the brief question: "Is this system healthy right now?"
#
# This module monitors 7 metrics:
#   1. CPU load average (adaptive to core count)
#   2. Disk usage
#   3. Memory + swap (correlated — low RAM alone ≠ problem, low RAM + high swap = problem)
#   4. Process count vs baseline (detects fork bombs, malware spawning)
#   5. Failed systemd services
#   6. Recent system error logs
#   7. Uptime (unexpected reboot detection)
#
# TEMPORAL LOGIC:
#   Alerts only trigger if a condition persists across TWO consecutive cycles.
#   This reduces false positives from brief spikes. The brief says:
#   "the difference between a tool that cries wolf and one you can actually trust."
#
#   How it works: each metric gets a flag (0=ok, 1=warning, 2=critical).
#   Flags are saved to a state file. On the next run, an alert only fires
#   if the PREVIOUS flag was already >= 1. One-time spikes are ignored.
#
# Data sources:
#   /proc/loadavg   → CPU load average
#   /proc/meminfo   → memory and swap stats
#   /proc/uptime    → system uptime in seconds
#   df /            → root partition disk usage
#   ps -e           → running process count
#   systemctl       → failed services
#   journalctl      → recent error logs
# ============================================================================

# --- Stage 2 self-loop wrapper (see file_integrity.sh for rationale) ---
# Stage 4 will split this into a separate display loop and alert loop; for
# now the whole module runs on SH_INTERVAL.
if [[ -z "${__HIDS_INLOOP:-}" ]] && [[ "${HIDS_SELF_LOOP:-1}" == "1" ]]; then
  export __HIDS_INLOOP=1
  _interval="${SH_INTERVAL:-60}"
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

# Resolve project path (fixes relative path bug from original code)
HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"
source "$HIDS_DIR/config/thresholds.conf"

# State file stores the previous cycle's flags for temporal logic
STATE_FILE="$HIDS_DIR/baselines/system_health_state.sh"

# Process baseline file — stores the "normal" process count from first run
PROC_BASELINE_FILE="$HIDS_DIR/baselines/process_count.txt"

mkdir -p "$HIDS_DIR/baselines" "$HIDS_DIR/logs"

# --- Load previous state ---
# Default all flags to 0 (no previous alert)
load_prev=0
disk_prev=0
mem_prev=0
proc_prev=0

if [[ -f "$STATE_FILE" ]]; then
  source "$STATE_FILE"
fi

# ============================================================================
# COLLECT METRICS
# ============================================================================

# CPU load: 1-minute average from /proc/loadavg
load=$(awk '{print $1}' /proc/loadavg)

# Number of CPU cores — used to calculate adaptive thresholds
# On a 4-core machine, load 4.0 = 100%. On 1-core, load 1.0 = 100%.
cores=$(nproc)

# Warning threshold = 70% of core count (e.g., 2.8 on a 4-core machine)
warn_load=$(awk "BEGIN {printf \"%.2f\", $cores * 0.7}")

# Disk usage percentage of root partition
disk=$(df / | awk 'NR==2 {gsub("%","",$5); print $5}')

# Available memory as percentage of total
# Reads MemTotal and MemAvailable from /proc/meminfo
mem_pct=$(awk '
  /MemTotal/ {total=$2}
  /MemAvailable/ {avail=$2}
  END {
    if (total > 0) {
      printf "%.0f", (avail/total)*100
    } else {
      print 0
    }
  }
' /proc/meminfo)

# Swap usage in KB (total - free = used)
swap=$(awk '
  /SwapTotal/ {t=$2}
  /SwapFree/  {f=$2}
  END {print t-f}
' /proc/meminfo)

# Total number of running processes
proc_count=$(ps -e --no-headers | wc -l)

# --- Process baseline ---
# Created by baseline.sh during `main.sh --init`. We do NOT auto-create it
# here: a baseline captured during a random first cycle (e.g. post-reboot
# while services are still starting) would be unrepresentative.
# If the baseline is missing, we skip the process-spike check for this cycle.
if [[ -f "$PROC_BASELINE_FILE" ]]; then
  baseline_proc=$(cat "$PROC_BASELINE_FILE")
  # Calculate dynamic thresholds based on baseline
  # e.g., baseline=120, WARN=+50% → alert at 180 processes
  warn_proc=$(( baseline_proc + (baseline_proc * PROCESS_WARN_PERCENT / 100) ))
  crit_proc=$(( baseline_proc + (baseline_proc * PROCESS_CRIT_PERCENT / 100) ))
else
  baseline_proc=""
  warn_proc=0
  crit_proc=0
fi

# Count failed systemd services
failed_services=$(systemctl --failed --no-legend 2>/dev/null | grep -c .)

# Count recent error-level log entries
error_logs=$(journalctl -p err -n 20 --no-pager 2>/dev/null | grep -c .)

# System uptime in seconds (for reboot detection)
uptime_seconds=$(awk '{print int($1)}' /proc/uptime)

# ============================================================================
# DETECTION WITH TEMPORAL LOGIC
# ============================================================================
# Each metric sets a flag for the current cycle.
# An alert only fires if the previous cycle's flag was ALSO elevated.
# This means a condition must persist for 2 consecutive cycles to trigger.

current_load_flag=0
current_disk_flag=0
current_mem_flag=0
current_proc_flag=0

# --- CPU Load ---
# CRITICAL: load >= number of cores (100% saturated)
# WARNING: load > 70% of cores
if awk "BEGIN {exit !($load >= $cores)}"; then
  current_load_flag=2
  if [[ "${load_prev:-0}" -ge 1 ]]; then
    alert "CRITICAL" "system_health" "Load average critical: ${load} (>= ${cores} cores)"
  fi
elif awk "BEGIN {exit !($load > ($cores * 0.7))}"; then
  current_load_flag=1
  if [[ "${load_prev:-0}" -ge 1 ]]; then
    alert "WARNING" "system_health" "Load elevated: ${load} (> ${warn_load})"
  fi
fi

# --- Disk ---
if (( disk >= DISK_CRIT_PERCENT )); then
  current_disk_flag=2
  if [[ "${disk_prev:-0}" -ge 1 ]]; then
    alert "CRITICAL" "system_health" "Disk critical: ${disk}% (threshold: ${DISK_CRIT_PERCENT}%)"
  fi
elif (( disk >= DISK_WARN_PERCENT )); then
  current_disk_flag=1
  if [[ "${disk_prev:-0}" -ge 1 ]]; then
    alert "WARNING" "system_health" "Disk warning: ${disk}% (threshold: ${DISK_WARN_PERCENT}%)"
  fi
fi

# --- Memory + Swap (correlated) ---
# Low available memory ALONE might be fine (Linux uses RAM for caching).
# Low memory + high swap = the system is actually struggling.
# This correlation reduces false positives significantly.
if (( mem_pct < MEM_CRIT_PERCENT )) && (( swap >= SWAP_CRIT_KB )); then
  current_mem_flag=2
  if [[ "${mem_prev:-0}" -ge 1 ]]; then
    alert "CRITICAL" "system_health" "Severe memory pressure: ${mem_pct}% available, swap ${swap}kB used"
  fi
elif (( mem_pct < MEM_WARN_PERCENT )) && (( swap > 0 )); then
  current_mem_flag=1
  if [[ "${mem_prev:-0}" -ge 1 ]]; then
    alert "WARNING" "system_health" "Memory pressure: ${mem_pct}% available, swap ${swap}kB used"
  fi
fi

# --- Process count ---
# Compares against baseline to detect abnormal spikes
# A fork bomb or malware spawning processes would trigger this
# Skip if baseline is missing (file_integrity.sh already warns about this)
if [[ -n "$baseline_proc" ]]; then
  if (( proc_count >= crit_proc )); then
    current_proc_flag=2
    if [[ "${proc_prev:-0}" -ge 1 ]]; then
      alert "CRITICAL" "system_health" "Process spike: ${proc_count} (baseline: ${baseline_proc})"
    fi
  elif (( proc_count >= warn_proc )); then
    current_proc_flag=1
    if [[ "${proc_prev:-0}" -ge 1 ]]; then
      alert "WARNING" "system_health" "Process increase: ${proc_count} (baseline: ${baseline_proc})"
    fi
  fi
fi

# ============================================================================
# IMMEDIATE ALERTS (no temporal logic — these are always important)
# ============================================================================

# Failed services = something broke, alert immediately
if (( failed_services >= FAILED_SERVICES_CRIT )); then
  alert "CRITICAL" "system_health" "Failed systemd services: ${failed_services}"
fi

# Error log volume
if (( error_logs >= ERROR_LOG_CRIT_COUNT )); then
  alert "CRITICAL" "system_health" "High error log volume: ${error_logs} recent errors"
elif (( error_logs >= ERROR_LOG_WARN_COUNT )); then
  alert "WARNING" "system_health" "Elevated error logs: ${error_logs} recent errors"
fi

# Recent reboot — unexpected reboots on a production server are suspicious
if (( uptime_seconds < RECENT_REBOOT_SECONDS )); then
  alert "WARNING" "system_health" "Recent reboot detected: ${uptime_seconds}s ago"
fi

# ============================================================================
# SAVE STATE for next cycle's temporal logic
# ============================================================================
cat > "$STATE_FILE" <<EOF
load_prev=$current_load_flag
disk_prev=$current_disk_flag
mem_prev=$current_mem_flag
proc_prev=$current_proc_flag
EOF
