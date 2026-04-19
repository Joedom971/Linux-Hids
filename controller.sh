#!/bin/bash
# ============================================================================
# controller.sh — HIDS supervisor (v2)
# ============================================================================
# v1 ran every module sequentially in one loop: any hang or crash blocked
# the next cycle, so modules were not truly independent.
#
# v2 runs the four collectors (file_integrity, user_activity,
# process_network, system_health) as independent backgrounded processes.
# If one dies, the others keep running and the supervisor relaunches it.
#
# The pipeline (auditd_parser -> enrichment -> correlation_engine) stays
# sequential; it's stateless per cycle, so a failed tick is safely retried.
# It runs on its own timer inside the supervisor.
#
# Collector modes:
#   scheduled  - module runs one-shot, supervisor re-launches after the
#                interval elapses (Stage 1 default)
#   continuous - module loops internally and stays alive; supervisor only
#                relaunches on death (Stage 2)
#
# Crash-loop guard: CRASH_LIMIT non-zero exits within CRASH_WINDOW seconds
# puts the module in cooldown for CRASH_COOLDOWN seconds, with a CRITICAL
# alert so the operator knows it was quarantined.
#
# SIGTERM/SIGINT kills every child and exits cleanly.
# ============================================================================

DIR="$(cd "$(dirname "$0")" && pwd)"
export HIDS_DIR="$DIR"

source "$DIR/config/hids.conf"
source "$DIR/config/file_integrity.conf"
source "$DIR/config/thresholds.conf"
source "$DIR/config/auditd.conf"
source "$DIR/modules/alerting.sh"   # alert() used by the supervisor itself

CRASH_LIMIT="${CRASH_LIMIT:-3}"
CRASH_WINDOW="${CRASH_WINDOW:-300}"
CRASH_COOLDOWN="${CRASH_COOLDOWN:-300}"
SUPERVISOR_TICK="${SUPERVISOR_TICK:-1}"
# Minimum seconds between relaunches. Prevents a hot loop if a continuous
# module exits immediately (e.g. missing dependency binary).
MIN_RESTART_GAP="${MIN_RESTART_GAP:-5}"

FI_INTERVAL="${FI_INTERVAL:-$RUN_INTERVAL}"
UA_INTERVAL="${UA_INTERVAL:-$RUN_INTERVAL}"
PN_INTERVAL="${PN_INTERVAL:-$RUN_INTERVAL}"
# system_health alert cadence: 30s is enough given 2-cycle temporal logic.
# The 3s display refresh lives in system_health_dashboard.sh.
SH_INTERVAL="${SH_INTERVAL:-30}"

COLLECTOR_NAMES=(file_integrity user_activity process_network system_health user_activity_events file_integrity_events system_health_dashboard)
COLLECTOR_PATHS=(
  "$DIR/modules/file_integrity.sh"
  "$DIR/modules/user_activity.sh"
  "$DIR/modules/process_network.sh"
  "$DIR/modules/system_health.sh"
  "$DIR/modules/user_activity_events.sh"
  "$DIR/modules/file_integrity_events.sh"
  "$DIR/modules/system_health_dashboard.sh"
)
# Intervals: irrelevant for continuous-mode collectors; kept for override/debug.
COLLECTOR_INTERVALS=("$FI_INTERVAL" "$UA_INTERVAL" "$PN_INTERVAL" "$SH_INTERVAL" 0 0 0)
# All self-loop internally; event collectors use tail -F / inotify; dashboard uses 3s display loop.
COLLECTOR_MODES=(continuous continuous continuous continuous continuous continuous continuous)

declare -a PIDS=(0 0 0 0 0 0 0)
declare -a LAST_START=(0 0 0 0 0 0 0)
declare -a CRASH_COUNT=(0 0 0 0 0 0 0)
declare -a CRASH_WIN_START=(0 0 0 0 0 0 0)
declare -a COOLDOWN_UNTIL=(0 0 0 0 0 0 0)
LAST_PIPELINE=0

now() { date +%s; }

is_alive() {
  local pid=$1
  [[ $pid -gt 0 ]] && kill -0 "$pid" 2>/dev/null
}

launch_collector() {
  local i=$1
  local name="${COLLECTOR_NAMES[$i]}"
  local path="${COLLECTOR_PATHS[$i]}"
  local logfile="$LOG_DIR/$name.log"
  bash "$path" >> "$logfile" 2>&1 &
  PIDS[$i]=$!
  LAST_START[$i]=$(now)
}

record_crash() {
  local i=$1
  local name="${COLLECTOR_NAMES[$i]}"
  local t; t=$(now)
  if (( t - CRASH_WIN_START[i] > CRASH_WINDOW )); then
    CRASH_WIN_START[$i]=$t
    CRASH_COUNT[$i]=0
  fi
  CRASH_COUNT[$i]=$(( CRASH_COUNT[i] + 1 ))
  if (( CRASH_COUNT[i] >= CRASH_LIMIT )); then
    COOLDOWN_UNTIL[$i]=$(( t + CRASH_COOLDOWN ))
    CRASH_COUNT[$i]=0
    alert "CRITICAL" "controller" \
      "module '$name' quarantined after $CRASH_LIMIT crashes in ${CRASH_WINDOW}s; cooldown ${CRASH_COOLDOWN}s"
  fi
}

# NOTE: must be called from the supervisor's own shell (NOT inside $(...)),
# because `wait` only works on children of the current shell. A previous
# version of this function used command substitution, which put wait in a
# subshell where the pid wasn't a known child -> wait returned 127 and we
# reported false crashes.
#
# Sets the global EXIT_CODE. Returns 0 if the process was reaped, 1 if it's
# still alive (caller should not have invoked this).
reap_collector() {
  local pid=$1
  if kill -0 "$pid" 2>/dev/null; then
    return 1
  fi
  wait "$pid" 2>/dev/null
  EXIT_CODE=$?
  return 0
}

run_pipeline() {
  {
    if [[ "$ENABLE_AUDITD" == "true" ]]; then
      bash "$DIR/modules/auditd_parser.sh" || return 1
    fi
    bash "$DIR/modules/enrichment.sh"         || return 2
    bash "$DIR/modules/correlation_engine.sh" || return 3
  } >> "$LOG_DIR/pipeline.log" 2>&1
}

# Recursively signal the entire process subtree rooted at $1.
# Necessary because bash doesn't auto-propagate signals to its children.
# Without this, a collector's `tail -F` or `sleep` (grandchildren of the
# supervisor) survive shutdown as orphans.
# Strategy: signal children first, then the parent, so the parent can't
# fork new descendants while we're killing its existing ones.
kill_tree() {
  local parent=$1
  local sig=${2:-TERM}
  local children child
  children=$(pgrep -P "$parent" 2>/dev/null)
  for child in $children; do
    kill_tree "$child" "$sig"
  done
  kill "-$sig" "$parent" 2>/dev/null
}

shutdown() {
  echo "[controller] shutdown: stopping child processes..."
  local i
  for i in "${!PIDS[@]}"; do
    is_alive "${PIDS[$i]}" && kill_tree "${PIDS[$i]}" TERM
  done
  sleep 2
  # Anything that didn't honor TERM within 2s gets KILL'd, tree and all.
  for i in "${!PIDS[@]}"; do
    is_alive "${PIDS[$i]}" && kill_tree "${PIDS[$i]}" KILL
  done
  # Stop the alert-stream tail
  [[ -n "${TAIL_PID:-}" ]] && kill "$TAIL_PID" 2>/dev/null
  echo "[controller] stopped."
  exit 0
}
trap shutdown TERM INT

# ----------------------------------------------------------------------------
# Friendly startup banner — one line per collector with its actual cadence,
# plus hints on where the user can watch alerts and the live dashboard.
# ----------------------------------------------------------------------------
describe_cadence() {
  case "$1" in
    file_integrity)           echo "poll every ${FI_INTERVAL}s" ;;
    user_activity)            echo "poll every ${UA_INTERVAL}s" ;;
    process_network)          echo "poll every ${PN_INTERVAL}s" ;;
    system_health)            echo "poll every ${SH_INTERVAL}s (alerting)" ;;
    user_activity_events)     echo "event-driven (auditd tail)" ;;
    file_integrity_events)    echo "event-driven (inotify)" ;;
    system_health_dashboard)  echo "refresh every ${SH_DISPLAY_INTERVAL:-3}s (display only)" ;;
    *)                        echo "—" ;;
  esac
}

C_B=$'\033[1;34m'; C_D=$'\033[2m'; C_N=$'\033[0m'
echo "${C_B}HIDS supervisor started${C_N} ${C_D}(pid $$)${C_N}"
echo "${C_D}───────────────────────────────────────────────────────${C_N}"
echo "  Active modules:"
for i in "${!COLLECTOR_NAMES[@]}"; do
  printf "    %-26s ${C_D}%s${C_N}\n" "${COLLECTOR_NAMES[$i]}" "$(describe_cadence "${COLLECTOR_NAMES[$i]}")"
done
echo "${C_D}───────────────────────────────────────────────────────${C_N}"
echo "  Alerts stream live below. Also persisted to logs/alerts.json."
echo "  Watch dashboard   :  watch -n 1 --color cat $LOG_DIR/system_health.status"
echo "  Dashboard         :  watch -n 1 --color cat logs/system_health.status"
echo "  Stop              :  Ctrl+C  (or: sudo systemctl stop hids)"
echo "${C_D}───────────────────────────────────────────────────────${C_N}"

# Start the live alert tail. -n0 = only show new alerts fired AFTER startup
# (anything older is already in logs/alerts.json). Runs in background so the
# supervisor loop below keeps working. Its pid is tracked so shutdown kills it.
ALERT_TAIL_LOG="$LOG_DIR/alerts.console.log"
touch "$ALERT_TAIL_LOG"
tail -n 0 -F "$ALERT_TAIL_LOG" 2>/dev/null &
TAIL_PID=$!

while true; do
  t=$(now)

  for i in "${!COLLECTOR_NAMES[@]}"; do
    name="${COLLECTOR_NAMES[$i]}"
    mode="${COLLECTOR_MODES[$i]}"
    interval="${COLLECTOR_INTERVALS[$i]}"
    pid="${PIDS[$i]}"

    if (( t < COOLDOWN_UNTIL[i] )); then
      continue
    fi

    if is_alive "$pid"; then
      continue
    fi

    if (( pid > 0 )); then
      EXIT_CODE=0
      reap_collector "$pid"
      PIDS[$i]=0
      if (( EXIT_CODE != 0 )); then
        alert "WARNING" "controller" "module '$name' exited with code $EXIT_CODE"
        record_crash "$i"
        continue
      fi
    fi

    case "$mode" in
      scheduled)
        if (( t - LAST_START[i] >= interval )); then
          launch_collector "$i"
        fi
        ;;
      continuous)
        if (( t - LAST_START[i] >= MIN_RESTART_GAP )); then
          launch_collector "$i"
        fi
        ;;
    esac
  done

  if (( t - LAST_PIPELINE >= RUN_INTERVAL )); then
    run_pipeline &
    LAST_PIPELINE=$t
  fi

  sleep "$SUPERVISOR_TICK"
done
