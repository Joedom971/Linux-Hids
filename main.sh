#!/bin/bash
# ============================================================================
# main.sh — HIDS entry point
# ============================================================================
# This is the script you run. It does 3 things:
#   1. Prevents two instances from running simultaneously (lock.pid)
#   2. On first run (--init), creates the baseline reference
#   3. Launches the controller loop
#
# Usage:
#   sudo bash main.sh           → start the HIDS in normal mode
#   sudo bash main.sh --init    → create baseline then start the HIDS
#
# BUG FIXED: baseline.sh was never called in the original code.
# BUG FIXED: lock.pid was in the project tree but never implemented.
# ============================================================================

# Resolve the absolute path of the project (avoids relative path issues)
DIR="$(cd "$(dirname "$0")" && pwd)"

# Export HIDS_DIR BEFORE sourcing config so path values can reference it
export HIDS_DIR="$DIR"

# Load global config (reads LOG_DIR/BASELINE_DIR built from $HIDS_DIR)
source "$DIR/config/hids.conf"

# --- Root check ---
# The HIDS needs to read /proc, /etc/shadow, /var/log/audit, etc.
if [[ $EUID -ne 0 ]]; then
  echo "[-] This script must be run as root (sudo)."
  exit 1
fi

# --- Lock file: prevent two simultaneous instances ---
# If lock.pid exists AND the process is still alive, refuse to start.
# This prevents two HIDS from writing to the same log files.
LOCK_FILE="$DIR/run/lock.pid"
mkdir -p "$DIR/run"

if [[ -f "$LOCK_FILE" ]]; then
  old_pid=$(cat "$LOCK_FILE")
  if kill -0 "$old_pid" 2>/dev/null; then
    echo "[-] HIDS already running (PID $old_pid)."
    if systemctl is-active --quiet hids 2>/dev/null; then
      echo "    It is running as a systemd service. Use:"
      echo "      systemctl stop hids       → stop the HIDS"
      echo "      systemctl restart hids    → restart the HIDS"
      echo "      journalctl -u hids -f     → follow live logs"
    else
      echo "    Stop it first (kill $old_pid) or wait for it to finish."
    fi
    exit 1
  else
    # Process is dead but the file remained (previous crash)
    echo "[!] Stale lock found, cleaning up..."
    rm -f "$LOCK_FILE"
  fi
fi

# Write our PID to the lock file
echo $$ > "$LOCK_FILE"

# Clean up the lock on exit (Ctrl+C, kill, or normal termination).
# --init mode exits cleanly after baseline creation and should not claim the
# HIDS "stopped" (it was never running); only announce a stop for the full run.
cleanup() {
  rm -f "$LOCK_FILE"
  [[ "$1" != "--init" ]] && echo '[+] HIDS stopped.'
  exit 0
}
trap 'cleanup "$1"' EXIT INT TERM

# --- Create required directories (paths come from hids.conf) ---
mkdir -p "$LOG_DIR" "$BASELINE_DIR"

# --- Init mode: create the baseline ---
# The baseline = snapshot of the machine's healthy state (users, hashes, ports, SUID).
# Without a baseline, modules cannot detect changes.
if [[ "$1" == "--init" ]]; then
  echo "[+] Initializing baseline..."
  source "$DIR/config/file_integrity.conf"
  source "$DIR/modules/baseline.sh"
  init_baseline
  echo "[+] Baseline created in $BASELINE_DIR/"
  exit 0
fi

echo "[+] Starting SOC HIDS (PID $$)..."
echo "[+] Interval: ${RUN_INTERVAL}s | Logs: $LOG_DIR/"
echo "[+] Press Ctrl+C to stop."

# Launch the main loop
bash "$DIR/controller.sh"
