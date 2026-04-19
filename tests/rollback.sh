#!/bin/bash
# ============================================================================
# rollback.sh — Replay the test journal to undo what tests did
# ============================================================================
# Normal path: run_all.sh registers cleanups for every test; trap EXIT
# invokes them and the system is left clean.
#
# Failure path this script handles:
#   - kill -9 / Ctrl-C during cleanup
#   - a test crashed before register_cleanup was called but AFTER
#     journal_log recorded the destructive action
#   - the test host was rebooted mid-run
#
# We read .test_journal.log line by line (earliest first) and undo each
# action. For file writes we also restore from the backup captured in
# $BACKUP_DIR. On success we truncate the journal so a re-run is a no-op.
#
# Journal line formats:
#   useradd|<username>
#   file_write|<target_path>|<backup_path>
#   truncate|<target_path>|<backup_path>
#   chmod|<target_path>|<original_octal_mode>
#   port_listener|<pid>
#
# Usage:
#   sudo bash tests/rollback.sh            → replay
#   sudo bash tests/rollback.sh --dry-run  → show actions without doing them
# ============================================================================

set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
JOURNAL="$TESTS_DIR/.test_journal.log"

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) DRY_RUN=1 ;;
    --help|-h)    sed -n '2,30p' "$0"; exit 0 ;;
    *)            echo "Unknown flag: $arg"; exit 2 ;;
  esac
done

if [[ ! -s "$JOURNAL" ]]; then
  echo "[+] Journal is empty — nothing to roll back."
  exit 0
fi

if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
  echo "[-] rollback.sh must run as root (some actions touch /etc)."
  echo "    Use --dry-run to see what would happen without root."
  exit 1
fi

run() {
  # Pretty-prints the command, then runs it unless --dry-run
  echo "  → $*"
  (( DRY_RUN == 0 )) && "$@"
}

echo "[+] Replaying $JOURNAL"
echo ""

# Read the journal into an array so we can iterate in REVERSE order —
# later actions might depend on earlier state, so we undo latest-first.
mapfile -t lines < "$JOURNAL"

for (( i=${#lines[@]}-1; i>=0; i-- )); do
  line="${lines[i]}"
  [[ -z "$line" ]] && continue

  IFS='|' read -r action arg1 arg2 arg3 <<< "$line"

  case "$action" in

    useradd)
      # arg1 = username
      if id "$arg1" &>/dev/null; then
        echo "[undo] deleting user: $arg1"
        run userdel -r "$arg1" 2>/dev/null || run userdel "$arg1"
      else
        echo "[skip] user $arg1 not present"
      fi
      ;;

    file_write|truncate)
      # arg1 = target path, arg2 = backup path
      if [[ -f "$arg2" ]]; then
        echo "[undo] restoring $arg1 from $arg2"
        run cp -p "$arg2" "$arg1"
        run rm -f "$arg2"
      else
        echo "[skip] backup missing for $arg1 (was: $arg2)"
      fi
      ;;

    chmod)
      # arg1 = path, arg2 = original mode
      if [[ -e "$arg1" ]]; then
        echo "[undo] chmod $arg2 $arg1"
        run chmod "$arg2" "$arg1"
      else
        echo "[skip] $arg1 no longer exists"
      fi
      ;;

    port_listener)
      # arg1 = pid of the listener we spawned
      if [[ -n "${arg1:-}" ]] && kill -0 "$arg1" 2>/dev/null; then
        echo "[undo] killing listener PID $arg1"
        run kill "$arg1" 2>/dev/null || run kill -9 "$arg1"
      else
        echo "[skip] listener PID $arg1 already gone"
      fi
      ;;

    tmpfile)
      # arg1 = path to remove (created during test)
      if [[ -e "$arg1" ]]; then
        echo "[undo] removing $arg1"
        run rm -rf "$arg1"
      fi
      ;;

    *)
      echo "[warn] unknown journal action: $action ($line)"
      ;;
  esac
done

echo ""
if (( DRY_RUN == 0 )); then
  : > "$JOURNAL"
  echo "[+] Rollback complete. Journal cleared."
else
  echo "[+] Dry run — no changes applied. Journal preserved."
fi
