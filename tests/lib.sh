#!/bin/bash
# ============================================================================
# lib.sh — Shared helpers for every test_*.sh file
# ============================================================================
# Contract every test file must honour:
#   1. Call journal_log BEFORE any destructive action (useradd, write to
#      /etc, chmod on a real file). This is the recovery record read by
#      rollback.sh if the test crashes before cleanup runs.
#   2. Call backup_file before overwriting any real file — backup path is
#      returned and must be passed to the corresponding journal_log line.
#   3. Register a cleanup function with register_cleanup. run_all.sh will
#      call every registered cleanup in reverse order on EXIT.
#
# Why a journal AND registered cleanups:
#   - Registered cleanups run on normal test completion / failure / Ctrl-C.
#   - The journal survives a brutal kill -9 / power loss / test harness
#     panic. rollback.sh replays it to undo what cleanups never got to do.
# ============================================================================

# Resolve HIDS_DIR = parent of tests/
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HIDS_DIR="$(cd "$TESTS_DIR/.." && pwd)"
export HIDS_DIR

# v2 collectors (file_integrity, user_activity, process_network, system_health)
# wrap their body in a self-looping re-exec (Stage 2 of the v2 refactor).
# Tests invoke each module as a one-shot to make assertions against alerts.json
# and then return — so we disable the wrapper globally for the test harness.
# Without this, `bash modules/foo.sh` would run forever and every test hangs.
export HIDS_SELF_LOOP=0

# Tag every alert fired during this test session so ops can distinguish real
# alerts from test-generated ones. alerting.sh adds a "test_run": "<id>"
# field to the JSON and prepends [TEST] to the console line when this is set.
# Value is the unix ts of the test run so each session is uniquely attributable.
export HIDS_TEST_RUN="$(date +%s)"

JOURNAL="$TESTS_DIR/.test_journal.log"
BACKUP_DIR="$TESTS_DIR/.test_backup"

mkdir -p "$BACKUP_DIR"
touch "$JOURNAL"

# --- Colors (guarded for non-TTY) ---
if [[ -t 1 ]]; then
  C_RED=$'\033[1;31m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
  C_BLUE=$'\033[1;34m'; C_NC=$'\033[0m'
else
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_NC=''
fi

# Counters populated by run_test — read by run_all.sh at the end
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
FAILED_NAMES=()

# Registered cleanup functions (called in reverse order)
_CLEANUP_FUNCS=()

# ----------------------------------------------------------------------------
# journal_log ACTION ARG1 [ARG2 ...]
# Appends one pipe-delimited line to the journal. Call BEFORE the action
# is performed so a crash mid-action is still recoverable.
# ----------------------------------------------------------------------------
journal_log() {
  local line
  printf -v line '%s' "$1"
  shift
  for a in "$@"; do
    line+="|$a"
  done
  echo "$line" >> "$JOURNAL"
}

# ----------------------------------------------------------------------------
# backup_file PATH
# Copies PATH to $BACKUP_DIR with a unique name. Echos the backup path.
# Records the mapping in the journal so rollback.sh can restore.
# Returns non-zero if the source file does not exist.
# ----------------------------------------------------------------------------
backup_file() {
  local src="$1"
  [[ -f "$src" ]] || return 1
  local uniq="$(date +%s)_$$_$RANDOM"
  local dest="$BACKUP_DIR/$(basename "$src").$uniq.bak"
  cp -p "$src" "$dest"
  journal_log "file_write" "$src" "$dest"
  echo "$dest"
}

# ----------------------------------------------------------------------------
# register_cleanup FUNCTION_NAME
# Adds the function to the cleanup stack. run_all.sh trap EXIT invokes
# every registered cleanup in reverse insertion order.
# ----------------------------------------------------------------------------
register_cleanup() {
  _CLEANUP_FUNCS+=("$1")
}

# Called by run_all.sh at the end (or by Ctrl-C handler)
run_all_cleanups() {
  local i
  for (( i=${#_CLEANUP_FUNCS[@]}-1; i>=0; i-- )); do
    # Each cleanup is wrapped in || true so one failure doesn't abort the chain
    "${_CLEANUP_FUNCS[i]}" 2>/dev/null || true
  done
  _CLEANUP_FUNCS=()
}

# ----------------------------------------------------------------------------
# assert_alert SEVERITY MODULE PATTERN
# Greps $HIDS_DIR/logs/alerts.json for a JSON entry where
# severity == SEVERITY, module == MODULE, and message contains PATTERN.
# Returns 0 if found, 1 otherwise. PATTERN is a fixed string (no regex).
# ----------------------------------------------------------------------------
assert_alert() {
  local severity="$1" module="$2" pattern="$3"
  local alerts="$HIDS_DIR/logs/alerts.json"
  [[ -f "$alerts" ]] || return 1
  # Each alert is 7 lines { ... }. Use awk to read one record at a time.
  awk -v sev="$severity" -v mod="$module" -v pat="$pattern" '
    /^\{$/ { in_obj=1; sev_m=0; mod_m=0; msg_m=0; next }
    /^\}$/ {
      if (in_obj && sev_m && mod_m && msg_m) { found=1; exit }
      in_obj=0; next
    }
    in_obj {
      if (index($0, "\"severity\": \"" sev "\"")) sev_m=1
      if (index($0, "\"module\": \"" mod "\""))   mod_m=1
      if (index($0, pat))                          msg_m=1
    }
    END { exit (found ? 0 : 1) }
  ' "$alerts"
}

# ----------------------------------------------------------------------------
# assert_file_exists PATH
# ----------------------------------------------------------------------------
assert_file_exists() {
  [[ -f "$1" ]]
}

# ----------------------------------------------------------------------------
# assert_eq EXPECTED ACTUAL [MESSAGE]
# ----------------------------------------------------------------------------
assert_eq() {
  if [[ "$1" != "$2" ]]; then
    echo "    ${C_RED}✗ assert_eq failed${C_NC}: expected='$1' actual='$2' ${3:-}"
    return 1
  fi
}

# ----------------------------------------------------------------------------
# run_test NAME FUNCTION
# Invokes FUNCTION. Prints PASS/FAIL. Updates counters.
# The test function should return 0 on success, non-zero on failure.
# ----------------------------------------------------------------------------
run_test() {
  local name="$1" fn="$2"
  echo ""
  echo "${C_BLUE}▶${C_NC} $name"
  if "$fn"; then
    echo "  ${C_GREEN}✓ PASS${C_NC}"
    (( TESTS_PASSED++ ))
  else
    echo "  ${C_RED}✗ FAIL${C_NC}"
    (( TESTS_FAILED++ ))
    FAILED_NAMES+=("$name")
  fi
}

# ----------------------------------------------------------------------------
# skip_test NAME REASON
# Marks a test as skipped (e.g. --invasive flag not set).
# ----------------------------------------------------------------------------
skip_test() {
  echo ""
  echo "${C_YELLOW}⊘ SKIP${C_NC} $1 — $2"
  (( TESTS_SKIPPED++ ))
}

# ----------------------------------------------------------------------------
# require_root
# Aborts the current test if not running as root. Returns non-zero so the
# caller can skip gracefully.
# ----------------------------------------------------------------------------
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "    ${C_YELLOW}requires root — skipping${C_NC}"
    return 1
  fi
}

# ----------------------------------------------------------------------------
# require_invasive
# Returns 0 if INVASIVE=1 (env var), non-zero otherwise.
# Used by tests that modify the real system (useradd, /etc writes).
# ----------------------------------------------------------------------------
require_invasive() {
  [[ "${INVASIVE:-0}" == "1" ]]
}

# ----------------------------------------------------------------------------
# clear_dedup_state
# Empties alerting.sh's dedup file so repeated tests always produce an
# alert (otherwise a previous identical alert would silence a retest).
# ----------------------------------------------------------------------------
clear_dedup_state() {
  local state="$HIDS_DIR/run/alert_state.txt"
  if [[ -f "$state" ]]; then
    journal_log "truncate" "$state" "$(backup_file "$state")"
    : > "$state"
  fi
}
