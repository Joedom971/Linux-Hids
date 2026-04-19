#!/bin/bash
# ============================================================================
# run_all.sh — HIDS test orchestrator
# ============================================================================
# Discovers every tests/test_*.sh file and runs it. Each test file sources
# lib.sh and registers its own cleanup functions. trap EXIT ensures every
# registered cleanup runs on normal completion OR on Ctrl-C.
#
# Flags:
#   --module NAME   Run only tests/test_NAME.sh (without the test_ prefix)
#   --invasive      Enable tests that touch the real system (useradd, /etc)
#                   Without this flag those tests are skipped.
#   --list          Print test files and exit
#
# Env override:
#   INVASIVE=1      same as --invasive
#
# Exit codes:
#   0   every test passed (or was cleanly skipped)
#   1   at least one test failed
#   2   usage error
# ============================================================================

set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
HIDS_DIR="$(cd "$TESTS_DIR/.." && pwd)"
export HIDS_DIR

# --- flag parsing ---
ONLY_MODULE=""
LIST_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --module)    ONLY_MODULE="$2"; shift 2 ;;
    --invasive)  export INVASIVE=1; shift ;;
    --list)      LIST_ONLY=1; shift ;;
    --help|-h)   sed -n '2,26p' "$0"; exit 0 ;;
    *)           echo "Unknown flag: $1"; exit 2 ;;
  esac
done

# --- discover tests ---
shopt -s nullglob
if [[ -n "$ONLY_MODULE" ]]; then
  TESTS=("$TESTS_DIR/test_${ONLY_MODULE}.sh")
  [[ -f "${TESTS[0]}" ]] || { echo "No test file for module: $ONLY_MODULE"; exit 2; }
else
  TESTS=("$TESTS_DIR"/test_*.sh)
fi

if (( LIST_ONLY == 1 )); then
  printf '%s\n' "${TESTS[@]}"
  exit 0
fi

source "$TESTS_DIR/lib.sh"

# --- trap: make sure cleanups run on ANY exit path ---
on_exit() {
  # Run cleanups registered by any test that did not clean up yet
  run_all_cleanups
  # Show final summary
  echo ""
  echo "=============================================="
  echo "Summary:"
  echo "  ${C_GREEN}PASS${C_NC}: $TESTS_PASSED"
  echo "  ${C_RED}FAIL${C_NC}: $TESTS_FAILED"
  echo "  ${C_YELLOW}SKIP${C_NC}: $TESTS_SKIPPED"
  if (( TESTS_FAILED > 0 )); then
    echo ""
    echo "  Failed tests:"
    for n in "${FAILED_NAMES[@]}"; do
      echo "    - $n"
    done
  fi
  if [[ -s "$JOURNAL" ]]; then
    echo ""
    echo "  ${C_YELLOW}Journal still has entries${C_NC} — run:"
    echo "    sudo bash $TESTS_DIR/rollback.sh"
  fi
  echo ""
  echo "  Test alerts tagged with test_run=${HIDS_TEST_RUN}. Useful commands:"
  echo "    jq 'select(.test_run == null)' $HIDS_DIR/logs/alerts.json   # real alerts only"
  echo "    jq 'select(.test_run == \"${HIDS_TEST_RUN}\")' $HIDS_DIR/logs/alerts.json  # this run"
  echo "    # To remove them from alerts.json:"
  echo "    jq -s 'map(select(.test_run == null))[]' $HIDS_DIR/logs/alerts.json > /tmp/a && mv /tmp/a $HIDS_DIR/logs/alerts.json"
  echo "=============================================="
  # Propagate failure to the caller (CI, script chain)
  (( TESTS_FAILED == 0 ))
}
trap 'on_exit; exit $?' EXIT INT TERM

# --- banner ---
echo "=============================================="
echo "HIDS test suite"
echo "  HIDS_DIR    = $HIDS_DIR"
echo "  INVASIVE    = ${INVASIVE:-0}"
echo "  root        = $(( EUID == 0 ? 1 : 0 ))"
echo "=============================================="

# --- execute each test file ---
# Each test file exposes a function 'main' that wraps its own run_test calls.
# Sourcing rather than forking keeps all counters and the cleanup stack in
# the same shell session.
for t in "${TESTS[@]}"; do
  echo ""
  echo "${C_BLUE}╔═══════════════════════════════════════${C_NC}"
  echo "${C_BLUE}║${C_NC} $(basename "$t")"
  echo "${C_BLUE}╚═══════════════════════════════════════${C_NC}"
  # shellcheck source=/dev/null
  source "$t"
  if declare -F main >/dev/null; then
    main
    # unset main so the next file's main doesn't collide via source
    unset -f main
  else
    echo "  ${C_YELLOW}no main() in $(basename "$t") — skipped${C_NC}"
  fi
done

# run_all_cleanups is also called by the EXIT trap, but we call it now
# so the "Journal still has entries" warning reflects post-cleanup state
run_all_cleanups
