#!/bin/bash
# ============================================================================
# test_process_network.sh — Simulate attacker presence on the host
# ============================================================================
# Four attack scenarios against process_network.sh. All actors are
# short-lived and journaled for rollback.sh cleanup.
#
# Safety: all four are SAFE (no real system users, no /etc writes).
#   P1 — binds a high port
#   P2 — drops + runs a payload from /tmp
#   P3 — binds on 0.0.0.0 (wildcard) on a non-allowed port
#   P4 — LD_PRELOAD injection into a child process
# ============================================================================

# ---------------------------------------------------------------------------
# P1 — Reverse-shell listener: attacker opens an unexpected port
# ---------------------------------------------------------------------------
_attack_rogue_listener() {
  require_root || return 0
  command -v nc &>/dev/null || { echo "    nc missing — skipped"; return 0; }

  local port=31733
  # ATTACK: open a listener on a port not in the baseline
  nc -l -p "$port" >/dev/null 2>&1 &
  local listener=$!
  journal_log "port_listener" "$listener"
  sleep 1

  clear_dedup_state
  bash "$HIDS_DIR/modules/process_network.sh" >/dev/null

  local ok=1
  assert_alert "WARNING" "network" "$port" && ok=0 || true

  kill "$listener" 2>/dev/null || true
  wait  "$listener" 2>/dev/null || true
  return $ok
}

# ---------------------------------------------------------------------------
# P2 — Dropper: payload planted in /tmp and executed
# ---------------------------------------------------------------------------
_attack_tmp_execution() {
  require_root || return 0

  local payload="/tmp/.hids_drop_$$"
  cp /bin/sleep "$payload"
  chmod +x "$payload"
  journal_log "tmpfile" "$payload"

  # ATTACK: run a binary staged in /tmp
  "$payload" 15 &
  local runpid=$!
  journal_log "port_listener" "$runpid"   # reuse "kill PID" action
  sleep 1

  clear_dedup_state
  bash "$HIDS_DIR/modules/process_network.sh" >/dev/null

  local ok=1
  assert_alert "CRITICAL" "process" "$payload" && ok=0 || true

  kill "$runpid" 2>/dev/null || true
  wait "$runpid" 2>/dev/null || true
  rm -f "$payload"
  return $ok
}

# ---------------------------------------------------------------------------
# P3 — Wildcard bind: service exposed to the whole network
#   Attacker scenario: open a port on 0.0.0.0 (not localhost) — common for
#   accidentally-exposed backdoors.
# ---------------------------------------------------------------------------
_attack_wildcard_bind() {
  require_root || return 0
  command -v nc &>/dev/null || { echo "    nc missing — skipped"; return 0; }

  local port=31744
  # ATTACK: wildcard bind
  nc -l -p "$port" -s 0.0.0.0 >/dev/null 2>&1 &
  local listener=$!
  journal_log "port_listener" "$listener"
  sleep 1

  clear_dedup_state
  bash "$HIDS_DIR/modules/process_network.sh" >/dev/null

  local ok=1
  assert_alert "WARNING" "network" "0.0.0.0" && ok=0
  assert_alert "WARNING" "network" "$port"   && ok=0

  kill "$listener" 2>/dev/null || true
  wait "$listener" 2>/dev/null || true
  return $ok
}

# ---------------------------------------------------------------------------
# P4 — LD_PRELOAD injection (credential-stealer backdoor)
#   Attacker scenario: launch a process with LD_PRELOAD pointing at a
#   shared library, so every syscall in that process goes through the
#   attacker's hook (classic sudo-password stealer).
# ---------------------------------------------------------------------------
_attack_ld_preload() {
  require_root || return 0

  local lib="/tmp/.hids_ld_$$.so"
  # A zero-byte file is enough — the detector only reads the env var, not
  # the library itself. Using a real hook would work but isn't needed.
  : > "$lib"
  journal_log "tmpfile" "$lib"

  # ATTACK: long-running process with LD_PRELOAD set
  env LD_PRELOAD="$lib" sleep 15 &
  local runpid=$!
  journal_log "port_listener" "$runpid"
  sleep 1

  clear_dedup_state
  bash "$HIDS_DIR/modules/process_network.sh" >/dev/null

  local ok=1
  assert_alert "CRITICAL" "process" "LD_PRELOAD" && ok=0 || true

  kill "$runpid" 2>/dev/null || true
  wait "$runpid" 2>/dev/null || true
  rm -f "$lib"
  return $ok
}

main() {
  run_test "PN P1 — attacker opens rogue listening port"      _attack_rogue_listener
  run_test "PN P2 — dropper executes payload from /tmp"       _attack_tmp_execution
  run_test "PN P3 — wildcard 0.0.0.0 bind on non-allowed port" _attack_wildcard_bind
  run_test "PN P4 — LD_PRELOAD credential-stealer injection"   _attack_ld_preload
}
