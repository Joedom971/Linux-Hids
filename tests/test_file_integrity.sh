#!/bin/bash
# ============================================================================
# test_file_integrity.sh — Simulate attacks on protected files
# ============================================================================
# Each test plays an attacker scenario against file_integrity.sh and asserts
# the HIDS fires the expected alert. Every destructive step is journaled
# BEFORE it runs so rollback.sh can undo even a crashed test.
#
# Safety:
#   A1, A2, A3 — SAFE. Use a sandbox file under /tmp spliced into the
#                 baseline; original baseline restored from backup.
#   A4         — INVASIVE (touches real /etc/shadow). Gated by --invasive.
# ============================================================================

# ---------------------------------------------------------------------------
# A1 — Content tampering on a baselined file
#   Attacker scenario: modify a protected file's contents (e.g. insert a
#   rogue line into /etc/passwd). We simulate on a sandbox path splinted
#   into the baseline so the real /etc is untouched on a non-invasive run.
# ---------------------------------------------------------------------------
_attack_content_tamper() {
  require_root || return 0
  local files_txt="$HIDS_DIR/baselines/files.txt"
  [[ -f "$files_txt" ]] || { echo "    run main.sh --init first"; return 1; }

  local victim="/tmp/.hids_fi_A1_$$"
  echo "trusted-original" > "$victim"
  journal_log "tmpfile" "$victim"

  local bak
  bak=$(backup_file "$files_txt") || return 1
  local h m o s
  h=$(sha256sum "$victim" | awk '{print $1}')
  m=$(stat -c '%a' "$victim")
  o=$(stat -c '%U:%G' "$victim")
  s=$(stat -c '%s' "$victim")
  printf '%s  %s  %s  %s  %s\n' "$h" "$m" "$o" "$s" "$victim" >> "$files_txt"

  # ATTACK: rewrite the file's contents
  echo "rootkit-payload-injected" > "$victim"

  clear_dedup_state
  bash "$HIDS_DIR/modules/file_integrity.sh" >/dev/null

  assert_alert "CRITICAL" "file_integrity" "$victim" \
    || assert_alert "WARNING" "file_integrity" "$victim"
}

# ---------------------------------------------------------------------------
# A2 — Permission attack (chmod to leak sensitive data)
#   Attacker scenario: `chmod 644 /etc/shadow` to world-read the hashes.
#   We simulate the permission-change detection on a sandboxed baseline row.
# ---------------------------------------------------------------------------
_attack_permission_change() {
  require_root || return 0
  local files_txt="$HIDS_DIR/baselines/files.txt"
  [[ -f "$files_txt" ]] || return 1

  local victim="/tmp/.hids_fi_A2_$$"
  echo "sensitive-data" > "$victim"
  chmod 600 "$victim"
  journal_log "tmpfile" "$victim"

  local bak
  bak=$(backup_file "$files_txt") || return 1
  local h m o s
  h=$(sha256sum "$victim" | awk '{print $1}')
  m=$(stat -c '%a' "$victim")   # 600 recorded in baseline
  o=$(stat -c '%U:%G' "$victim")
  s=$(stat -c '%s' "$victim")
  printf '%s  %s  %s  %s  %s\n' "$h" "$m" "$o" "$s" "$victim" >> "$files_txt"

  # ATTACK: world-readable
  journal_log "chmod" "$victim" "600"
  chmod 644 "$victim"

  clear_dedup_state
  bash "$HIDS_DIR/modules/file_integrity.sh" >/dev/null

  assert_alert "CRITICAL" "file_integrity" "$victim" \
    || assert_alert "WARNING" "file_integrity" "$victim"
}

# ---------------------------------------------------------------------------
# A3 — Real-time tamper detected by inotify (file_integrity_events.sh)
#   Attacker scenario: modify a critical file while HIDS is running — the
#   event module should fire within ~1s, not wait for the 60s poll.
# ---------------------------------------------------------------------------
_attack_inotify_burst() {
  require_root || return 0
  command -v inotifywait &>/dev/null || {
    echo "    inotify-tools not installed — skipped"
    return 0
  }

  # Use an existing critical file the event module already watches.
  # /etc/hostname is low-impact: we back it up, touch it, restore it.
  local victim="/etc/hostname"
  [[ -f "$victim" ]] || return 1
  local bak
  bak=$(backup_file "$victim") || return 1

  # Start the event watcher in the background; let it arm its inotify watch
  bash "$HIDS_DIR/modules/file_integrity_events.sh" >/dev/null 2>&1 &
  local watcher=$!
  journal_log "port_listener" "$watcher"
  sleep 2

  # ATTACK: touch the protected file
  touch "$victim"
  sleep 2

  kill "$watcher" 2>/dev/null || true
  wait "$watcher" 2>/dev/null || true

  assert_alert "CRITICAL" "file_integrity_events" "$victim" \
    || assert_alert "CRITICAL" "file_integrity" "$victim"
}

# ---------------------------------------------------------------------------
# A4 — /etc/shadow content drift (INVASIVE)
#   Attacker scenario: pre-seed a known password hash into /etc/shadow to
#   bypass authentication. We append a harmless comment and restore.
# ---------------------------------------------------------------------------
_attack_real_shadow_drift() {
  require_root || return 0
  require_invasive || {
    echo "    invasive test — skipped (pass --invasive to enable)"
    return 0
  }
  [[ -f /etc/shadow ]] || return 1

  local bak
  bak=$(backup_file "/etc/shadow") || return 1

  # ATTACK: append a no-op line that still changes the hash
  echo "# hids-attack-simulation-$$" >> /etc/shadow

  clear_dedup_state
  bash "$HIDS_DIR/modules/file_integrity.sh" >/dev/null

  # Immediate restore — don't wait for trap
  cp -p "$bak" /etc/shadow

  assert_alert "CRITICAL" "file_integrity" "/etc/shadow"
}

main() {
  run_test "FI A1 — attacker rewrites protected file contents"  _attack_content_tamper
  run_test "FI A2 — attacker world-reads a 600 file via chmod" _attack_permission_change
  run_test "FI A3 — real-time tamper caught by inotify watcher" _attack_inotify_burst
  run_test "FI A4 — real /etc/shadow drift (INVASIVE)"          _attack_real_shadow_drift
}
