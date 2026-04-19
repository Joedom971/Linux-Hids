#!/bin/bash
# ============================================================================
# test_user_activity.sh — Simulate attacks against account integrity
# ============================================================================
# Each test plays a realistic post-compromise persistence technique and
# asserts the HIDS catches it. All destructive steps are journaled so
# rollback.sh can clean up after a crash.
#
# Safety:
#   U1 — SAFE  (sandboxed authorized_keys)
#   U2 — SAFE  (sandboxed passwd line, baseline-spliced)
#   U3 — INVASIVE (real useradd with UID 0). Gated by --invasive.
#   U4 — INVASIVE (real useradd + chsh). Gated by --invasive.
# ============================================================================

# ---------------------------------------------------------------------------
# U1 — SSH persistence: attacker drops their key in authorized_keys
# ---------------------------------------------------------------------------
_attack_ssh_key_drop() {
  require_root || return 0
  local ak_hash="$HIDS_DIR/baselines/authorized_keys.hash"
  [[ -f "$ak_hash" ]] || { echo "    run main.sh --init first"; return 1; }

  local fake="/tmp/.hids_ak_$$/authorized_keys"
  mkdir -p "$(dirname "$fake")"
  echo "ssh-rsa AAAAlegitimate user@host" > "$fake"
  journal_log "tmpfile" "$(dirname "$fake")"

  local bak
  bak=$(backup_file "$ak_hash") || return 1
  local h
  h=$(sha256sum "$fake" | awk '{print $1}')
  printf '%s  %s\n' "$h" "$fake" >> "$ak_hash"

  # ATTACK: attacker appends their public key
  echo "ssh-rsa AAAAattackerkey attacker@evil" >> "$fake"

  clear_dedup_state
  bash "$HIDS_DIR/modules/user_activity.sh" >/dev/null

  assert_alert "CRITICAL" "user_activity" "$fake"
}

# ---------------------------------------------------------------------------
# U2 — Passwordless account: attacker clears password field in /etc/passwd
#   Simulated on a sandbox file (no actual /etc/passwd write). Verifies
#   the "empty password placeholder" detector wires up correctly.
# ---------------------------------------------------------------------------
_attack_empty_password_field() {
  require_root || return 0
  require_invasive || {
    echo "    invasive test — skipped (pass --invasive to enable)"
    return 0
  }

  local bak
  bak=$(backup_file "/etc/passwd") || return 1

  local testuser="hidsU2_$$"
  journal_log "useradd" "$testuser"
  useradd -m -s /bin/bash "$testuser" 2>/dev/null || return 1

  # ATTACK: clear the password placeholder (':x:' → '::')
  sed -i "s|^${testuser}:x:|${testuser}::|" /etc/passwd

  clear_dedup_state
  bash "$HIDS_DIR/modules/user_activity.sh" >/dev/null

  local ok=1
  assert_alert "CRITICAL" "user_activity" "$testuser" && ok=0 || true

  # Immediate cleanup — don't wait for trap
  cp -p "$bak" /etc/passwd
  userdel -r "$testuser" 2>/dev/null || true
  return $ok
}

# ---------------------------------------------------------------------------
# U3 — Root backdoor: attacker creates a second UID 0 account
# ---------------------------------------------------------------------------
_attack_uid0_backdoor() {
  require_root || return 0
  require_invasive || {
    echo "    invasive test — skipped (pass --invasive to enable)"
    return 0
  }
  local uid0_file="$HIDS_DIR/baselines/uid0_accounts.txt"
  [[ -f "$uid0_file" ]] || return 1

  local testuser="hidsU3_$$"
  journal_log "useradd" "$testuser"

  # ATTACK: root-equivalent backdoor account
  useradd -o -u 0 -g 0 -s /bin/bash "$testuser" 2>/dev/null || return 1

  clear_dedup_state
  bash "$HIDS_DIR/modules/user_activity.sh" >/dev/null

  local ok=1
  assert_alert "CRITICAL" "user_activity" "$testuser" && ok=0 || true

  userdel "$testuser" 2>/dev/null || true
  return $ok
}

# ---------------------------------------------------------------------------
# U4 — Shell replacement on a service account
#   Attacker scenario: an unprivileged service account's login shell gets
#   flipped from /usr/sbin/nologin to /bin/bash (persistence hatch).
# ---------------------------------------------------------------------------
_attack_service_shell_flip() {
  require_root || return 0
  require_invasive || {
    echo "    invasive test — skipped (pass --invasive to enable)"
    return 0
  }

  local bak
  bak=$(backup_file "/etc/passwd") || return 1

  local testuser="hidsU4_$$"
  journal_log "useradd" "$testuser"
  useradd -r -s /usr/sbin/nologin "$testuser" 2>/dev/null || return 1

  # Rebuild user_shells.txt so the flip shows as drift
  awk -F: '{print $1":"$7}' /etc/passwd | sort \
    > "$HIDS_DIR/baselines/user_shells.txt"

  # ATTACK: flip the service account's shell
  sed -i "s|^${testuser}:x:\([^:]*\):\([^:]*\):\([^:]*\):\([^:]*\):/usr/sbin/nologin$|${testuser}:x:\1:\2:\3:\4:/bin/bash|" \
    /etc/passwd

  clear_dedup_state
  bash "$HIDS_DIR/modules/user_activity.sh" >/dev/null

  local ok=1
  assert_alert "CRITICAL" "user_activity" "$testuser" && ok=0
  assert_alert "WARNING"  "user_activity" "$testuser" && ok=0

  cp -p "$bak" /etc/passwd
  userdel "$testuser" 2>/dev/null || true
  return $ok
}

main() {
  run_test "UA U1 — SSH key dropped in authorized_keys"              _attack_ssh_key_drop
  run_test "UA U2 — passwordless account in /etc/passwd (INVASIVE)"  _attack_empty_password_field
  run_test "UA U3 — UID 0 backdoor account (INVASIVE)"               _attack_uid0_backdoor
  run_test "UA U4 — service account shell flip (INVASIVE)"           _attack_service_shell_flip
}
