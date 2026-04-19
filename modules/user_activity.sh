#!/bin/bash
# ============================================================================
# user_activity.sh — Module 2: Users, sessions, authentication, persistence
# ============================================================================
# Answers the brief question:
#   "Who is logged in, when did they log in, from where, and is that
#    behavior normal or suspicious?"
#
# Sections (mirror the design doc A–F):
#   A. Authentication anomalies    (brute force, off-hours, unknown IPs,
#                                   brute force SUCCESS, root SSH)
#   B. Privilege escalation        (UID 0, sudo/wheel membership, su,
#                                   abnormal sudo frequency)
#   C. Session anomalies           (concurrent same-user, long idle,
#                                   unexpected TTY, root session)
#   D. Persistence indicators      (new user, hidden account, abnormal
#                                   shell, authorized_keys drift)
#   E. Log tampering               (wtmp/btmp truncation)
#
# Section D (service account shells) and G (network bursts, reverse tunnels)
# live in process_network.sh — they require /proc and ss inspection.
#
# Data sources:
#   /etc/passwd, /etc/group        → accounts, UID 0, shells
#   getent                         → privileged group membership
#   who, w                         → active sessions, idle time, TTY
#   /var/log/auth.log (or secure)  → authentication events
#   lastb                          → failed login database
#   stat /var/log/{wtmp,btmp}      → tampering detection
#   ~/.ssh/authorized_keys         → SSH persistence
# ============================================================================

# --- Stage 2 self-loop wrapper (see file_integrity.sh for rationale) ---
if [[ -z "${__HIDS_INLOOP:-}" ]] && [[ "${HIDS_SELF_LOOP:-1}" == "1" ]]; then
  export __HIDS_INLOOP=1
  _interval="${UA_INTERVAL:-60}"
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

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"
source "$HIDS_DIR/config/thresholds.conf"
source "$HIDS_DIR/config/user_activity.conf"

BASE_DIR="$HIDS_DIR/baselines"
RAW_LOG="$HIDS_DIR/logs/raw_events.log"

# Pick the right auth log for the distro
AUTH_LOG="/var/log/auth.log"
[[ ! -f "$AUTH_LOG" ]] && AUTH_LOG="/var/log/secure"

log_raw() {
  echo "$(date -Iseconds)|user_activity|$*" >> "$RAW_LOG"
}

# ============================================================================
# A. AUTHENTICATION ANOMALIES
# ============================================================================

if [[ -f "$AUTH_LOG" ]]; then

  # --- A1. Repeated failed logins (brute force in progress) ---
  failed_count=$(tail -n 100 "$AUTH_LOG" 2>/dev/null | grep -c "Failed password")
  if (( failed_count >= MAX_FAILED_LOGINS )); then
    alert "WARNING" "user_activity" \
      "$failed_count failed login attempts (threshold: $MAX_FAILED_LOGINS)"
    log_raw "failed_logins|count=$failed_count"
  fi

  # --- A2. Brute force SUCCESS (fail → success from same IP) ---
  # Parse the recent window, build per-IP counters, flag any IP that has
  # >= BRUTE_FORCE_MIN_FAILS failures AND at least one subsequent success.
  window=$(tail -n "$BRUTE_FORCE_WINDOW_LINES" "$AUTH_LOG" 2>/dev/null)
  # Extract {fail|ok} events with IPs, in order
  events=$(echo "$window" | awk '
    /Failed password.*from / {
      match($0, /from [0-9.:a-fA-F]+/);
      ip=substr($0, RSTART+5, RLENGTH-5);
      print "FAIL " ip
    }
    /Accepted (password|publickey).*from / {
      match($0, /from [0-9.:a-fA-F]+/);
      ip=substr($0, RSTART+5, RLENGTH-5);
      print "OK " ip
    }')

  # For each IP that appears with OK, check how many FAILs came before it
  declare -A fail_count_per_ip
  while read -r kind ip; do
    [[ -z "$ip" ]] && continue
    if [[ "$kind" == "FAIL" ]]; then
      fail_count_per_ip["$ip"]=$(( ${fail_count_per_ip["$ip"]:-0} + 1 ))
    elif [[ "$kind" == "OK" ]]; then
      prior=${fail_count_per_ip["$ip"]:-0}
      if (( prior >= BRUTE_FORCE_MIN_FAILS )); then
        alert "CRITICAL" "user_activity" \
          "Brute-force SUCCESS from $ip ($prior prior failures, then accepted)"
        log_raw "brute_force_success|ip=$ip|fails=$prior"
        # Reset so we don't re-alert for the same IP on every subsequent OK
        fail_count_per_ip["$ip"]=0
      fi
    fi
  done <<< "$events"
  unset fail_count_per_ip

  # --- A3. Off-hours logins ---
  # Parse "Accepted" lines; extract time; flag if outside business window.
  tail -n 200 "$AUTH_LOG" 2>/dev/null | \
    grep "Accepted" | while read -r line; do
      # Time is field 3 in syslog format "Mon DD HH:MM:SS ..."
      ts=$(echo "$line" | awk '{print $3}')
      hour=${ts%%:*}
      # Strip leading zero safely (decimal interpretation)
      hour=$((10#${hour:-0}))
      if (( hour < ALLOWED_LOGIN_HOURS_START || hour >= ALLOWED_LOGIN_HOURS_END )); then
        who_user=$(echo "$line" | grep -oP 'for \K\S+' | head -1)
        from_ip=$(echo "$line" | grep -oP 'from \K\S+' | head -1)
        alert "WARNING" "user_activity" \
          "Off-hours login: user=$who_user from=$from_ip at ${hour}h"
        log_raw "off_hours_login|user=$who_user|ip=$from_ip|hour=$hour"
      fi
    done

  # --- A4. Logins from non-whitelisted IPs ---
  if [[ -n "$ALLOWED_IPS" ]]; then
    tail -n 200 "$AUTH_LOG" 2>/dev/null | \
      grep "Accepted" | while read -r line; do
        from_ip=$(echo "$line" | grep -oP 'from \K\S+' | head -1)
        [[ -z "$from_ip" ]] && continue
        allowed=0
        for prefix in $ALLOWED_IPS; do
          if [[ "$from_ip" == "$prefix"* ]]; then
            allowed=1
            break
          fi
        done
        if (( allowed == 0 )); then
          who_user=$(echo "$line" | grep -oP 'for \K\S+' | head -1)
          alert "WARNING" "user_activity" \
            "Login from non-whitelisted IP: $from_ip (user=$who_user)"
          log_raw "unknown_ip_login|ip=$from_ip|user=$who_user"
        fi
      done
  fi

  # --- A5. Root login via SSH (should be disabled in PermitRootLogin) ---
  root_ssh=$(tail -n 200 "$AUTH_LOG" 2>/dev/null | \
             grep "Accepted" | grep -E "for root |user=root " | wc -l)
  if (( root_ssh > 0 )); then
    alert "CRITICAL" "user_activity" \
      "Root login via SSH observed ($root_ssh event(s) in recent log)"
    log_raw "root_ssh_login|count=$root_ssh"
  fi

fi

# ============================================================================
# B. PRIVILEGE ESCALATION
# ============================================================================

# --- B1. New UID 0 accounts ---
# Only root should have UID 0. Any other UID 0 user = instant silent root.
current_uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | sort)
if [[ -f "$BASE_DIR/uid0_accounts.txt" ]]; then
  new_uid0=$(comm -13 "$BASE_DIR/uid0_accounts.txt" <(echo "$current_uid0"))
  if [[ -n "$new_uid0" ]]; then
    for u in $new_uid0; do
      alert "CRITICAL" "user_activity" \
        "New UID 0 account detected: $u (potential silent root backdoor)"
      log_raw "new_uid0|user=$u"
    done
  fi
fi

# --- B2. New privileged group members (sudo / wheel / admin) ---
current_priv=$({
  getent group sudo  2>/dev/null | awk -F: '{gsub(",","\n",$4); print $4}'
  getent group wheel 2>/dev/null | awk -F: '{gsub(",","\n",$4); print $4}'
  getent group admin 2>/dev/null | awk -F: '{gsub(",","\n",$4); print $4}'
} | sed '/^$/d' | sort -u)

if [[ -f "$BASE_DIR/sudo_members.txt" ]]; then
  new_priv=$(comm -13 "$BASE_DIR/sudo_members.txt" <(echo "$current_priv"))
  if [[ -n "$new_priv" ]]; then
    for u in $new_priv; do
      alert "CRITICAL" "user_activity" \
        "New privileged group member: $u (sudo/wheel/admin)"
      log_raw "new_priv_member|user=$u"
    done
  fi
fi

# --- B3. su usage (bypasses normal sudo audit trail) ---
if [[ -f "$AUTH_LOG" ]]; then
  # Match "session opened for user root by" via su (not sudo)
  su_count=$(tail -n 100 "$AUTH_LOG" 2>/dev/null | \
             grep -E "^.*su(\[|:).*session opened" | wc -l)
  if (( su_count >= MAX_SU_COMMANDS )); then
    alert "WARNING" "user_activity" \
      "$su_count su invocations (threshold: $MAX_SU_COMMANDS) — bypasses sudo logging"
    log_raw "su_usage|count=$su_count"
  fi

  # --- B4. Abnormal sudo frequency (kept from previous version) ---
  sudo_attempts=$(tail -n 50 "$AUTH_LOG" 2>/dev/null | grep -c "sudo.*COMMAND")
  if (( sudo_attempts > MAX_SUDO_COMMANDS )); then
    alert "WARNING" "user_activity" \
      "$sudo_attempts recent sudo commands detected (threshold: $MAX_SUDO_COMMANDS)"
    log_raw "sudo_burst|count=$sudo_attempts"
  fi
fi

# ============================================================================
# C. SESSION ANOMALIES
# ============================================================================

# --- C1. Active root session ---
active_sessions=$(who 2>/dev/null)
if echo "$active_sessions" | grep -q "^root "; then
  alert "WARNING" "user_activity" "Active root session detected"
  log_raw "root_session_active"
fi

# --- C2. Multiple concurrent sessions from different IPs (same user) ---
# who output: <user> <tty> <date> <time> (<from>)
echo "$active_sessions" | awk '{
  user=$1
  # Last field between parentheses, if present, is the source
  match($0, /\([^)]+\)/)
  from = (RSTART > 0) ? substr($0, RSTART+1, RLENGTH-2) : "local"
  print user "|" from
}' | sort -u | awk -F'|' '
  { seen[$1] = (seen[$1] ? seen[$1] "," : "") $2; count[$1]++ }
  END {
    for (u in count) if (count[u] > 1) print u "|" count[u] "|" seen[u]
  }' | while IFS='|' read -r user n froms; do
    if (( n > MAX_CONCURRENT_SESSIONS )); then
      alert "WARNING" "user_activity" \
        "User $user has $n concurrent sessions from: $froms"
      log_raw "concurrent_sessions|user=$user|count=$n|sources=$froms"
    fi
  done

# --- C3. Long idle sessions ---
# w output fields: USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
# IDLE can be HH:MMm, Xdays, Xmin — we look for "days" as a cheap over-threshold signal
# and also parse "HH:MM" as hours.
w -h 2>/dev/null | while read -r user tty from login_at idle rest; do
  hours=0
  case "$idle" in
    *days)    hours=$(( ${idle%days} * 24 )) ;;
    *day)     hours=24 ;;
    *:*)      h=${idle%%:*}; hours=$((10#${h:-0})) ;;
    *m)       hours=0 ;;  # minutes → below threshold
    *)        hours=0 ;;
  esac
  if (( hours >= IDLE_SESSION_WARN_HOURS )); then
    alert "INFO" "user_activity" \
      "Long idle session: user=$user tty=$tty from=$from idle=$idle"
    log_raw "idle_session|user=$user|tty=$tty|from=$from|idle=$idle"
  fi
done

# --- C4. Unexpected TTY ---
# On a server, interactive sessions should be on pts/N (SSH). Direct tty
# logins suggest physical console access — worth noting.
echo "$active_sessions" | awk '{print $1, $2}' | while read -r user tty; do
  [[ -z "$tty" ]] && continue
  if [[ "$tty" =~ ^tty[0-9]+$ ]]; then
    alert "INFO" "user_activity" \
      "Console TTY session: user=$user tty=$tty"
    log_raw "console_session|user=$user|tty=$tty"
  fi
done

# ============================================================================
# D. PERSISTENCE INDICATORS
# ============================================================================

# --- D1. New user vs baseline ---
current=$(cut -d: -f1 /etc/passwd | sort)
if [[ -f "$BASE_DIR/users.txt" ]]; then
  diff=$(comm -13 "$BASE_DIR/users.txt" <(echo "$current"))
  if [[ -n "$diff" ]]; then
    alert "CRITICAL" "user_activity" "New users detected: $diff"
    log_raw "new_users|list=$(echo "$diff" | tr '\n' ',')"
  fi
else
  echo "$current" > "$BASE_DIR/users.txt"
fi

# --- D2. Hidden / malformed accounts in /etc/passwd ---
# Duplicate UIDs (two accounts sharing a UID — stealth technique)
dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
if [[ -n "$dup_uids" ]]; then
  for uid in $dup_uids; do
    names=$(awk -F: -v u="$uid" '$3 == u {print $1}' /etc/passwd | tr '\n' ',')
    alert "CRITICAL" "user_activity" \
      "Duplicate UID $uid shared by: ${names%,}"
    log_raw "dup_uid|uid=$uid|users=${names%,}"
  done
fi

# Accounts with empty password field in /etc/passwd (should be 'x' for shadow)
no_pw=$(awk -F: '$2 == "" {print $1}' /etc/passwd)
if [[ -n "$no_pw" ]]; then
  for u in $no_pw; do
    alert "CRITICAL" "user_activity" \
      "Account with no password placeholder in /etc/passwd: $u"
    log_raw "empty_passwd_field|user=$u"
  done
fi

# --- D3. Abnormal shell for a known account ---
# Compare the current user:shell map to baseline. A silently changed shell
# (e.g., nobody's shell flipped from nologin to bash) = backdoor.
if [[ -f "$BASE_DIR/user_shells.txt" ]]; then
  current_shells=$(awk -F: '{print $1":"$7}' /etc/passwd | sort)
  shell_diff=$(comm -13 "$BASE_DIR/user_shells.txt" <(echo "$current_shells"))
  if [[ -n "$shell_diff" ]]; then
    while IFS=: read -r u sh; do
      [[ -z "$u" ]] && continue
      # Ignore if this is a newly created user (already flagged in D1)
      grep -qx "$u" "$BASE_DIR/users.txt" 2>/dev/null || continue
      alert "CRITICAL" "user_activity" \
        "Shell changed for existing user: $u → $sh"
      log_raw "shell_changed|user=$u|shell=$sh"
    done <<< "$shell_diff"
  fi
fi

# --- D4. Unknown / non-standard shells ---
# Flag any shell that is neither in our EXPECTED_SHELLS list nor in /etc/shells.
valid_shells=$(cat /etc/shells 2>/dev/null; echo "$EXPECTED_SHELLS" | tr ' ' '\n')
awk -F: '{print $1":"$7}' /etc/passwd | while IFS=: read -r u sh; do
  [[ -z "$sh" ]] && continue
  if ! echo "$valid_shells" | grep -qx "$sh"; then
    alert "WARNING" "user_activity" \
      "User $u has non-standard shell: $sh"
    log_raw "nonstd_shell|user=$u|shell=$sh"
  fi
done

# --- D5. authorized_keys drift (SSH persistence) ---
# Compare current hash of every authorized_keys file to baseline.
# Strategy:
#   1. For every path recorded in the baseline → re-hash it and compare.
#      Missing files or hash mismatches = drift.
#   2. Then scan /root + /home/* for any authorized_keys NOT in the baseline
#      (a brand-new one = fresh SSH persistence).
if [[ -f "$BASE_DIR/authorized_keys.hash" ]]; then
  # (1) Drift check against baseline paths (authoritative list)
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    base_hash=$(echo "$line" | awk '{print $1}')
    base_path=$(echo "$line" | awk '{print $2}')
    if [[ ! -f "$base_path" ]]; then
      alert "CRITICAL" "user_activity" \
        "authorized_keys removed: $base_path"
      log_raw "authorized_keys_removed|path=$base_path"
      continue
    fi
    curr_hash=$(sha256sum "$base_path" | awk '{print $1}')
    if [[ "$curr_hash" != "$base_hash" ]]; then
      alert "CRITICAL" "user_activity" \
        "authorized_keys modified: $base_path"
      log_raw "authorized_keys_changed|path=$base_path"
    fi
  done < "$BASE_DIR/authorized_keys.hash"

  # (2) New-file check: anything under /root or /home/* absent from baseline
  for home in /root /home/*; do
    ak="$home/.ssh/authorized_keys"
    [[ -f "$ak" ]] || continue
    if ! grep -qF "  $ak" "$BASE_DIR/authorized_keys.hash"; then
      alert "CRITICAL" "user_activity" \
        "New authorized_keys file (SSH persistence): $ak"
      log_raw "new_authorized_keys|path=$ak"
    fi
  done
fi

# ============================================================================
# E. LOG TAMPERING
# ============================================================================
# If an attacker clears /var/log/wtmp or /var/log/btmp to hide login traces,
# the file size will shrink (unless the system was also rebooted and
# recreated the file, which is itself rare and suspicious).

if [[ -f "$BASE_DIR/login_db_sizes.txt" ]]; then
  while read -r base_sz path; do
    [[ -z "$path" ]] && continue
    if [[ -f "$path" ]]; then
      current_sz=$(stat -c '%s' "$path" 2>/dev/null)
      if (( current_sz < base_sz )); then
        alert "CRITICAL" "user_activity" \
          "Login DB truncated: $path now ${current_sz}B, baseline ${base_sz}B"
        log_raw "log_truncation|file=$path|old=$base_sz|new=$current_sz"
      fi
    else
      alert "CRITICAL" "user_activity" \
        "Login DB missing: $path (baseline had it)"
      log_raw "log_missing|file=$path"
    fi
  done < "$BASE_DIR/login_db_sizes.txt"
fi

# --- E2. Total failed logins from btmp ---
# lastb reads /var/log/btmp. A sudden drop to zero when we used to see
# attempts is also suspicious, but the truncation check above covers it.
# We just surface the count as an INFO line for operators.
if command -v lastb &>/dev/null; then
  lastb_count=$(lastb -n 1000 2>/dev/null | grep -v "^$" | grep -vc "^btmp begins")
  if (( lastb_count > 100 )); then
    alert "INFO" "user_activity" \
      "$lastb_count total failed login records in btmp"
    log_raw "lastb_total|count=$lastb_count"
  fi
fi

# ============================================================================
# F. Auditd enrichment — moved to user_activity_events.sh (Stage 3a)
# ============================================================================
# The polling implementation that lived here (ausearch -k <key> -ts recent,
# every UA_INTERVAL seconds) was replaced with a streaming tail -F reader
# in modules/user_activity_events.sh. Latency dropped from ~60s to ~1s.
# That module is launched by the supervisor as its own collector.
