#!/bin/bash
# ============================================================================
# baseline.sh — Baseline creation (reference state)
# ============================================================================
# The baseline is a "snapshot" of the machine's healthy state.
# Modules compare the current state to this baseline to detect changes.
# Without a baseline, there is no way to know what has changed.
#
# Called by main.sh with the --init flag.
# Creates 6 reference files in baselines/:
#   - files.txt         → sha256 + mode + owner:group + size for each critical file
#   - users.txt         → list of system users
#   - ports.txt         → listening ports
#   - suid.txt          → files with the SUID bit (runs as owner, often root)
#   - process_count.txt → normal process count (detects fork bombs, malware spawns)
#   - .integrity        → sha256 of each baseline file (detects tampering of baselines)
#
# IMPORTANT: in production, these baselines should be stored off-host
# (remote server, read-only USB, Git repo). If an attacker compromises
# the machine, they can tamper with the local baseline.
# ============================================================================

# Resolve project path
HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
# Respect a pre-set BASELINE_DIR (test harness points it at a sandbox to
# avoid clobbering the live baseline).
BASELINE_DIR="${BASELINE_DIR:-$HIDS_DIR/baselines}"

# Load the list of critical files
source "$HIDS_DIR/config/file_integrity.conf"

init_baseline() {

    echo "[+] Creating baseline..."

    mkdir -p "$BASELINE_DIR"

    # --- Critical files baseline (consolidated with metadata) ---
    # For each critical file, capture: sha256 hash + permissions + owner + size.
    # Detects not only content changes but also chmod/chown attacks that
    # do not alter content (e.g. `chmod 644 /etc/shadow` to leak hashes).
    # Format per line: <sha256>  <mode>  <owner>:<group>  <size>  <path>
    > "$BASELINE_DIR/files.txt"
    for f in "${CRITICAL_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            hash=$(sha256sum "$f" | awk '{print $1}')
            mode=$(stat -c '%a' "$f")
            owner=$(stat -c '%U:%G' "$f")
            size=$(stat -c '%s' "$f")
            printf '%s  %s  %s  %s  %s\n' \
                "$hash" "$mode" "$owner" "$size" "$f" \
                >> "$BASELINE_DIR/files.txt"
        else
            echo "[!] File not found, skipping: $f"
        fi
    done

    # --- User baseline ---
    # Extract usernames from /etc/passwd.
    # A new user appearing later = possible backdoor account.
    cut -d: -f1 /etc/passwd | sort > "$BASELINE_DIR/users.txt"

    # --- UID 0 accounts baseline ---
    # Only `root` (UID 0) should normally exist. An attacker may add a
    # second account with UID 0 to get silent root access without modifying
    # /etc/passwd's first line.
    awk -F: '$3 == 0 {print $1}' /etc/passwd | sort \
        > "$BASELINE_DIR/uid0_accounts.txt"

    # --- Privileged group membership baseline ---
    # Members of sudo/wheel/admin at init time. Any addition later = privilege
    # escalation signal.
    {
      getent group sudo  2>/dev/null | awk -F: '{gsub(",","\n",$4); print $4}'
      getent group wheel 2>/dev/null | awk -F: '{gsub(",","\n",$4); print $4}'
      getent group admin 2>/dev/null | awk -F: '{gsub(",","\n",$4); print $4}'
    } | sed '/^$/d' | sort -u > "$BASELINE_DIR/sudo_members.txt"

    # --- User shell map baseline ---
    # user:/shell/path per line. Detects silent shell replacement on a
    # service account (e.g., nobody's shell changed from /usr/sbin/nologin
    # to /bin/bash).
    awk -F: '{print $1":"$7}' /etc/passwd | sort \
        > "$BASELINE_DIR/user_shells.txt"

    # --- authorized_keys baseline ---
    # SHA-256 of every authorized_keys file on the system, plus a list of
    # key fingerprints. A new key here = silent SSH persistence (most common
    # persistence technique on compromised Linux hosts).
    > "$BASELINE_DIR/authorized_keys.hash"
    # Root + every home directory
    for home in /root /home/*; do
        ak="$home/.ssh/authorized_keys"
        if [[ -f "$ak" ]]; then
            h=$(sha256sum "$ak" | awk '{print $1}')
            printf '%s  %s\n' "$h" "$ak" >> "$BASELINE_DIR/authorized_keys.hash"
        fi
    done

    # --- Login database sizes (wtmp/btmp) ---
    # Any attacker who clears their tracks will truncate these. If the
    # current size later is SMALLER than baseline → tampering.
    for db in /var/log/wtmp /var/log/btmp; do
        if [[ -f "$db" ]]; then
            sz=$(stat -c '%s' "$db" 2>/dev/null)
            printf '%s  %s\n' "$sz" "$db"
        fi
    done > "$BASELINE_DIR/login_db_sizes.txt"

    # --- Listening ports baseline ---
    # ss -tuln lists TCP/UDP listening ports.
    # A new port appearing later = possible reverse shell or backdoor.
    ss -tuln | awk 'NR>1 {print $5}' | sed 's/.*://' | sort -u > "$BASELINE_DIR/ports.txt"

    # --- SUID files baseline ---
    # A SUID file executes with the owner's permissions (often root).
    # An attacker adding SUID to /bin/bash gets a root shell.
    # find looks for all files with the 4000 permission (SUID bit).
    find / -perm -4000 -type f 2>/dev/null | sort > "$BASELINE_DIR/suid.txt"

    # --- Process count baseline ---
    # Normal process count on a clean system. Consumed by system_health.sh
    # to detect abnormal spikes (fork bombs, malware spawning children).
    ps -e --no-headers | wc -l | tr -d ' ' > "$BASELINE_DIR/process_count.txt"

    # --- Meta-integrity ---
    # SHA-256 of each baseline file above. Verified every cycle by
    # watchdog.sh. Detects an attacker who modifies the baselines themselves
    # to hide traces of their changes (e.g. adding their user to users.txt
    # after `useradd backdoor`).
    # auth_ips.txt is included if install.sh created the template; ignored
    # silently otherwise.
    (cd "$BASELINE_DIR" && \
     sha256sum files.txt users.txt ports.txt suid.txt process_count.txt \
               uid0_accounts.txt sudo_members.txt user_shells.txt \
               authorized_keys.hash login_db_sizes.txt \
               auth_ips.txt 2>/dev/null > .integrity)

    echo "[+] Baseline ready in $BASELINE_DIR/"
}
