#!/bin/bash
# ============================================================================
# install.sh — HIDS installer and dependency checker
# ============================================================================
# Run this ONCE before using the HIDS for the first time.
# It does 4 things:
#   1. Checks if running as root
#   2. Installs auditd if not present
#   3. Deploys auditd rules for HIDS detection
#   4. Creates and enables the systemd service
#
# Usage:
#   sudo bash install.sh
#
# After running this script, the HIDS will:
#   - Start automatically on boot
#   - Be manageable via systemctl (start/stop/status)
#   - Have auditd configured with detection rules
# ============================================================================

set -e  # Exit on any error

# Resolve the absolute path of the project
HIDS_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Colors for output ---
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

# ============================================================================
# Step 0: Root check
# ============================================================================
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root (sudo)."
  exit 1
fi

info "Starting HIDS installation..."
echo ""

# ============================================================================
# Step 1: Detect package manager
# ============================================================================
# Different Linux distros use different package managers.
# We support apt (Debian/Ubuntu) and yum/dnf (RHEL/CentOS/Fedora).
if command -v apt-get &>/dev/null; then
  PKG_MANAGER="apt-get"
  PKG_INSTALL="apt-get install -y"
  PKG_UPDATE="apt-get update -y"
elif command -v dnf &>/dev/null; then
  PKG_MANAGER="dnf"
  PKG_INSTALL="dnf install -y"
  PKG_UPDATE="dnf check-update || true"
elif command -v yum &>/dev/null; then
  PKG_MANAGER="yum"
  PKG_INSTALL="yum install -y"
  PKG_UPDATE="yum check-update || true"
else
  error "No supported package manager found (apt, dnf, yum)."
  exit 1
fi

info "Detected package manager: $PKG_MANAGER"

# ============================================================================
# Step 2: Install auditd if not present
# ============================================================================
# auditd is the Linux kernel audit framework. Our auditd_parser.sh reads
# its logs to detect command executions and suspicious syscalls.
# Without auditd, the correlation engine has no data to work with.

if command -v auditd &>/dev/null || command -v auditctl &>/dev/null; then
  info "auditd is already installed."
else
  warn "auditd is not installed. Installing..."
  $PKG_UPDATE
  $PKG_INSTALL auditd audispd-plugins 2>/dev/null || $PKG_INSTALL audit 2>/dev/null
  info "auditd installed successfully."
fi

# Make sure auditd is running
if systemctl is-active --quiet auditd; then
  info "auditd is already running."
else
  systemctl enable --now auditd
  info "auditd started and enabled on boot."
fi

# ============================================================================
# Step 3: Deploy auditd rules
# ============================================================================
# These rules tell auditd WHAT to monitor. Without rules, the audit log
# contains almost nothing useful for our HIDS.
#
# The -k flags are tags that allow filtering events by category.

RULES_FILE="/etc/audit/rules.d/hids.rules"

if [[ -f "$RULES_FILE" ]]; then
  warn "auditd rules already exist at $RULES_FILE. Backing up..."
  cp "$RULES_FILE" "${RULES_FILE}.bak.$(date +%s)"
fi

info "Deploying auditd rules..."

cat > "$RULES_FILE" << 'EOF'
# ============================================================================
# hids.rules — Auditd rules for SOC HIDS
# ============================================================================

# --- Critical file monitoring ---
# Watch for writes (w) and attribute changes (a) on sensitive files.
# These are the same files tracked by file_integrity.sh, but auditd
# also captures WHO modified them and WHEN (more precise).
-w /etc/passwd -p wa -k user_modify
-w /etc/shadow -p wa -k user_modify
-w /etc/group -p wa -k user_modify
-w /etc/sudoers -p wa -k priv_escalation
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/crontab -p wa -k persistence
-w /etc/hosts -p wa -k dns_tamper
-w /etc/resolv.conf -p wa -k dns_tamper

# --- Execution from suspicious directories ---
# /tmp and /dev/shm are world-writable. Attackers commonly download
# payloads there and execute them. This catches those executions.
-a always,exit -F dir=/tmp -F perm=x -k tmp_exec
-a always,exit -F dir=/dev/shm -F perm=x -k shm_exec

# --- Permission changes ---
# chmod u+s = sets the SUID bit, which is a privilege escalation technique
# Modern auditd requires an arch specifier on syscall rules, and refuses
# the whole rule file if it is missing — so we declare both 64-bit and
# 32-bit variants to cover compat binaries on 64-bit hosts.
-a always,exit -F arch=b64 -S chmod -S fchmod -k perm_change
-a always,exit -F arch=b32 -S chmod -S fchmod -k perm_change

# --- Suspicious command monitoring & user/group management ---
# Appended below via a shell loop: rules referencing a non-existent
# binary (e.g. /usr/bin/ncat absent on Kali base) cause auditctl to
# abort the load, so we only emit rules for binaries that exist.
EOF

# Append -F exe= rules ONLY for binaries present on this host.
# auditctl refuses to load the whole file if any -F exe= path is missing.
for bin_cfg in \
    "/usr/bin/wget:download" \
    "/usr/bin/curl:download" \
    "/usr/bin/nc:netcat" \
    "/usr/bin/ncat:netcat" \
    "/usr/sbin/useradd:account_change" \
    "/usr/sbin/usermod:account_change" \
    "/usr/sbin/userdel:account_change"; do
  bin_path="${bin_cfg%%:*}"
  bin_key="${bin_cfg##*:}"
  if [[ -x "$bin_path" ]]; then
    echo "-a always,exit -F exe=${bin_path} -k ${bin_key}" >> "$RULES_FILE"
  else
    warn "Skipping auditd rule for missing binary: ${bin_path}"
  fi
done

# Reload auditd rules.
# `|| true` prevents `set -e` from killing the installer if a single rule
# is rejected (e.g. a binary we didn't filter disappears between our check
# and the load). Rules that DO load are still active; the rest are logged
# by auditctl to the audit log. We verify coverage below with `auditctl -l`.
augenrules --load >/dev/null 2>&1 || auditctl -R "$RULES_FILE" >/dev/null 2>&1 || true

loaded_rules=$(auditctl -l 2>/dev/null | grep -c . || true)
if (( loaded_rules > 0 )); then
  info "auditd rules deployed (${loaded_rules} rules active)."
else
  warn "auditd rules deployed but none are active — check 'auditctl -l' after install."
fi

# ============================================================================
# Step 4: Install bc (required by system_health.sh for decimal comparison)
# ============================================================================
if command -v bc &>/dev/null; then
  info "bc is already installed."
else
  warn "bc is not installed. Installing..."
  $PKG_INSTALL bc
  info "bc installed successfully."
fi

# ============================================================================
# Step 4b: Install inotify-tools (required by file_integrity_events.sh)
# ============================================================================
# file_integrity_events.sh uses `inotifywait` to fire real-time alerts when
# critical files are modified. Without it, only the 60-second periodic scan
# in file_integrity.sh runs.
if command -v inotifywait &>/dev/null; then
  info "inotify-tools is already installed."
else
  warn "inotify-tools is not installed. Installing..."
  # Package name: inotify-tools on apt/dnf/yum
  $PKG_INSTALL inotify-tools
  info "inotify-tools installed successfully."
fi

# ============================================================================
# Step 4c: Install jq (used for readable alerts.json inspection)
# ============================================================================
# alerts.json is a stream of pretty-printed JSON objects. jq lets operators
# filter by severity, separate test alerts from real ones, etc:
#   jq -s 'map(select(.test_run == null))' logs/alerts.json   # real only
#   jq -s 'map(select(.severity == "CRITICAL"))' logs/alerts.json
if command -v jq &>/dev/null; then
  info "jq is already installed."
else
  warn "jq is not installed. Installing..."
  $PKG_INSTALL jq
  info "jq installed successfully."
fi

# ============================================================================
# Step 5: Create systemd service
# ============================================================================
# systemd manages the HIDS as a system service. This means:
#   - It starts automatically on boot
#   - It restarts if it crashes (Restart=on-failure)
#   - You can manage it with systemctl start/stop/status hids
#   - Logs are accessible via journalctl -u hids

SERVICE_FILE="/etc/systemd/system/hids.service"

info "Creating systemd service..."

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SOC Host Intrusion Detection System
# Start after the network is up and auditd is running
# This ensures audit.log exists when our parser tries to read it
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
# Run main.sh from the project directory
ExecStart=/bin/bash ${HIDS_DIR}/main.sh
# Working directory = project root (so relative paths in configs work)
WorkingDirectory=${HIDS_DIR}
# Restart automatically if the HIDS crashes (max 3 times in 60 seconds)
Restart=on-failure
RestartSec=10
# Run as root (required to read /proc, /etc/shadow, audit.log)
User=root
# Send stdout/stderr to the journal (viewable with journalctl)
StandardOutput=journal
StandardError=journal

[Install]
# Start on boot when the system reaches multi-user mode
WantedBy=multi-user.target
EOF

# Reload systemd to recognize the new service
systemctl daemon-reload

# Enable the service to start on boot
systemctl enable hids.service

info "systemd service created and enabled."

# ============================================================================
# Step 6: Create authentication baseline template
# ============================================================================
# auth_ips.txt is a declarative baseline: the admin lists, per user, the
# source IPs allowed to open an SSH session. The HIDS flags any session
# opened from an IP not in the list (credential theft / lateral movement).
#
# We cannot auto-learn this from auth.log on a fresh install (no history),
# so we drop a commented template and let the admin fill it in before
# starting the HIDS.

AUTH_BASELINE="$HIDS_DIR/baselines/auth_ips.txt"
mkdir -p "$HIDS_DIR/baselines"

if [[ ! -f "$AUTH_BASELINE" ]]; then
  cat > "$AUTH_BASELINE" << 'EOF'
# ============================================================================
# auth_ips.txt — Authentication baseline (per-user allowed source IPs)
# ============================================================================
# Declares, per user, the IPs allowed to open an SSH session.
# The HIDS flags any session opened from an IP not listed here.
#
# Format: username:ip1,ip2,ip3
# Lines starting with # are ignored.
#
# IMPORTANT: edit this file BEFORE starting the HIDS, then:
#   sudo systemctl restart hids
#
# Examples:
# admin:192.168.1.10,192.168.1.20
# deploy:10.0.0.50
# ============================================================================
EOF
  info "Auth baseline template created at $AUTH_BASELINE"
  warn "Edit $AUTH_BASELINE before starting the HIDS to declare allowed SSH source IPs."
fi

# ============================================================================
# Step 6b: Ensure user_activity.conf exists
# ============================================================================
# user_activity.sh requires this config (sourced at startup). If the repo
# is deployed without it — or if an admin deletes it — recreate a safe
# default so the module can still load. Existing files are never
# overwritten so admin tuning is preserved.

USER_CONF="$HIDS_DIR/config/user_activity.conf"
if [[ ! -f "$USER_CONF" ]]; then
  info "Creating default user_activity.conf..."
  cat > "$USER_CONF" << 'EOF'
#!/bin/bash
# Auto-generated by install.sh — tune to your environment.

ALLOWED_LOGIN_HOURS_START=7
ALLOWED_LOGIN_HOURS_END=21

# Prefix-string match (not CIDR). Examples: "192.168." "10." "127."
ALLOWED_IPS="127. 192.168. 10. ::1"

SERVICE_ACCOUNTS="www-data nginx apache httpd mysql postgres redis mongodb \
  ftp nobody daemon bin sys games mail news uucp proxy list irc gnats"
INTERACTIVE_SHELLS="bash sh zsh dash ksh tcsh csh ash fish"

MAX_CONCURRENT_SESSIONS=2
IDLE_SESSION_WARN_HOURS=24

BRUTE_FORCE_WINDOW_LINES=500
BRUTE_FORCE_MIN_FAILS=5

CONN_BURST_MAX=20
CONN_BURST_WINDOW_LINES=200

EXPECTED_SHELLS="/bin/bash /bin/sh /bin/zsh /bin/dash /bin/rbash \
  /usr/bin/bash /usr/bin/zsh /usr/bin/fish \
  /sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false \
  /bin/sync /usr/sbin/shutdown /usr/sbin/halt"
EOF
  info "Default config written to $USER_CONF — edit it to tune thresholds."
else
  info "user_activity.conf already exists — keeping it."
fi

# ============================================================================
# Step 6c: Migrate legacy state file names
# ============================================================================
# Older installs wrote system_health_state.db; the file is plain bash
# sourced by the module, so it was renamed to .sh. Remove the stale file
# so the module does not carry duplicate state.
if [[ -f "$HIDS_DIR/baselines/system_health_state.db" ]]; then
  info "Removing legacy baselines/system_health_state.db"
  rm -f "$HIDS_DIR/baselines/system_health_state.db"
fi

# ============================================================================
# Summary
# ============================================================================
# install.sh deliberately does NOT run --init or start the service. Creating
# the baseline and starting monitoring are operator-driven actions — the
# installer only prepares dependencies, rules, config templates, and the
# systemd unit.
echo ""
echo "=============================================="
info "HIDS installation complete — NOT started."
echo "=============================================="
echo ""
info "Next steps (in order):"
echo ""
echo "  1. Review and tune configs:"
echo "       $HIDS_DIR/config/"
echo "       $HIDS_DIR/baselines/auth_ips.txt   (declare allowed SSH source IPs)"
echo ""
echo "  2. Create the baseline (snapshot of the healthy system):"
echo "       sudo bash $HIDS_DIR/main.sh --init"
echo ""
echo "  3. Start the HIDS (either one):"
echo "       sudo bash $HIDS_DIR/main.sh          (foreground, Ctrl+C to stop)"
echo "       sudo systemctl start hids            (background, via systemd)"
echo ""
echo "  Managing the systemd service:"
echo "    systemctl status hids      → check if running"
echo "    systemctl stop hids        → stop"
echo "    systemctl restart hids     → restart"
echo "    journalctl -u hids -f      → follow live logs"
echo ""
echo "  Auditd:"
echo "    auditctl -l                → list active rules"
echo "    ausearch -k tmp_exec       → search events by key"
echo ""
echo "  HIDS logs (after starting):"
echo "    $HIDS_DIR/logs/alerts.json"
echo "    $HIDS_DIR/logs/raw_events.log"
echo ""
