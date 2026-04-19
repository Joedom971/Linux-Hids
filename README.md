# SOC HIDS — Host Intrusion Detection System

A Bash-based Host Intrusion Detection System for Linux. Detects compromise indicators across file integrity, account activity, running processes, open ports, and system health. Designed for Linux workstations and servers; validated on Kali.

> BeCode team project — Mahmoud, Johan, Muza.

---

## What it does

Four independent collectors run in parallel under a supervisor. Each module has a narrow focus and writes alerts to a central JSON log for SIEM ingestion.

| Module | What it catches |
|---|---|
| `file_integrity` | Tampering of `/etc/passwd`, `/etc/shadow`, sudoers, SSH host keys, critical binaries — content, permissions, ownership |
| `user_activity` | New users, UID 0 backdoors, passwordless accounts, service-account shell flips, SSH `authorized_keys` drift, failed login bursts, off-hours root logins |
| `process_network` | Rogue listening ports, execution from `/tmp`, hidden processes (rootkit indicator), LD_PRELOAD injection, process name spoofing, wildcard binds, SUID growth |
| `system_health` | Resource exhaustion, failed services, error-log volume spikes, abnormal process counts, recent reboots |

Plus two **event-driven companions** for sub-second latency:

| Module | Mechanism |
|---|---|
| `file_integrity_events` | `inotifywait` on parent directories of critical files — fires the instant they change |
| `user_activity_events` | `tail -F /var/log/audit/audit.log` filtered by auditd keys (`user_modify`, `priv_escalation`, `persistence`, `ssh_config`…) |

And a **live dashboard**:

| Module | Cadence |
|---|---|
| `system_health_dashboard` | Rewrites a colored snapshot to `logs/system_health.status` every 3s |
=======
# Linux Bash-Based HIDS

## Overview

This project implements a Host Intrusion Detection System (HIDS) using only native Linux tools and Bash scripting.

The system monitors a Linux host for suspicious activity across multiple domains:
- System health
- User activity
- Processes and network behavior
- File integrity
- Alerting and correlation

The goal is to detect abnormal behavior, reduce noise, and provide actionable alerts similar to real-world tools like Wazuh, OSSEC, and Auditd.
>>>>>>> 382d66681b9c9a9f2947d0fa4b41b243a80a8ad5

---

## Architecture

<<<<<<< HEAD
```
┌─────────────────────────────────────────────────────────┐
│                      controller.sh                       │
│                    (supervisor / PID 1)                  │
│                                                          │
│   crash-loop guard · kill_tree() · alert tail           │
└──────┬──────────────────────────────────────────────────┘
       │ supervises (restart-on-death)
       │
   ┌───┴────┬────────┬─────────┬──────┬──────────┬────────┐
   │        │        │         │      │          │        │
   ▼        ▼        ▼         ▼      ▼          ▼        ▼
 file_   user_   process_   system_  ua_     fi_      sh_
 integ.  activ.  network    health   events  events   dashboard
   │        │        │         │       │        │        │
   └────────┴────────┴─────────┴───────┴────────┴────────┘
                         │
                         ▼
                   alerting.sh
                   ├── logs/alerts.json     (SIEM-ready, deduped)
                   └── logs/alerts.console.log  (live tail feed)
```

**Why a supervisor?** If one module crashes or hangs, the others keep running and the supervisor relaunches the failed one. A crash-loop guard (3 crashes in 300s → 300s cooldown) prevents hot-loops.

**Pipeline** (auditd_parser → enrichment → correlation_engine) runs on a separate timer inside the supervisor. It correlates raw events across modules ("shell spawned + outbound socket = reverse-shell indicator") and fires higher-confidence alerts.

---

## Install

Clone onto the target host, then run the installer **once as root**:

```bash
sudo bash install.sh
```

The installer:
- detects `apt` / `dnf` / `yum` and installs dependencies: `auditd`, `bc`, `inotify-tools`, `jq`
- deploys auditd rules for user/privilege/persistence/ssh tracking
- creates config templates in `config/` (no live start, no baseline)
- installs the systemd unit (optional)

After install, build the baseline and start monitoring:

```bash
sudo bash main.sh --init     # capture the trusted reference state
sudo bash main.sh            # start the supervisor in the foreground
```

Or run as a service:

```bash
sudo systemctl enable --now hids
sudo systemctl status hids
```

---

## Using it

Once `main.sh` (or the service) is running:

**Live alerts** stream into the supervisor's terminal. In another terminal, query the JSON log:

```bash
# every alert ever fired
jq -s '.' logs/alerts.json

# only criticals
jq -s 'map(select(.severity == "CRITICAL"))' logs/alerts.json

# only real alerts (exclude test runs)
jq -s 'map(select(.test_run == null))' logs/alerts.json
```

**Dashboard** — a colored live view of system health:

```bash
watch -n 1 --color cat logs/system_health.status
```

**Stop** — `Ctrl+C` in the main terminal, or `sudo systemctl stop hids`.

---

## Configuration

All configuration is in `config/`:

| File | Purpose |
|---|---|
| `hids.conf` | Intervals, log paths, dedup window, crash-loop limits |
| `file_integrity.conf` | `CRITICAL_FILES` list (what to hash) |
| `user_activity.conf` | Allowed login hours, trusted IPs, failed-login thresholds |
| `thresholds.conf` | CPU/memory/disk/swap/process-count warning+critical bands |
| `auditd.conf` | `ENABLE_AUDITD` toggle and module names |

Edit, then reload (`systemctl restart hids` or Ctrl+C + re-run `main.sh`).

---

## Testing — real attack simulation

The `tests/` directory holds attack-simulation tests that **actually compromise the test host** in controlled ways and assert the HIDS caught it. Every destructive step is journaled *before* it runs, so `rollback.sh` can undo everything even after a `kill -9`.

**12 attacks across 3 test files:**

| Category | Attack | Alert |
|---|---|---|
| File integrity | Rewrite protected file contents | `CRITICAL` |
| File integrity | `chmod 644` a 600 file | permission drift |
| File integrity | Touch critical file while HIDS runs (inotify) | real-time |
| File integrity (invasive) | Modify real `/etc/shadow` | `CRITICAL` |
| User activity | SSH key dropped in authorized_keys | `CRITICAL` |
| User activity (invasive) | Passwordless account | `CRITICAL` |
| User activity (invasive) | UID 0 backdoor account | `CRITICAL` |
| User activity (invasive) | Service account shell flip | drift |
| Process/network | Rogue listening port | `WARNING` |
| Process/network | Payload dropped + executed from `/tmp` | `CRITICAL` |
| Process/network | Wildcard `0.0.0.0` bind | `WARNING` |
| Process/network | `LD_PRELOAD` injection | `CRITICAL` |

**Run the safe subset:**

```bash
sudo bash tests/run_all.sh
```

**Enable invasive tests** (real `useradd`, real `/etc/shadow` edits — fully rolled back):

```bash
sudo bash tests/run_all.sh --invasive
```

**Pick a single module:**

```bash
sudo bash tests/run_all.sh --module file_integrity
```

**Clean up after a crashed run:**

```bash
sudo bash tests/rollback.sh           # replay the journal
sudo bash tests/rollback.sh --dry-run # preview without acting
```

**Every alert fired during a test** is tagged in `alerts.json` with a `test_run` field so you can filter it out of your production view:

```bash
jq -s 'map(select(.test_run == null))' logs/alerts.json
```

---

## Logs

| Path | Contents |
|---|---|
| `logs/alerts.json` | One JSON object per alert — SIEM-ready (Splunk, Wazuh, ELK) |
| `logs/alerts.console.log` | Flat colored text stream (what the supervisor tails to terminal) |
| `logs/system_health.status` | Live dashboard snapshot (atomic rewrites) |
| `logs/<module>.log` | Per-module stdout/stderr from the supervisor |
| `logs/raw_events.log` | Pipe-delimited events for the correlation engine |
| `logs/pipeline.log` | Output from auditd_parser → enrichment → correlation |

**JSON alert format:**

```json
{
  "timestamp": "2026-04-19T14:30:38+02:00",
  "host": "kali",
  "severity": "CRITICAL",
  "module": "user_activity",
  "message": "authorized_keys modified: /root/.ssh/authorized_keys"
}
```

A `"test_run": "<unix-ts>"` field is added when the alert originated from the test harness.

---

## Directory layout

```
HIDS.v2/
├── install.sh                 # one-shot installer
├── main.sh                    # operator entry point (supervisor launcher)
├── controller.sh              # the supervisor itself
├── config/                    # tunable thresholds, file lists, etc.
├── modules/                   # one script per detector
│   ├── alerting.sh            # centralized alert() function + dedup
│   ├── baseline.sh            # reference-state builder (--init)
│   ├── file_integrity.sh
│   ├── file_integrity_events.sh
│   ├── user_activity.sh
│   ├── user_activity_events.sh
│   ├── process_network.sh
│   ├── system_health.sh
│   ├── system_health_dashboard.sh
│   ├── auditd_parser.sh       # pipeline stage 1
│   ├── enrichment.sh          # pipeline stage 2
│   └── correlation_engine.sh  # pipeline stage 3
├── baselines/                 # trusted snapshot (built by --init)
├── logs/                      # alerts + per-module stdout
├── run/                       # dedup state, lockfiles
└── tests/
    ├── run_all.sh             # orchestrator
    ├── rollback.sh            # undo via journal replay
    ├── lib.sh                 # shared helpers (journal, assertions)
    ├── test_file_integrity.sh
    ├── test_user_activity.sh
    └── test_process_network.sh
```

---

## Requirements

- Linux with `bash` ≥ 4.0
- Root privileges (reads `/etc/shadow`, `/proc/<pid>/exe`, auditd log)
- `auditd`, `inotify-tools`, `bc`, `jq` — installed automatically by `install.sh`

Tested on Kali. Should work on any Debian/Ubuntu/RHEL derivative.

---

## Known limitations

- **Baselines are local** — a compromised host can have its own baseline rewritten. Production deployments should replicate `baselines/` to a read-only remote store.
- **No kernel-level monitoring** — everything is userspace. A kernel rootkit could hide from `/proc` itself, evading our "hidden process" check.
- **auditd rule coverage is opinionated** — see `install.sh` for the exact rule set. Extend in place if your threat model needs more.

---

## License

Educational/project use. No warranty.
=======
The system is built using a **modular architecture**:
Controller → Modules → Raw Events → Correlation → Alerting → Enrichment

- Each module runs independently and detects anomalies in its domain
- Events are written to a centralized log (`raw_events.log`)
- The correlation engine combines weak signals into strong alerts
- Alerts are processed by the alerting module (JSON format)
- Enrichment adds forensic context (process tree, IP resolution, etc.)


### Components

- **Controller**
  - Executes modules periodically  
  - Defines execution frequency  

- **System Health Module (state-based)**
  - Monitors system condition over time  

- **Auditd-based Modules (event-based)**
  - Monitor real-time system activity  

- **Alerting Module**
  - Standardizes alert output  
  - Writes logs  

- **Baselines**
  - Store initial system state for comparison  

---

### Design Approach

The HIDS combines:

- **State-based monitoring**
  - Continuous system condition (CPU, memory, etc.)

- **Event-based monitoring**
  - Discrete actions (process execution, file changes)

This separation improves:
- clarity  
- detection accuracy  
- modularity  

---

## Modules

### Module 1 — System Health

This module provides a real-time assessment of whether the system is operating under normal conditions or experiencing abnormal stress.

#### Purpose
A compromised or misconfigured system often reveals itself through abnormal resource usage. However, high usage alone is not sufficient to trigger an alert — context and persistence matter.

#### What it monitors
- CPU usage (overall load)
- Memory usage
- Disk usage
- System load average

#### Detection approach
This module uses a **state-based monitoring model**:
- It collects system metrics at regular intervals
- Compares them against configurable thresholds (`thresholds.conf`)
- Applies **temporal logic** to avoid false positives

#### Temporal logic
Instead of alerting on a single spike:
- The module tracks whether a condition persists across multiple runs
- Only sustained abnormal behavior triggers an alert

Example:
- CPU spike for 1 second → ignored  
- CPU > threshold for multiple cycles → alert

#### Missing signal detection
The module also detects:
- Missing command outputs
- Failed metric collection

This is important because attackers may interfere with monitoring tools.

#### Output
- Alerts only when abnormal conditions persist
- Reduces noise and avoids alert fatigue

#### Detection type
State-based detection

---

### Module 2 — User Activity

This module monitors authentication behavior, user sessions, privilege escalation, and persistence mechanisms.

#### Purpose
Most attacks begin or evolve through user activity:
- Unauthorized logins
- Privilege escalation
- Persistence via accounts or SSH keys

This module focuses on detecting deviations from expected user behavior.

---

## A. Authentication anomalies

Detects suspicious login behavior:
- Repeated failed logins (brute-force attempts)
- Successful login after multiple failures (compromise indicator)
- Logins outside allowed hours
- Logins from non-whitelisted IPs
- Root login via SSH

#### Detection logic
- Parses authentication logs (`auth.log`)
- Correlates failures and successes per IP
- Applies thresholds and time windows

---

## B. Privilege escalation

Detects attempts to gain elevated privileges:
- New UID 0 accounts (silent root access)
- New members in sudo/wheel groups
- Excessive sudo usage
- Use of `su` (bypasses standard logging)

---

## C. Session anomalies

Detects abnormal session behavior:
- Multiple concurrent sessions for the same user
- Sessions from multiple IPs
- Long idle sessions (potential hijacking)
- Console (TTY) logins on a server

---

## D. Persistence indicators

Detects long-term attacker footholds:
- New user accounts
- Hidden accounts (duplicate UID)
- Changes in user shells
- Unauthorized SSH keys (`authorized_keys`)

---

## E. Log tampering

Detects attempts to hide activity:
- Truncated or deleted log files
- Missing authentication databases

---

## F. Auditd integration

Uses kernel-level audit logs to detect:
- Account modifications
- Privilege escalation attempts
- SSH configuration changes

#### Key strength
- Uses **auid (audit user ID)** → identifies the real user behind sudo

---

#### Detection type
Combination of:
- Event-based detection (log parsing)
- State-based detection (baseline comparison)

---
### Module 3 — Process and Network Audit

This module detects suspicious processes, network activity, and system-level anomalies.

#### Purpose
Attackers operate through processes and network connections:
- Malware execution
- Backdoors
- Reverse shells
- Data exfiltration

---

## Key detections

### 1. Unexpected ports
- Detects listening ports not in the whitelist
- Indicates backdoors or unauthorized services

### 2. New ports vs baseline
- Compares current ports with baseline snapshot
- Detects newly opened services

### 3. Suspicious execution paths
- Detects binaries running from:
  - /tmp
  - /dev/shm
  - /var/tmp
- These are common attacker staging locations

---

### 4. SUID abuse
- Detects new SUID files
- Critical privilege escalation vector

---

### 5. Hidden processes
- Compares `/proc` vs `ps`
- Detects rootkits hiding processes

---

### 6. Advanced attack indicators
- Service accounts spawning shells (webshells)
- Reverse tunnels (SSH -R)
- Shell with active network socket (reverse shell)
- Interpreter with outbound connection (C2 behavior)
- LD_PRELOAD injection
- RWX memory pages (shellcode execution)
- Name spoofing
- Process reparenting (daemonized malware)

---

### 7. Network anomalies
- Connection bursts
- Long-lived connections
- C2 beaconing patterns

---

#### Data sources
- `/proc` → process internals
- `ss` → network sockets
- `ps` → process list
- auditd → execution context

---

#### Detection type
Hybrid:
- State-based (baseline comparison)
- Event-based (real-time inspection)
- Behavioral detection (heuristics)

---

### Module 4 — File Integrity

This module ensures that critical system files have not been modified.

#### Purpose
Attackers modify files to:
- Add backdoors
- Escalate privileges
- Maintain persistence

---

## Detection approach

Uses **cryptographic hashing (SHA-256)**:
- Each file is hashed during baseline creation
- Current hash is compared to baseline

---

## What it detects

- File content changes
- Permission changes
- Ownership changes
- File deletion

---

## Auditd enrichment

When a change is detected:
- Queries audit logs to identify:
  - Who modified the file
  - Which command was used

Example:
- Instead of: "File modified"
- You get: "File modified by user X using command Y"

---

## Design decision

- Baseline is NOT automatically updated
- Admin must manually reinitialize baseline

This prevents attackers from hiding changes.

---

#### Detection type
State-based detection (baseline comparison)

---

### Module 5 — Alerting

This module centralizes all alerts generated by the system.

#### Purpose
A detection system is only useful if alerts are:
- Clear
- Structured
- Actionable
- Not overwhelming

---

## Features

### Structured alerts
- JSON format
- Compatible with SIEM tools (Splunk, ELK, Wazuh)

---

### Severity levels
- INFO → informational
- WARNING → suspicious
- CRITICAL → high-risk

---

### Deduplication
Prevents alert flooding:
- Same alert is suppressed for a configurable time window
- Uses hashing + timestamp tracking

---

## Output
- Stored in `alerts.json`
- Displayed in terminal with color coding

---

#### Detection type
Not a detection module — alert management layer

---

### Module 6 - Baseline

Shows what normal looks like on this machine?

All detection modules rely on this reference to identify anomalies.

---

The baseline module generates 4 reference files:

| File | Description |
|------|------------|
| `file_hashes.txt` | SHA-256 hashes of critical files |
| `users.txt` | list of system users |
| `ports.txt` | list of listening ports |
| `suid.txt` | list of SUID files |

---

This baseline allows other modules to detect:

- file modification → hash change  
- new user → possible backdoor account  
- new port → possible reverse shell  
- new SUID file → privilege escalation  

---

### Data sources used

- `/etc/passwd` → users  
- `ss -tuln` → listening ports  
- `find / -perm -4000` → SUID files  
- `sha256sum` → file integrity  

---

### Execution

The baseline is created using:

```bash`
./baseline.sh --init or via controller with init flag

### Module 7 — Correlation Engine

This module combines multiple weak signals into strong attack indicators.

#### Purpose
Single events are often ambiguous.
Correlation identifies patterns that indicate real attacks.

---

## Core principle
Weak signals → Strong detection

Example:
- Root user → normal
- Execution from /tmp → suspicious
- EXECVE event → normal

Combined:
→ CRITICAL (likely compromise)

---

## Example patterns

- Root execution from /tmp
- Reverse shell indicators
- Download + execution chain
- UID 0 account + root activity
- Permission changes on system binaries

---

## Data source
- `raw_events.log` from all modules

---

#### Detection type
Correlation-based detection (multi-signal analysis)

### Module 8 — Enrichment

This module adds context to alerts to assist investigation.

#### Purpose
Detection tells you WHAT happened.
Enrichment helps you understand:
- HOW it happened
- WHO did it
- WHERE it came from

---

## Enrichment types

### 1. Process ancestry
- Reconstructs execution chain:
  ssh → bash → payload

---

### 2. File attribution
- Uses auditd to identify:
  - User responsible
  - Command used

---

### 3. Reverse DNS
- Converts IP → hostname
- Helps identify attacker infrastructure

---

## Output
- Stored in `enriched.log`

---

#### Detection type
Post-processing (context enhancement)

## Usage

### Initialize baseline:

```bash
sudo bash main.sh --init
```

### Run HIDS

bash main.sh
>>>>>>> 382d66681b9c9a9f2947d0fa4b41b243a80a8ad5
