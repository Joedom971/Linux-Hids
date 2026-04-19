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

---

## Architecture

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
