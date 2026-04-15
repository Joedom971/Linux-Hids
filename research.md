# Bash-Based Linux HIDS — Unified Research Document

---

# Phase 1
## 1. Research for a Bash-Based Linux HIDS (Unified Version)

### 1. Core Question: What separates a good monitoring tool from a bad one?

Before designing any HIDS, we analyzed real-world tools:
- Wazuh
- OSSEC
- Auditd
- Tripwire

The goal is not to replicate their features, but to understand their design philosophy.

---

## 2. What Good HIDS / Monitoring Tools Have in Common

### 🔹 1. Collect locally, decide intelligently
- Data is collected on the host (locally)
- Only meaningful or enriched events are sent outward
- Rule: never ship raw data without context

Prefer:
- process trees
- usernames
- hashes
- structured metadata

---

### 🔹 2. Baseline-first design (not alert-first)
- Establish a known-good state first
- Then detect deviations

Examples:
- File checksums baseline (Tripwire model)
- Running services snapshot
- System state snapshot

Baseline first → Monitor second → Alert on deviation

---

### 🔹 3. Noise control is critical
- Too many alerts → system becomes useless
- Alert fatigue reduces security response quality

Good tools:
- filter noise
- prioritize events
- suppress low-value signals

---

### 🔹 4. Severity classification is required
Not all events are equal.

Examples:
- Wazuh rule levels (0–15)
- Tripwire policy categorization
- Auditd kernel audit priorities

---

### 🔹 5. Structured + persistent output
Good tools:
- alerts are stored
- logs are machine-readable
- timestamps + context included

Bad tools:
- terminal-only output
- no history

---

### 🔹 6. Explainability / traceability
A good alert must answer:
- Why was this flagged?
- What rule triggered it?
- What context supports it?

---

### 🔹 7. Actionable alerts only
A good tool:
- filters noise
- highlights anomalies
- produces actionable alerts

---

## 3. What a Bad Monitoring Tool Looks Like

- dumps raw output
- no interpretation
- no baseline
- no context
- excessive alerts
- no severity
- no persistence
- not machine-readable

---

## 4. Core Design Conclusions for Our Bash HIDS

Must focus on:
- low noise output
- severity levels
- persistent logging
- baseline comparison
- structured logs (JSON)
- context enrichment

---

## FINAL DESIGN PHILOSOPHY
A HIDS is not about collecting data — it is about defining what abnormal means on a system.

---

## 5. Architecture & Design Choices

### Modular Agent Architecture
Modules:
- syscheck
- root check
- log collector
- process monitor
- network monitor

---

### Separation of concerns
- Collector → gathers facts
- Analyzer → decides abnormality
- Output → formats alerts

---

### Rule Engine
- config-based rules
- NOT hardcoded if-statements

---

### Event-driven vs periodic
Old:
- periodic scans

Modern:
- event-driven detection

---

### Kernel vs User space vs eBPF
- user-space: safe
- kernel: powerful but risky
- eBPF: modern safe alternative

---

## 6. Data Design Requirements

```json
{
  "timestamp": "",
  "user": "",
  "process_id": "",
  "action": "",
  "hash": "",
  "context": ""
}
```

Never ship raw data → always ship context.

---

## 7. System Health Monitoring Module

### Purpose
Is the system healthy or under stress?

---

### Core System Signals
- CPU load average
- Memory pressure
- Swap usage
- Disk usage
- I/O pressure
- Process count
- uptime stability
- kernel + system errors

---

### Healthy vs Stressed State

| Metric | Healthy | Stressed |
|--------|--------|----------|
| Load | below cores | above cores |
| Memory | stable | low |
| Swap | none | increasing |
| Disk | <80% | >90% |
| Processes | stable | spike |
| Uptime | stable | unstable |
| Logs | clean | errors |

---

### Linux Exposure (/proc)
- /proc/loadavg
- /proc/meminfo
- /proc/uptime
- /proc/stat
- /proc/vmstat
- /proc/diskstats
- /proc/pressure/

---

### Commands
- uptime
- free -h
- df -h
- vmstat
- ps
- dmesg
- journalctl

---

### Alert thresholds
- load > cores → warning/critical
- memory < 20% → warning
- disk > 80% → warning
- disk > 90% → critical
- swap increasing → issue

---

### Key principle
Never alert on single snapshot → use trends

---

## 8. Users & Activity Monitoring

Tracks:
- logins
- sessions
- sudo usage
- privilege escalation

Sources:
- /var/log/auth.log
- /var/log/wtmp
- /var/log/btmp
- /etc/passwd

Suspicious:
- root SSH login
- brute force
- new users
- sudo abuse

---

## 9. Processes & Network Monitoring

### Processes
- /proc/[pid]
- ps aux

Suspicious:
- /tmp execution
- deleted binaries
- high CPU
- abnormal PPID

---

### Network
- ss -tulnp
- lsof -i
- /proc/net/tcp

Suspicious:
- new ports
- reverse shells
- beaconing
- raw sockets

---

## 10. File Integrity Monitoring

Critical files:
- /etc/passwd
- /etc/shadow
- /etc/sudoers
- /etc/ssh/sshd_config
- /etc/crontab

Detection:
- hash change
- permission change
- ownership change
- SUID detection

---

## 11. Logging & Alerting

Sources:
- journald
- syslog
- auditd
- kernel logs

Formats:
- JSON
- pipe logs

Severity:
- INFO
- WARNING
- CRITICAL

---

## 12. Final System Philosophy

A HIDS is not a logger.

It is:
a decision system that detects abnormal system behavior using:
    - baseline comparison
    - correlation
    - structured context
    - severity ranking