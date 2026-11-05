# CHRONOS-FL — Cyber Forensic Flight Recorder & Evidence Trust Platform

> **Preserving Forensic Evidence and Quantifying Timeline Trust in the Face of Anti-Forensic Evidence Destruction.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Build Status](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)

---

## 🎯 Vision & Core Problem

When attackers compromise Linux systems, they routinely perform **anti-forensic techniques** to cover their tracks:

```bash
history -c                       # Clear shell command history
rm -rf /var/log/*                # Wipe system logs
systemctl stop auditd            # Shut down kernel audit daemon
shred -u malware.bin             # Securely delete payload binaries
touch -t 202001010000 payload    # Timestomp file timestamps
date --set="2020-01-01 00:00:00" # Alter system wall clock
```

When incident responders and forensic investigators arrive on scene:
- ❌ **Logs are Missing**
- ❌ **History is Cleared**
- ❌ **Payloads are Wiped**
- ❓ **Can any part of the remaining timeline be trusted?**

**CHRONOS-FL** acts as a **digital flight recorder** that continuously records forensic-relevant events via low-overhead kernel telemetry, reconstructs causality timelines, detects anti-forensic evidence destruction in real time, seals evidence inside a cryptographically chained ledger, and computes quantitative **Evidence Survivability (ESS)** and **Timeline Confidence (TCS)** metrics.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           eBPF Sensors / CO-RE                          │
│               (sys_enter_execve, sys_enter_connect, etc.)                │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Module 1: Evidence Collector                      │
│             (Process, File, Network, Privilege Event Streams)           │
└────────────┬───────────────────────┬────────────────────────┬───────────┘
             │                       │                        │
             ▼                       ▼                        ▼
┌──────────────────────┐  ┌──────────────────────┐  ┌───────────────────┐
│ Module 2: Timeline   │  │ Module 3: Evidence   │  │ Module 4: Anti-   │
│   Reconstruction     │  │    Causality Graph   │  │ Forensic Detector │
└────────────┬─────────┘  └──────────┬───────────┘  └─────────┬─────────┘
             │                       │                        │
             │                       │                        ▼
             │                       │              ┌───────────────────┐
             │                       │              │ Module 5: Snapshot│
             │                       │              │     Recorder      │
             │                       │              └─────────┬─────────┘
             │                       │                        │
             └───────────────────────┼────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Module 6: Evidence Ledger                          │
│               (Tamper-Evident SHA-256 Cryptographic Hash Chain)          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│               Modules 7 & 8: Trust Analysis Engine                      │
│      (ESS: Evidence Survivability Score & TCS: Timeline Confidence Score)│
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│             Module 9: Investigation Dashboard & REST API                │
│            (Interactive Web UI & Real-Time Security Monitoring)         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Complete Module Breakdown

| Module | Name | Responsibility | Status |
|---|---|---|---|
| **Module 1** | **Evidence Collector** | Continuous collection of Process (`execve`, `fork`, `clone`), File (`create`, `delete`, `rename`), Network (`connect`, `bind`, `accept`), and Privilege (`sudo`, `setuid`, capabilities) events. | ✅ Verified |
| **Module 2** | **Timeline Reconstruction** | Reconstructs the primary chronological forensic timeline (`User Login` ➔ `Download` ➔ `Execution` ➔ `C2 Reverse Shell`). | ✅ Verified |
| **Module 3** | **Evidence Graph** | Constructs causal relationships (`User` ➔ `Bash` ➔ `Curl` ➔ `Payload` ➔ `Reverse Shell`) to analyze attack lineage. | ✅ Verified |
| **Module 4** | **Anti-Forensic Detection** | Signature & behavioral detection of log deletion (`rm -rf /var/log`), history clearing (`history -c`), audit shutdown (`systemctl stop auditd`), secure wiping (`shred`), timestomping (`touch -t`), and time changes (`date --set`). | ✅ Verified |
| **Module 5** | **Snapshot Recorder** | Automatically captures volatile system state (running processes, sockets, open file descriptors, loaded kernel modules, container state) before evidence disappears. | ✅ Verified |
| **Module 6** | **Evidence Ledger** | Cryptographically seals timeline chunks (`Chunk 1` ➔ `Chunk 2` ➔ `Chunk 3`) into a SHA-256 hash chain to guarantee tamper detection. | ✅ Verified |
| **Module 7** | **Evidence Survivability Score (ESS)** | Quantifies what percentage of expected evidence sources survived (`ESS = 80%`). | ✅ Verified |
| **Module 8** | **Timeline Confidence Score (TCS)** | Quantifies confidence in reconstructed timeline based on missing logs, anti-forensics, timestamp anomalies, and ledger integrity (`TCS = 92%`). | ✅ Verified |
| **Module 9** | **Investigation Dashboard** | Embedded Web Dashboard & FastAPI REST backend providing full visibility into timeline, causality graph, ESS/TCS scores, alerts, and snapshots. | ✅ Verified |

---

## 🚀 Quickstart & Usage

### 1. Run End-to-End Pipeline Demo
```bash
python3 demo_full_pipeline.py
```
*or via Makefile:*
```bash
make demo
```

### 2. Run Interactive Attack & Anti-Forensics Simulation
```bash
python3 demo_attack_simulation.py
```

### 3. Launch Investigation Dashboard & REST API
```bash
python3 chronos_cli.py serve --port 8000
```
Open **http://127.0.0.1:8000** in your browser to view the live interactive forensic investigation UI.

### 4. Run Automated Test Suite
```bash
python3 -m pytest tests/ -v
```

---

## 📊 Trust Analysis Metrics Formulations

### Evidence Survivability Score (ESS)
$$\text{ESS} = \left( \frac{\sum_{s \in \text{Surviving Sources}} w_s}{\sum_{s \in \text{All Expected Sources}} w_s} \right) \times 100\%$$

Example output when system logs and shell history are wiped:
- Audit Logs: **Lost** (Weight: 2.5)
- Systemd Journal: **Lost** (Weight: 1.5)
- eBPF Trace: **Present** (Weight: 3.0)
- Network Flow Logs: **Present** (Weight: 3.0)
- Command History: **Lost** (Weight: 1.0)
$$\rightarrow \text{ESS} = 54.5\%$$

### Timeline Confidence Score (TCS)
$$\text{TCS} = 100\% - P_{\text{missing}} - P_{\text{deletion}} - P_{\text{history}} - P_{\text{clock}} - P_{\text{tampering}}$$

Confidence Levels:
- **90% - 100%**: `HIGH` — Fully trustworthy timeline.
- **75% - 89%**: `MEDIUM` — Moderately trustworthy.
- **50% - 74%**: `LOW` — Low confidence due to evidence destruction.
- **< 50%**: `CRITICAL_TAMPERING` — Compromised or tampered ledger/timeline.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
