# CHRONOS-FL Architecture & Technical Specification

## 1. System Overview

CHRONOS-FL is an open-source Cyber Forensic Flight Recorder and Evidence Trust Platform designed for Digital Forensics Analysts, Incident Response (DFIR) teams, and Security Researchers.

Unlike traditional SIEM/EDR platforms that assume log streams are complete and immutable, CHRONOS-FL assumes an adversarial threat model where attackers actively attempt evidence destruction.

---

## 2. High-Level System Design & Component Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Kernel & OS Telemetry                            │
│                 (CO-RE eBPF Probes, sys_enter_execve, /proc)                │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           System Infrastructure                             │
│                  chronos.system.collector (Evidence Bus)                    │
└───────────────┬──────────────────────┬───────────────────────┬──────────────┘
                │                      │                       │
                ▼                      ▼                       ▼
┌─────────────────────────┐  ┌────────────────────┐  ┌─────────────────────────┐
│ chronos.research        │  │ chronos.research   │  │ chronos.research        │
│   .timeline_engine      │  │   .causality_engine│  │   .detection_engine     │
└───────────────┬─────────┘  └─────────┬──────────┘  └─────────┬───────────────┘
                │                      │                       │
                │                      │                       ▼
                │                      │             ┌─────────────────────────┐
                │                      │             │ chronos.system          │
                │                      │             │   .snapshot_recorder    │
                │                      │             └─────────┬───────────────┘
                │                      │                       │
                └──────────────────────┼───────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           System Infrastructure                             │
│               chronos.system.ledger_storage (SHA-256 Hash Chain)            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Research Trust Layer                              │
│              chronos.research.trust_engine (ESS & TCS Computation)          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        API & Workstation UI Layer                           │
│               chronos.api (REST Router) & chronos.ui (DFIR SPA)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Domain Boundary Layer Mapping

| Layer | Package Path | Primary Responsibilities |
|---|---|---|
| **Configuration** | `chronos.config` | Centralized settings isolation using Pydantic `BaseSettings` with environment variable overrides. |
| **Shared Domain** | `chronos.shared` | Strongly-typed Pydantic v2 DTOs, custom exceptions, and structured logging. |
| **Research Core** | `chronos.research` | Publication-ready algorithms for Timeline Reconstruction, Causality Graphing, Anti-Forensics Detection, and ESS/TCS Trust Engine. |
| **System Mechanics** | `chronos.system` | Telemetry event bus (`collector.py`), live OS sensor polling (`live_sensor.py`), volatile snapshot state recorder (`snapshot_recorder.py`), and cryptographic block storage (`ledger_storage.py`). |
| **API & Workstation** | `chronos.api` / `chronos.ui` | FastAPI REST endpoints, OpenAPI schemas, and single-page DFIR Workstation UI. |
| **CLI & Launchers** | `chronos.cli` / `scripts` | CLI command entry points and operational simulation scripts. |

---

## 4. Threat Model & Security Properties

### Adversary Capabilities
Adversaries with root/sudo privileges are assumed capable of:
1. Clearing command history files (`history -c`, `rm ~/.bash_history`).
2. Deleting system logs (`rm -rf /var/log/*`, truncating log streams).
3. Terminating security daemons (`systemctl stop auditd`, killing auditctl).
4. Securely wiping malware binaries (`shred -u`).
5. Altering inode metadata and timestamps (`touch -t`).
6. Tampering with system clocks (`date --set`).

### Security Invariants & Defenses
- **Asynchronous eBPF Flight Recording:** Telemetry events are captured at kernel syscall entry points prior to userspace log modification.
- **Immediate Snapshot Capture:** Anti-forensic detections instantly trigger volatile memory and socket state captures before processes terminate.
- **Cryptographic Tamper-Evident Ledger:** Evidence events are sealed into sequential SHA-256 hash chains. Post-hoc ledger tampering immediately breaks previous hash references ($H_n \neq \text{SHA256}(H_{n-1} \parallel \text{Events})$), reducing TCS confidence to `CRITICAL_TAMPERING`.

---

## 5. Research Contributions

1. **Anti-Forensic Behavior Detection:** Rules and signatures quantifying active evidence destruction attempts.
2. **Evidence Survivability Score (ESS):** Weighted quantitative ratio of surviving vs destroyed expected forensic sources.
3. **Timeline Confidence Score (TCS):** Penalty-delineated score measuring trustworthiness of the reconstructed timeline.
4. **Tamper-Evident Cryptographic Ledger:** Block-chained forensic audit trail guaranteeing mathematical integrity verification.
