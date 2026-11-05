# CHRONOS-FL System Design & Domain Architecture

## Overview
CHRONOS-FL follows a domain-driven, modular architecture separating research algorithms from system infrastructure.

### Directory Responsibilities

- **`chronos/config/`**: System configuration isolation via Pydantic `BaseSettings`.
- **`chronos/shared/`**: Pydantic v2 schemas (`Event`, `AntiForensicAlert`, `Snapshot`, `LedgerChunk`, `ESSResult`, `TCSResult`), structured logging, and custom exception classes.
- **`chronos/research/`**: Pure domain research engines:
  - `timeline_engine.py`: Reconstructs attack timeline stages.
  - `causality_engine.py`: Directed multigraph causality lineage.
  - `detection_engine.py`: Anti-forensic behavioral detection signatures.
  - `trust_engine.py`: ESS and TCS trust score formulation.
- **`chronos/system/`**: Low-level infrastructure:
  - `collector.py`: Event collection bus and listener dispatching.
  - `live_sensor.py`: `/proc` and `psutil` live OS telemetry collector.
  - `snapshot_recorder.py`: System state snapshot recorder.
  - `ledger_storage.py`: SHA-256 hash-chained tamper-evident block storage.
- **`chronos/api/`**: FastAPI REST router, dependency injection, and endpoint controllers.
- **`chronos/ui/`**: Professional single-page DFIR Workstation frontend HTML/CSS/JS template.
- **`chronos/cli/`**: CLI tool entry points (`chronos-fl status`, `demo`, `sim`, `serve`).
