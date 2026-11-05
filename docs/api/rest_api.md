# CHRONOS-FL REST API Specification

## Endpoints Summary

### System Health
- **`GET /api/status`**: Returns flight recorder health, event counts, snapshot counts, and ledger integrity.

### Telemetry Ingestion
- **`POST /api/events/ingest`**: Ingests JSON event payload (`event_type`, `pid`, `ppid`, `comm`, `cmdline`, `user`, `target_path`, `target_ip`, `target_port`).

### Forensic Data Views
- **`GET /api/timeline`**: Returns reconstructed chronological primary timeline.
- **`GET /api/graph`**: Returns JSON nodes and edges for causality multigraph.
- **`GET /api/alerts`**: Returns anti-forensics alerts with severity and trust penalties.
- **`GET /api/snapshots`**: Returns volatile state snapshots.
- **`GET /api/ledger`**: Returns sealed ledger chunks and hash verification results.
- **`GET /api/trust/scores`**: Returns Evidence Survivability Score (ESS) and Timeline Confidence Score (TCS).

### Case & Reporting
- **`GET /api/cases`**: Returns active investigation case state and analyst notes.
- **`POST /api/cases/notes`**: Updates analyst notes.
- **`GET /api/export/report`**: Generates full machine-readable JSON forensic investigation report.
