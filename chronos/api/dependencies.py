"""
API Dependencies & Shared Service Provider for CHRONOS-FL.
"""

from __future__ import annotations
import time
from chronos.system.collector import EvidenceCollector
from chronos.system.snapshot_recorder import SnapshotRecorder
from chronos.system.ledger_storage import EvidenceLedgerStorage
from chronos.system.repository import EvidenceRepository
from chronos.system.heartbeat import HeartbeatMonitor
from chronos.research.timeline_engine import TimelineEngine
from chronos.research.causality_engine import CausalityEngine
from chronos.research.detection_engine import AntiForensicsDetectionEngine
from chronos.research.trust_engine import TrustAnalysisEngine
from chronos.research.gap_detector import EvidenceGapDetector
from chronos.ai_assistant.investigator import AIInvestigator
from chronos.shared.models import Event

# Global Core Instances
collector = EvidenceCollector(host_id="victim_host_01")
repository = EvidenceRepository()
timeline_engine = TimelineEngine()
causality_engine = CausalityEngine(host_id="victim_host_01")
detection_engine = AntiForensicsDetectionEngine()
gap_detector = EvidenceGapDetector(max_allowed_gap_seconds=60.0)
snapshot_recorder = SnapshotRecorder()
ledger_storage = EvidenceLedgerStorage()
trust_engine = TrustAnalysisEngine()
ai_investigator = AIInvestigator()

def _pipeline_event_bus(event: Event) -> None:
    timeline_engine.add_event(event)
    causality_engine.ingest_event(event)
    detection_engine.analyze_event(event)
    ledger_storage.add_event(event)
    repository.store_event(event)

collector.register_listener(_pipeline_event_bus)
detection_engine.register_alert_callback(snapshot_recorder.on_anti_forensic_alert)
detection_engine.register_alert_callback(lambda a, e: repository.store_alert(a))

heartbeat_monitor = HeartbeatMonitor(event_callback=_pipeline_event_bus, expected_interval_seconds=30.0)

# Case State Storage
case_state = {
    "case_id": "CAS-2026-0915-01",
    "title": "Unauthenticated Intrusion & Anti-Forensic Log Wiping Investigation",
    "investigator": "Lead DFIR Analyst",
    "subject_host": "victim_host_01 (192.168.1.50)",
    "status": "Active Investigation",
    "created_at": time.time() - 3600,
    "analyst_notes": "Initial analysis indicates adversary accessed the system via SSH, downloaded a malicious stager, spawned a reverse shell C2 connection, and attempted to wipe system logs (/var/log/*), clear command history, and terminate auditd.",
}
