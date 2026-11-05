"""
Unit Tests for CHRONOS-FL System Infrastructure (Collector, Ledger, Snapshots).
"""

from chronos.system.collector import EvidenceCollector
from chronos.system.ledger_storage import EvidenceLedgerStorage
from chronos.system.snapshot_recorder import SnapshotRecorder
from chronos.shared.models import Event, EventType, AntiForensicAlert


def test_evidence_collector():
    collector = EvidenceCollector(host_id="unit_test_host")
    collector.record_event(event_type=EventType.EXECVE.value, pid=1001, comm="bash", cmdline="/bin/bash")
    collector.record_event(event_type=EventType.CONNECT.value, pid=1002, comm="nc", target_ip="1.1.1.1", target_port=80)

    assert len(collector.events) == 2
    assert len(collector.filter_events(category="process")) == 1
    assert len(collector.filter_events(category="network")) == 1


def test_ledger_storage_hash_chain():
    storage = EvidenceLedgerStorage(chunk_size=2)
    storage.add_event(Event(event_type=EventType.EXECVE.value, pid=1, comm="init"))
    storage.add_event(Event(event_type=EventType.EXECVE.value, pid=2, comm="sshd"))

    assert len(storage.chunks) == 1
    valid, issues = storage.verify_integrity()
    assert valid is True

    # Tamper test
    storage.tamper_with_chunk(chunk_index=0, modified_event_index=0, key="comm", new_value="tampered")
    valid_after, issues_after = storage.verify_integrity()
    assert valid_after is False
    assert len(issues_after) > 0


def test_snapshot_recorder():
    recorder = SnapshotRecorder()
    snap = recorder.capture_snapshot(trigger_reason="Unit Test", live_system=False)

    assert snap.trigger_reason == "Unit Test"
    assert len(snap.processes) > 0
    assert len(snap.network_connections) > 0
