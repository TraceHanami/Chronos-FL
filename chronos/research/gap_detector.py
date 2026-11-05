"""
Research Module: Evidence Gap Detection Engine.

Analyzes telemetry stream gaps to identify periods of missing visibility, daemon shutdown,
or agent network disconnects. Formulates objective hypotheses without biased attribution.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from chronos.shared.models import Event, EvidenceGap, AntiForensicAlert, AntiForensicCategory, EventType
from chronos.shared.logging import get_logger

logger = get_logger("chronos.research.gap_detector")


class EvidenceGapDetector:
    """Detects telemetry silence gaps and correlates with audit or agent state events."""

    def __init__(self, max_allowed_gap_seconds: float = 60.0):
        self.max_allowed_gap = max_allowed_gap_seconds
        self.gaps: List[EvidenceGap] = []

    def analyze_timeline_gaps(
        self,
        events: List[Event],
        alerts: List[AntiForensicAlert]
    ) -> List[EvidenceGap]:
        """Scan ordered telemetry events and construct EvidenceGap records for gaps exceeding threshold."""
        if len(events) < 2:
            return self.gaps

        sorted_events = sorted(events, key=lambda x: x.timestamp)
        new_gaps: List[EvidenceGap] = []

        for i in range(len(sorted_events) - 1):
            curr_evt = sorted_events[i]
            next_evt = sorted_events[i + 1]
            diff = next_evt.timestamp - curr_evt.timestamp

            if diff > self.max_allowed_gap:
                start_t = curr_evt.timestamp
                end_t = next_evt.timestamp

                causes: List[str] = []
                hypotheses: List[str] = []

                # Correlate with alerts occurring near gap start
                related_alerts = [a for a in alerts if abs(a.timestamp - start_t) <= 15.0 or (start_t <= a.timestamp <= end_t)]

                for alert in related_alerts:
                    cat = str(alert.category)
                    if AntiForensicCategory.AUDIT_SHUTDOWN.value in cat:
                        causes.append("Audit Daemon Shutdown Event")
                        hypotheses.append("Adversary intentionally disabled auditd telemetry ring buffer via auditctl or systemctl.")
                    elif AntiForensicCategory.LOG_DELETION.value in cat:
                        causes.append("System Log Wiping Event")
                        hypotheses.append("Adversary cleared log files, destroying telemetry records prior to gap.")
                    elif AntiForensicCategory.AGENT_TERMINATION.value in cat:
                        causes.append("Flight Recorder Agent Termination")
                        hypotheses.append("Agent process was SIGKILLed or uninstalled.")

                # Check for heartbeat or system stop events
                if "heartbeat" in str(curr_evt.event_type) or "heartbeat" in str(next_evt.event_type):
                    causes.append("Network Interruption / Agent Disconnect")
                    hypotheses.append("Network socket connection dropped between agent and remote collector.")

                if not causes:
                    causes.append("Telemetry Silence / Inactive Host Period")
                    hypotheses.append("Endpoint was idle, sleeping, rebooting, or sensor dropped high-volume buffer drops.")

                hypotheses.append("System reboot, kernel crash, or maintenance window occurred.")

                gap = EvidenceGap(
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=round(diff, 2),
                    potential_causes=causes,
                    hypotheses=hypotheses,
                    evidence_source="Evidence Gap Detection Engine",
                )
                new_gaps.append(gap)
                logger.info(f"Evidence Gap Detected: {diff:.1f}s from {start_t} to {end_t}")

        self.gaps = new_gaps
        return self.gaps

    def clear(self) -> None:
        self.gaps.clear()
