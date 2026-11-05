"""
Research Module: Primary Forensic Timeline Reconstruction Engine.

Reconstructs primary chronological attack timelines from raw telemetry,
classifying activity into attack phases and timeline categories:
Observed Events, Correlated Events, Inferred Events, Evidence Gaps.
"""

from __future__ import annotations
import datetime
from typing import List, Tuple, Optional
from chronos.shared.models import Event, TimelineItem, EventType, EvidenceGap


class TimelineEngine:
    """Reconstructs and classifies chronological forensic timelines."""

    def __init__(self):
        self.timeline_items: List[TimelineItem] = []

    def classify_stage(self, event: Event) -> Tuple[str, bool, str]:
        """Classify event into attack phase, returning (stage_name, is_suspicious, timeline_category)."""
        comm = (event.comm or "").lower()
        cmdline = (event.cmdline or "").lower()
        event_type = str(event.event_type).lower()

        # Anti-forensics stage
        if any(af in cmdline or af in comm for af in [
            "rm -rf /var/log", "history -c", "systemctl stop auditd", "shred", "touch -t", "date --set",
            "rm ~/.bash_history", "unset histfile", "pkill chronos"
        ]):
            return "Anti-Forensics Attempt", True, "Correlated Events"

        # Reverse Shell / C2 stage
        if any(c2 in cmdline for c2 in ["/dev/tcp/", "nc -e", "ncat -e", "socat exec", "bash -i >& /dev/tcp"]):
            return "Reverse Shell / C2", True, "Correlated Events"
        if comm in ["nc", "ncat", "socat", "chisel", "ngrok"] or (event.target_port and event.target_port in [4444, 1337, 8888, 9001]):
            return "Reverse Shell / C2", True, "Correlated Events"

        # Ingress / Download stage
        if comm in ["curl", "wget", "fetch"] or any(dl in cmdline for dl in ["curl ", "wget ", "urllib"]):
            return "Download / File Ingress", True, "Observed Events"

        # Privilege Escalation stage
        if event_type in [EventType.PRIVILEGE_SUDO.value, EventType.PRIVILEGE_SETUID.value, EventType.PRIVILEGE_CAPABILITY.value] or comm in ["sudo", "su", "pkexec"]:
            return "Privilege Escalation", True, "Observed Events"

        # Session / Login stage
        if comm in ["sshd", "login", "systemd-logind"]:
            return "User Login / Session", False, "Observed Events"

        # Execution stage
        if comm in ["bash", "sh", "zsh", "python", "python3", "perl", "ruby"] and any(susp in cmdline for susp in ["payload", "exploit", ".sh"]):
            return "Malicious Execution", True, "Observed Events"
        if event_type == EventType.EXECVE.value:
            return "Process Execution", False, "Observed Events"

        # File activity stage
        if event_type in [EventType.FILE_CREATE.value, EventType.FILE_DELETE.value, EventType.FILE_RENAME.value, "create", "delete", "modify"]:
            return "File Mutation", False, "Observed Events"

        # Network activity stage
        if event_type in [EventType.CONNECT.value, EventType.BIND.value, EventType.ACCEPT.value, "outbound_connection", "inbound_connection"]:
            return "Network Connection", False, "Observed Events"

        return "System Activity", False, "Observed Events"

    def add_event(self, event: Event) -> TimelineItem:
        """Add an event and reconstruct its timeline representation."""
        stage, suspicious, category = self.classify_stage(event)

        if event.cmdline:
            summary = f"[{event.comm}] {event.cmdline}"
        elif event.target_path:
            summary = f"[{event.comm}] Target: {event.target_path}"
        elif event.target_ip:
            summary = f"[{event.comm}] Connect -> {event.target_ip}:{event.target_port}"
        else:
            summary = f"[{event.comm}] PID {event.pid} triggered {event.event_type}"

        item = TimelineItem(
            timestamp=event.timestamp,
            stage=stage,
            category=category,
            summary=summary,
            detail=f"PID: {event.pid} | PPID: {event.ppid} | User: {event.user} ({event.uid}) | Hash: {(event.evidence_hash or '')[:12]}...",
            event_type=str(event.event_type),
            pid=event.pid,
            comm=event.comm,
            suspicious=suspicious,
            evidence_id=event.event_id,
            evidence_source=event.evidence_source,
        )
        self.timeline_items.append(item)
        self.timeline_items.sort(key=lambda x: x.timestamp)
        return item

    def add_evidence_gap(self, gap: EvidenceGap) -> TimelineItem:
        """Inject evidence gap timeline entry."""
        item = TimelineItem(
            timestamp=gap.start_time,
            stage="Telemetry Interruption",
            category="Evidence Gaps",
            summary=f"EVIDENCE GAP DETECTED ({gap.duration_seconds}s silence)",
            detail=f"Silence from {gap.start_time} to {gap.end_time}. Hypotheses: {'; '.join(gap.hypotheses)}",
            event_type="evidence_gap",
            pid=0,
            comm="gap_detector",
            suspicious=True,
            evidence_id=gap.gap_id,
            evidence_source="Gap Detection Engine",
        )
        self.timeline_items.append(item)
        self.timeline_items.sort(key=lambda x: x.timestamp)
        return item

    def add_inferred_event(
        self,
        timestamp: float,
        stage: str,
        summary: str,
        reasoning: str,
        evidence_ids: List[str]
    ) -> TimelineItem:
        """Add inferred timeline item reconstructed from circumstantial artifacts."""
        item = TimelineItem(
            timestamp=timestamp,
            stage=stage,
            category="Inferred Events",
            summary=f"[INFERRED] {summary}",
            detail=f"Reasoning: {reasoning} | Linked Evidence: {', '.join(evidence_ids)}",
            event_type="inferred",
            pid=0,
            comm="inference_engine",
            suspicious=True,
            evidence_id=evidence_ids[0] if evidence_ids else None,
            evidence_source="Inference Engine",
        )
        self.timeline_items.append(item)
        self.timeline_items.sort(key=lambda x: x.timestamp)
        return item

    def build_from_events(
        self,
        events: List[Event],
        gaps: Optional[List[EvidenceGap]] = None
    ) -> List[TimelineItem]:
        """Build timeline from list of events and optional gaps."""
        self.timeline_items.clear()
        for event in events:
            self.add_event(event)
        if gaps:
            for g in gaps:
                self.add_evidence_gap(g)
        return self.timeline_items

    def generate_summary(self) -> str:
        """Format timeline summary table."""
        if not self.timeline_items:
            return "No timeline events recorded."

        lines = [
            "Primary Forensic Timeline:",
            "---------------------------------------------------------------------------------------------------------",
            f"{'Time':<12} | {'Category':<16} | {'Stage':<22} | {'PID':<6} | {'Summary'}",
            "---------------------------------------------------------------------------------------------------------"
        ]
        for item in self.timeline_items:
            time_str = datetime.datetime.fromtimestamp(item.timestamp).strftime("%H:%M:%S")
            flag = " [!] " if item.suspicious else "     "
            lines.append(f"{time_str:<12} | {item.category:<16} | {item.stage:<22} | {item.pid:<6} |{flag}{item.summary[:45]}")

        lines.append("---------------------------------------------------------------------------------------------------------")
        return "\n".join(lines)
