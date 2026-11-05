from __future__ import annotations
from typing import Callable, List, Optional
from chronos.shared.models import Event, AntiForensicAlert, AntiForensicCategory, EventType
from chronos.shared.logging import get_logger

logger = get_logger("chronos.research.detection")


class AntiForensicsDetectionEngine:
    def __init__(self):
        self.alerts: List[AntiForensicAlert] = []
        self._on_alert_callbacks: List[Callable[[AntiForensicAlert, Event], None]] = []

    def register_alert_callback(self, cb: Callable[[AntiForensicAlert, Event], None]) -> None:
        self._on_alert_callbacks.append(cb)

    def analyze_event(self, evt: Event) -> Optional[AntiForensicAlert]:
        cmd = (evt.cmdline or "").lower()
        comm = (evt.comm or "").lower()
        tgt = (evt.target_path or "").lower()
        e_type = str(evt.event_type).lower()

        cat: Optional[AntiForensicCategory] = None
        desc = ""
        sev = "HIGH"

        if any(p in cmd for p in ["/var/log", "/var/audit", "/var/adm", "journald"]) and any(
            op in cmd for op in ["rm ", "truncate", "> /var/log", "unlink", "shred"]
        ):
            cat = AntiForensicCategory.LOG_DELETION
            desc = f"Log deletion attempt: '{evt.cmdline}'"
            sev = "CRITICAL"
        elif "file_delete" in e_type or "delete" in e_type:
            if tgt and any(p in tgt for p in ["/var/log/", "/var/audit/", "/var/adm/"]):
                cat = AntiForensicCategory.LOG_DELETION
                desc = f"Log file deletion: '{tgt}'"
                sev = "CRITICAL"

        elif any(p in cmd for p in ["history -c", ".bash_history", ".zsh_history", "unset histfile", "histfile=/dev/null", "histfilesize=0"]):
            cat = AntiForensicCategory.HISTORY_CLEARING
            desc = f"Shell history clearing: '{evt.cmdline}'"
            sev = "HIGH"

        elif any(p in cmd for p in ["stop auditd", "auditctl -e 0", "disable auditd", "killall auditd", "service auditd stop", "systemctl stop auditd"]):
            cat = AntiForensicCategory.AUDIT_SHUTDOWN
            desc = f"Audit daemon shutdown: '{evt.cmdline}'"
            sev = "CRITICAL"
        elif e_type == EventType.AUDITD_CHANGE.value or (comm == "auditctl" and "-e 0" in cmd):
            cat = AntiForensicCategory.AUDIT_SHUTDOWN
            desc = f"Audit subsystem shutdown: '{evt.cmdline}'"
            sev = "CRITICAL"

        elif comm in ["shred", "srm"] or "shred " in cmd or ("dd if=/dev/zero" in cmd and "of=" in cmd) or "srm " in cmd:
            cat = AntiForensicCategory.SECURE_DELETION
            desc = f"Secure file wiping: '{evt.cmdline}'"
            sev = "HIGH"

        elif comm == "touch" and any(f in cmd for f in ["-t ", "-r ", "-d ", "--date", "--reference"]):
            cat = AntiForensicCategory.TIMESTAMP_MANIPULATION
            desc = f"Timestamp manipulation: '{evt.cmdline}'"
            sev = "MEDIUM"

        elif comm in ["date", "timedatectl", "adjtimex"] and any(p in cmd for p in ["--set", "set-time", "-s "]):
            cat = AntiForensicCategory.TIME_CHANGE
            desc = f"System clock alteration: '{evt.cmdline}'"
            sev = "HIGH"

        elif any(t in cmd for t in ["pkill chronos", "killall chronos", "stop chronos", "kill -9 chronos"]) or (
            comm in ["kill", "pkill", "killall"] and "chronos" in cmd
        ):
            cat = AntiForensicCategory.AGENT_TERMINATION
            desc = f"Agent termination attempt: '{evt.cmdline}'"
            sev = "CRITICAL"

        elif any(c in cmd or c in tgt for c in ["rsyslog.conf", "journald.conf", "syslog-ng.conf", "audit.rules"]):
            if any(op in cmd for op in [">", "echo", "sed", "vi", "nano", "rm", "mv"]):
                cat = AntiForensicCategory.LOGGING_RECONFIGURATION
                desc = f"Logging reconfig: '{evt.cmdline}'"
                sev = "HIGH"

        if not cat:
            return None

        alert = AntiForensicAlert(
            category=cat.value,
            description=desc,
            pid=evt.pid,
            comm=evt.comm,
            cmdline=evt.cmdline,
            severity=sev,
            timestamp=evt.timestamp,
            evidence_source=evt.evidence_source,
            metadata={"trigger_event_id": evt.event_id},
        )
        self.alerts.append(alert)
        logger.warning(f"Anti-Forensics Alert: [{alert.severity}] {alert.category} - {alert.description}")

        for cb in self._on_alert_callbacks:
            cb(alert, evt)

        return alert

    def analyze_events(self, events: List[Event]) -> List[AntiForensicAlert]:
        detected = []
        for evt in events:
            alert = self.analyze_event(evt)
            if alert:
                detected.append(alert)
        return detected

    def clear(self) -> None:
        self.alerts.clear()
