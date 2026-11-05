"""
System Infrastructure Module: Evidence Collector.

Normalizes raw event streams and dispatches events across subscribers.
"""

from __future__ import annotations
import time
from typing import Callable, List, Dict, Any, Optional

from chronos.shared.models import Event, EventType
from chronos.shared.logging import get_logger

logger = get_logger("chronos.system.collector")


class EvidenceCollector:
    """Central evidence bus for event normalization and listener dispatching."""

    def __init__(self, host_id: str = "victim_host_01"):
        self.host_id = host_id
        self.events: List[Event] = []
        self._listeners: List[Callable[[Event], None]] = []

    def register_listener(self, callback: Callable[[Event], None]) -> None:
        """Register a subscriber callback."""
        self._listeners.append(callback)

    def record_event(
        self,
        event_type: str,
        pid: int,
        comm: str,
        cmdline: str = "",
        ppid: int = 1,
        uid: int = 1000,
        user: str = "root",
        target_path: Optional[str] = None,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        timestamp: Optional[float] = None,
        evidence_source: str = "eBPF Sensor",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Event:
        """Record event and notify listeners."""
        evt = Event(
            event_type=event_type,
            pid=pid,
            ppid=ppid,
            uid=uid,
            user=user,
            comm=comm,
            cmdline=cmdline,
            target_path=target_path,
            target_ip=target_ip,
            target_port=target_port,
            timestamp=timestamp if timestamp is not None else time.time(),
            host_id=self.host_id,
            evidence_source=evidence_source,
            metadata=metadata or {},
        )
        self.events.append(evt)

        for listener in self._listeners:
            try:
                listener(evt)
            except Exception as e:
                logger.error(f"Error in evidence listener callback: {e}")

        return evt

    def ingest_event_dict(self, data: Dict[str, Any]) -> Event:
        """Ingest dictionary event representation."""
        return self.record_event(
            event_type=data.get("event_type", EventType.EXECVE.value),
            pid=data.get("pid", 0),
            ppid=data.get("ppid", 1),
            uid=data.get("uid", 1000),
            user=data.get("user", "root"),
            comm=data.get("comm", "unknown"),
            cmdline=data.get("cmdline", ""),
            target_path=data.get("target_path"),
            target_ip=data.get("target_ip"),
            target_port=data.get("target_port"),
            timestamp=data.get("timestamp"),
            evidence_source=data.get("evidence_source", "Ingest API"),
            metadata=data.get("metadata", {}),
        )

    def filter_events(
        self,
        event_type: Optional[str] = None,
        pid: Optional[int] = None,
        category: Optional[str] = None,
    ) -> List[Event]:
        """Filter events by type, PID, or category."""
        res = self.events

        def _val(e_type) -> str:
            return (e_type.value if hasattr(e_type, "value") else str(e_type)).lower()

        if event_type:
            target_val = _val(event_type)
            res = [e for e in res if _val(e.event_type) == target_val]
        if pid:
            res = [e for e in res if e.pid == pid]
        if category:
            cat = category.lower()
            if cat == "process":
                res = [e for e in res if _val(e.event_type) in ["execve", "fork", "clone"]]
            elif cat == "file":
                res = [e for e in res if _val(e.event_type) in ["file_create", "file_delete", "file_rename", "create", "delete", "rename"]]
            elif cat == "network":
                res = [e for e in res if _val(e.event_type) in ["connect", "bind", "accept", "outbound_connection", "inbound_connection"]]
            elif cat == "privilege":
                res = [e for e in res if _val(e.event_type) in ["sudo", "setuid", "capability_change", "privilege_sudo", "privilege_setuid"]]
        return res

    def clear(self) -> None:
        """Clear collector queue."""
        self.events.clear()
