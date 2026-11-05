"""
System Infrastructure Module: Live Host OS Telemetry Sensor.

Scans the host OS via /proc and psutil, streaming process and network events into EvidenceCollector.
"""

from __future__ import annotations
from typing import List, Set
import psutil
from chronos.system.collector import EvidenceCollector
from chronos.shared.models import Event, EventType


class LiveHostSensor:
    """Polls host OS processes and sockets into EvidenceCollector."""

    def __init__(self, collector: EvidenceCollector):
        self.collector = collector
        self.seen_pids: Set[int] = set()

    def scan_running_processes(self) -> List[Event]:
        """Scan running processes and record initial baseline."""
        new_events = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'uids']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                if pid in self.seen_pids:
                    continue
                self.seen_pids.add(pid)

                ppid = pinfo['ppid'] or 1
                comm = pinfo['name'] or f"proc_{pid}"
                cmdline = " ".join(pinfo['cmdline'] or [])
                uids = pinfo.get('uids')
                uid = uids.real if uids else 1000
                user = "root" if uid == 0 else "user"

                evt_type = EventType.EXECVE.value
                if comm in ["sudo", "su", "pkexec", "doas"]:
                    evt_type = EventType.PRIVILEGE_SUDO.value

                evt = self.collector.record_event(
                    event_type=evt_type,
                    pid=pid,
                    ppid=ppid,
                    uid=uid,
                    user=user,
                    comm=comm,
                    cmdline=cmdline,
                    target_path=cmdline.split()[0] if cmdline else f"/{comm}",
                    evidence_source="Live OS Sensor (/proc)",
                )
                new_events.append(evt)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return new_events

    def scan_network_connections(self) -> List[Event]:
        """Scan active socket connections."""
        events = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.raddr and conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        comm = p.name()
                    except Exception:
                        comm = "network_proc"

                    evt = self.collector.record_event(
                        event_type=EventType.CONNECT.value,
                        pid=conn.pid,
                        comm=comm,
                        target_ip=conn.raddr.ip,
                        target_port=conn.raddr.port,
                        evidence_source="Live Network Sensor",
                    )
                    events.append(evt)
        except Exception:
            pass
        return events
