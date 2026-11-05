"""
Live Host Sensor for CHRONOS-FL.

Scans the local Linux host for active processes, network connections,
privilege transitions, and file system activities.
"""

from __future__ import annotations
import os
import time
from typing import List

import psutil
from chronos.collector.collector import EvidenceCollector
from chronos.models import EventType, Event


class LiveHostSensor:
    """
    Sensor component that polls Linux OS status and streams live telemetry into EvidenceCollector.
    """

    def __init__(self, collector: EvidenceCollector):
        self.collector = collector
        self.seen_pids = set()

    def scan_running_processes(self) -> List[Event]:
        """Scan running processes and record initial process tree baseline."""
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

                # Check if command is privilege escalation (sudo / setuid)
                event_type = EventType.EXECVE
                if comm in ["sudo", "su", "pkexec", "doas"]:
                    event_type = EventType.PRIVILEGE_SUDO

                evt = self.collector.record_event(
                    event_type=event_type,
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
        """Scan active network sockets on host."""
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
                        event_type=EventType.CONNECT,
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
