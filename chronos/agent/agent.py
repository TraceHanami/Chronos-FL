"""
Module 1: CHRONOS Linux Evidence Collection Agent.

Monitors process, file, network, auth, privilege, service, and audit telemetry events.
"""

from __future__ import annotations
import os
import time
from typing import Callable, List, Optional, Set, Dict, Any
import psutil

from chronos.shared.models import Event, EventType
from chronos.shared.logging import get_logger

logger = get_logger("chronos.agent")


class LinuxEvidenceAgent:
    """Linux Endpoint Evidence Collection Agent."""

    def __init__(self, host_id: str = "victim_host_01", callback: Optional[Callable[[Event], None]] = None):
        self.host_id = host_id
        self.callback = callback
        self.seen_pids: Set[int] = set()

    def create_event(
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
        evidence_source: str = "CHRONOS Agent",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Event:
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
            timestamp=time.time(),
            host_id=self.host_id,
            evidence_source=evidence_source,
            metadata=metadata or {},
        )
        if self.callback:
            try:
                self.callback(evt)
            except Exception as e:
                logger.error(f"Error in agent event callback: {e}")
        return evt

    def collect_process_events((self)) -> List[Event]:
        """Collect execve, fork, exit events."""
        events = []
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

                evt = self.create_event(
                    event_type=EventType.EXECVE.value,
                    pid=pid,
                    ppid=ppid,
                    uid=uid,
                    user=user,
                    comm=comm,
                    cmdline=cmdline,
                    target_path=cmdline.split()[0] if cmdline else f"/{comm}",
                    evidence_source="Linux Agent Process Monitor",
                )
                events.append(evt)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return events

    def collect_file_events(self, path: str, action: str = "create") -> Event:
        """Collect create, modify, delete file events."""
        evt_type = EventType.FILE_CREATE.value
        if action == "modify":
            evt_type = EventType.FILE_MODIFY.value
        elif action == "delete":
            evt_type = EventType.FILE_DELETE.value

        return self.create_event(
            event_type=evt_type,
            pid=os.getpid(),
            comm="inotify_sensor",
            target_path=path,
            evidence_source="Linux Agent File Sensor",
        )

    def collect_network_events(self) -> List[Event]:
        """Collect outbound connection & inbound connection events."""
        events = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        comm = p.name()
                    except Exception:
                        comm = "net_proc"

                    evt = self.create_event(
                        event_type=EventType.CONNECT.value,
                        pid=conn.pid,
                        comm=comm,
                        target_ip=conn.raddr.ip,
                        target_port=conn.raddr.port,
                        metadata={"source_ip": conn.laddr.ip if conn.laddr else "127.0.0.1"},
                        evidence_source="Linux Agent Socket Sensor",
                    )
                    events.append(evt)
        except Exception:
            pass
        return events

    def collect_auth_events(self, user: str, action: str = "login") -> Event:
        """Collect login, logout, sudo usage events."""
        evt_type = EventType.AUTH_LOGIN.value if action == "login" else EventType.AUTH_LOGOUT.value
        return self.create_event(
            event_type=evt_type,
            pid=os.getpid(),
            comm="pam_sshd",
            user=user,
            evidence_source="Linux Agent Auth Sensor",
        )

    def collect_privilege_events(self, comm: str, cmdline: str, uid: int) -> Event:
        """Collect UID changes, capability changes, sudo usage events."""
        return self.create_event(
            event_type=EventType.PRIVILEGE_SUDO.value,
            pid=os.getpid(),
            comm=comm,
            cmdline=cmdline,
            uid=uid,
            user="root" if uid == 0 else "user",
            evidence_source="Linux Agent Privilege Sensor",
        )

    def collect_service_events(self, service_name: str, action: str = "start") -> Event:
        """Collect service start, service stop events."""
        evt_type = EventType.SERVICE_START.value if action == "start" else EventType.SERVICE_STOP.value
        return self.create_event(
            event_type=evt_type,
            pid=1,
            comm="systemd",
            cmdline=f"systemctl {action} {service_name}",
            target_path=f"/etc/systemd/system/{service_name}.service",
            evidence_source="Linux Agent Service Sensor",
        )

    def collect_audit_events(self, action: str = "reconfig") -> Event:
        """Collect auditd changes."""
        return self.create_event(
            event_type=EventType.AUDITD_CHANGE.value,
            pid=os.getpid(),
            comm="auditctl",
            cmdline=f"auditctl {action}",
            evidence_source="Linux Audit Sensor",
        )
