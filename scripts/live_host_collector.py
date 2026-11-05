#!/usr/bin/env python3
"""
CHRONOS-FL Live Host Telemetry Collector Daemon.
"""

import os
import socket
import sys
import time
import urllib.request
import json
import psutil

BACKEND_API_URL = os.environ.get("CHRONOS_API_URL", "http://127.0.0.1:8050/api/events/ingest")
HOST_ID = os.environ.get("CHRONOS_HOST_ID", socket.gethostname())


def post_event(event_dict: dict):
    try:
        data = json.dumps(event_dict).encode("utf-8")
        req = urllib.request.Request(
            BACKEND_API_URL,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            pass
    except Exception:
        pass


def stream_initial_process_tree():
    print(f"[*] Discovering live host processes on {HOST_ID}...")
    count = 0
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'uids']):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            ppid = pinfo['ppid'] or 1
            comm = pinfo['name'] or f"proc_{pid}"
            cmdline = " ".join(pinfo['cmdline'] or [])
            uids = pinfo.get('uids')
            uid = uids.real if uids else 1000
            user = "root" if uid == 0 else "user"

            evt_type = "execve"
            if comm in ["sudo", "su", "pkexec", "doas"]:
                evt_type = "sudo"

            event = {
                "event_type": evt_type,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "user": user,
                "comm": comm,
                "cmdline": cmdline[:150] if cmdline else f"/{comm}",
                "target_path": cmdline.split()[0] if cmdline else f"/{comm}",
                "evidence_source": "Live OS Sensor (/proc)",
            }
            post_event(event)
            count += 1
            if count >= 35:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print(f"[+] Initialized live OS baseline with {count} active host processes.")


def stream_network_connections():
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr and conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    comm = p.name()
                except Exception:
                    comm = "network_proc"

                event = {
                    "event_type": "connect",
                    "pid": conn.pid,
                    "ppid": 1,
                    "comm": comm,
                    "target_ip": conn.raddr.ip,
                    "target_port": conn.raddr.port,
                    "evidence_source": "Live Network Sensor",
                }
                post_event(event)
    except Exception:
        pass


def monitor_live():
    print(f"[+] Real-time Linux OS telemetry collector active. Monitoring host: {HOST_ID}")
    seen_pids = set(psutil.pids())

    while True:
        try:
            current_pids = set(psutil.pids())
            new_pids = current_pids - seen_pids

            for pid in new_pids:
                try:
                    p = psutil.Process(pid)
                    ppid = p.ppid()
                    comm = p.name()
                    cmdline = " ".join(p.cmdline())
                    uids = p.uids()
                    user = "root" if uids.real == 0 else "user"

                    evt_type = "execve"
                    if comm in ["sudo", "su", "pkexec"]:
                        evt_type = "sudo"

                    event = {
                        "event_type": evt_type,
                        "pid": pid,
                        "ppid": ppid,
                        "uid": uids.real,
                        "user": user,
                        "comm": comm,
                        "cmdline": cmdline[:150] if cmdline else f"/{comm}",
                        "target_path": cmdline.split()[0] if cmdline else f"/{comm}",
                        "evidence_source": "Live Host Sensor",
                    }
                    post_event(event)
                    print(f"[LIVE OS EVENT] Process Executed: {comm} (PID: {pid}, PPID: {ppid}, User: {user})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            seen_pids = current_pids
            stream_network_connections()
            time.sleep(1.5)
        except KeyboardInterrupt:
            print("\n[+] Live collector stopped.")
            break
        except Exception:
            time.sleep(2)


if __name__ == "__main__":
    stream_initial_process_tree()
    stream_network_connections()
    monitor_live()
