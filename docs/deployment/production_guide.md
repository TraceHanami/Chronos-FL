# CHRONOS-FL Production Deployment Guide

## Prerequisites
- Linux Kernel version `>= 5.8` (for CO-RE eBPF ring buffer support)
- Python `>= 3.10`
- `libbpf` and `clang` (optional, for custom BPF probe compilation)

## Setup & Running
```bash
# 1. Clone repository
git clone https://github.com/your-org/Chronos-FL.git
cd Chronos-FL

# 2. Install package in editable mode
pip install -e .

# 3. Launch DFIR Workstation Dashboard
chronos-fl serve --host 0.0.0.0 --port 8050

# 4. Launch Live OS Sensor Daemon (Systemd Service / Background)
python3 scripts/live_host_collector.py
```

## Systemd Service Unit Example
```ini
[Unit]
Description=CHRONOS-FL Digital Flight Recorder Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/Chronos-FL
ExecStart=/usr/bin/python3 scripts/live_host_collector.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
