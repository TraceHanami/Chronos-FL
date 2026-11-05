#!/usr/bin/env python3
"""
CHRONOS-FL Live Host Collector Root Launcher.
"""

import sys
from scripts.live_host_collector import stream_initial_process_tree, stream_network_connections, monitor_live

if __name__ == "__main__":
    stream_initial_process_tree()
    stream_network_connections()
    monitor_live()
