"""
System Infrastructure Module: Heartbeat Monitoring & Collector Interruption Tracking.

Tracks agent heartbeat pulses every 30 seconds.
Generates interruption events when heartbeats are missed or restored.
"""

from __future__ import annotations
import time
from typing import Callable, List, Optional, Dict, Any
from chronos.shared.models import Event, EventType
from chronos.shared.logging import get_logger

logger = get_logger("chronos.system.heartbeat")


class HeartbeatMonitor:
    """Monitors periodic heartbeat signals from endpoint agents."""

    def __init__(
        self,
        event_callback: Callable[[Event], None],
        expected_interval_seconds: float = 30.0,
        missed_threshold_multiplier: float = 2.0,
    ):
        self.event_callback = event_callback
        self.interval = expected_interval_seconds
        self.threshold = expected_interval_seconds * missed_threshold_multiplier
        self.last_heartbeat_time: float = time.time()
        self.heartbeat_active: bool = True
        self.missed_count: int = 0
        self.heartbeat_history: List[Dict[str, Any]] = []

    def receive_heartbeat(self, agent_id: str = "agent_host_01") -> Event:
        """Record heartbeat received signal."""
        now = time.time()
        was_disconnected = not self.heartbeat_active
        time_diff = now - self.last_heartbeat_time

        self.last_heartbeat_time = now
        self.heartbeat_active = True

        status = "Heartbeat Received"
        evt_type = EventType.HEARTBEAT.value

        if was_disconnected:
            status = "Heartbeat Restored"
            evt_type = EventType.HEARTBEAT_INTERRUPTION.value
            logger.info(f"Agent [{agent_id}] Heartbeat Restored after gap of {time_diff:.1f}s")

        evt = Event(
            event_type=evt_type,
            pid=0,
            comm="chronos-agent",
            cmdline=f"heartbeat status={status}",
            timestamp=now,
            evidence_source="Heartbeat Monitor",
            metadata={
                "agent_id": agent_id,
                "status": status,
                "time_since_last": round(time_diff, 2),
                "missed_count": self.missed_count,
            },
        )

        self.heartbeat_history.append({"timestamp": now, "status": status, "agent_id": agent_id})
        self.event_callback(evt)
        return evt

    def check_liveness(self, agent_id: str = "agent_host_01") -> Optional[Event]:
        """Check whether heartbeat deadline was missed."""
        now = time.time()
        elapsed = now - self.last_heartbeat_time

        if elapsed > self.threshold and self.heartbeat_active:
            self.heartbeat_active = False
            self.missed_count += 1
            logger.warning(f"Agent [{agent_id}] Heartbeat Missed! Silence duration: {elapsed:.1f}s")

            evt = Event(
                event_type=EventType.HEARTBEAT_INTERRUPTION.value,
                pid=0,
                comm="chronos-agent",
                cmdline=f"heartbeat status=Heartbeat Missed elapsed={elapsed:.1f}s",
                timestamp=now,
                evidence_source="Heartbeat Monitor",
                metadata={
                    "agent_id": agent_id,
                    "status": "Heartbeat Missed",
                    "silence_duration": round(elapsed, 2),
                    "missed_count": self.missed_count,
                },
            )
            self.heartbeat_history.append({"timestamp": now, "status": "Heartbeat Missed", "agent_id": agent_id})
            self.event_callback(evt)
            return evt

        return None
