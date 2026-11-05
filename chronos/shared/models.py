"""
Pydantic Domain Schemas & DTOs for CHRONOS-FL.
"""

from __future__ import annotations
import hashlib
import json
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EventType(str, Enum):
    EXECVE = "execve"
    FORK = "fork"
    EXIT = "exit"
    CLONE = "clone"
    FILE_CREATE = "create"
    FILE_MODIFY = "modify"
    FILE_DELETE = "delete"
    FILE_RENAME = "rename"
    CONNECT = "outbound_connection"
    INBOUND_CONNECT = "inbound_connection"
    BIND = "bind"
    ACCEPT = "accept"
    AUTH_LOGIN = "login"
    AUTH_LOGOUT = "logout"
    PRIVILEGE_SUDO = "sudo_usage"
    PRIVILEGE_SETUID = "uid_change"
    PRIVILEGE_CAPABILITY = "capability_change"
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    AUDITD_CHANGE = "auditd_change"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_INTERRUPTION = "heartbeat_interruption"
    ANTI_FORENSIC = "anti_forensic"


class AntiForensicCategory(str, Enum):
    LOG_DELETION = "log_deletion"
    HISTORY_CLEARING = "history_clearing"
    AUDIT_SHUTDOWN = "audit_shutdown"
    SECURE_DELETION = "secure_deletion"
    TIMESTAMP_MANIPULATION = "timestamp_manipulation"
    TIME_CHANGE = "time_change"
    AGENT_TERMINATION = "agent_termination"
    LOGGING_RECONFIGURATION = "logging_reconfiguration"


class EvidenceStatus(str, Enum):
    PRESENT = "Present"
    TAMPERED = "Tampered"
    LOST = "Lost"


class NormalizedEvent(BaseModel):
    """Standardized Module 2 Event Schema."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    host: str = "victim_host_01"
    user: str = "root"
    pid: str = "0"
    ppid: str = "1"
    event_type: str = "execve"
    process: str = "unknown"
    command: str = ""
    path: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    port: str = ""
    collector: str = "CHRONOS Agent"
    evidence_hash: str = ""

    def calculate_hash(self) -> str:
        payload = f"{self.event_id}:{self.timestamp}:{self.host}:{self.user}:{self.pid}:{self.ppid}:{self.event_type}:{self.process}:{self.command}:{self.path}:{self.source_ip}:{self.destination_ip}:{self.port}:{self.collector}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def model_post_init(self, __context: Any) -> None:
        if not self.evidence_hash:
            self.evidence_hash = self.calculate_hash()


class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    pid: int
    ppid: int = 1
    uid: int = 1000
    user: str = "root"
    comm: str = "unknown"
    cmdline: str = ""
    target_path: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    timestamp: float = Field(default_factory=time.time)
    host_id: str = "victim_host_01"
    evidence_source: str = "eBPF Sensor"
    evidence_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.evidence_hash:
            payload = f"{self.event_id}:{self.timestamp}:{self.host_id}:{self.user}:{self.pid}:{self.ppid}:{self.event_type}:{self.comm}:{self.cmdline}:{self.target_path or ''}:{self.target_ip or ''}:{self.target_port or ''}:{self.evidence_source}"
            self.evidence_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_normalized(self) -> NormalizedEvent:
        ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp))
        return NormalizedEvent(
            event_id=self.event_id,
            timestamp=ts_str,
            host=self.host_id,
            user=self.user,
            pid=str(self.pid),
            ppid=str(self.ppid),
            event_type=str(self.event_type),
            process=self.comm,
            command=self.cmdline,
            path=self.target_path or "",
            source_ip=self.metadata.get("source_ip", "127.0.0.1"),
            destination_ip=self.target_ip or "",
            port=str(self.target_port) if self.target_port else "",
            collector=self.evidence_source,
            evidence_hash=self.evidence_hash or "",
        )

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["normalized"] = self.to_normalized().model_dump()
        return d


class AntiForensicAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str = AntiForensicCategory.LOG_DELETION.value
    description: str = ""
    pid: int = 0
    comm: str = ""
    cmdline: str = ""
    severity: str = "HIGH"
    timestamp: float = Field(default_factory=time.time)
    evidence_source: str = "eBPF Sensor"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class Snapshot(BaseModel):
    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    trigger_reason: str = ""
    trigger_alert_id: Optional[str] = None
    processes: List[Dict[str, Any]] = Field(default_factory=list)
    network_connections: List[Dict[str, Any]] = Field(default_factory=list)
    loaded_modules: List[str] = Field(default_factory=list)
    open_files: List[Dict[str, Any]] = Field(default_factory=list)
    container_state: Dict[str, Any] = Field(default_factory=dict)
    remote_object_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["processes_count"] = len(self.processes)
        d["loaded_modules_count"] = len(self.loaded_modules)
        return d


class EvidenceGap(BaseModel):
    gap_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    start_time: float
    end_time: float
    duration_seconds: float
    potential_causes: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    evidence_source: str = "Telemetry Monitored System"

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class TimelineItem(BaseModel):
    item_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    stage: str = "Activity"
    category: str = "Observed Events"  # Observed, Correlated, Inferred, Evidence Gap
    summary: str = ""
    detail: str = ""
    event_type: str = ""
    pid: int = 0
    comm: str = ""
    suspicious: bool = False
    evidence_id: Optional[str] = None
    evidence_source: str = "eBPF Trace"

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class LedgerChunk(BaseModel):
    chunk_id: int
    timestamp: float
    events: List[Dict[str, Any]]
    prev_hash: str
    chunk_hash: str
    signature: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["events_count"] = len(self.events)
        return d


class EvidenceSourceStatus(BaseModel):
    source_name: str
    status: str
    weight: float = 1.0
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ESSResult(BaseModel):
    ess_score: float
    surviving_sources: int
    total_sources: int
    sources: List[EvidenceSourceStatus]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["ess_score"] = round(self.ess_score, 1)
        return d


class TCSResult(BaseModel):
    tcs_score: float
    confidence_level: str
    penalties: List[Dict[str, Any]]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["tcs_score"] = round(self.tcs_score, 1)
        return d
