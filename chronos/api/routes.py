"""
REST API Router & Controllers for CHRONOS-FL.
"""

from __future__ import annotations
import os
import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from chronos.api.dependencies import (
    collector,
    repository,
    timeline_engine,
    causality_engine,
    detection_engine,
    gap_detector,
    snapshot_recorder,
    ledger_storage,
    trust_engine,
    heartbeat_monitor,
    ai_investigator,
    case_state,
)
from chronos.shared.models import AntiForensicCategory

router = APIRouter()


class EventIngestModel(BaseModel):
    event_type: str = "execve"
    pid: int = 1000
    ppid: int = 1
    uid: int = 1000
    user: str = "root"
    comm: str = "unknown"
    cmdline: str = ""
    target_path: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    evidence_source: str = "Ingest API"


class AIQueryModel(BaseModel):
    query: str


class NoteUpdateModel(BaseModel):
    notes: str


@router.get("/api/status")
def get_status():
    is_valid, ledger_issues = ledger_storage.verify_integrity()
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    return {
        "status": "active",
        "system": "CHRONOS-FL Cyber Forensic Flight Recorder",
        "total_events_collected": len(collector.events),
        "timeline_items": len(timeline_engine.timeline_items),
        "anti_forensic_alerts": len(detection_engine.alerts),
        "snapshots_recorded": len(snapshot_recorder.snapshots),
        "evidence_gaps_detected": len(gaps),
        "ledger_chunks": len(ledger_storage.chunks),
        "ledger_integrity": "INTACT" if is_valid else "TAMPERED",
    }


@router.get("/api/events")
def search_events(
    event_type: Optional[str] = None,
    user: Optional[str] = None,
    pid: Optional[int] = None,
    query: Optional[str] = None,
    limit: int = 100,
):
    """Retrieve normalized evidence events."""
    return repository.search_events(event_type=event_type, user=user, pid=pid, query=query, limit=limit)


@router.post("/api/events/ingest")
def ingest_event(payload: EventIngestModel):
    evt = collector.record_event(
        event_type=payload.event_type,
        pid=payload.pid,
        ppid=payload.ppid,
        uid=payload.uid,
        user=payload.user,
        comm=payload.comm,
        cmdline=payload.cmdline,
        target_path=payload.target_path,
        target_ip=payload.target_ip,
        target_port=payload.target_port,
        evidence_source=payload.evidence_source,
    )
    return {"status": "success", "event_id": evt.event_id, "evidence_hash": evt.evidence_hash}


@router.get("/api/timeline")
def get_timeline():
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    timeline_engine.build_from_events(collector.events, gaps=gaps)
    return [item.to_dict() for item in timeline_engine.timeline_items]


@router.get("/api/evidence")
def get_evidence():
    """Module 3 Evidence Repository API."""
    return repository.export_repository_archive()


@router.get("/api/graph")
def get_graph():
    return causality_engine.to_dict()


@router.post("/api/graph/export-neo4j")
def export_neo4j():
    success = causality_engine.export_to_neo4j()
    return {"status": "exported" if success else "neo4j_not_available"}


@router.get("/api/alerts")
def get_alerts():
    enriched = []
    for alert in detection_engine.alerts:
        data = alert.to_dict()
        category_str = str(alert.category)

        if AntiForensicCategory.LOG_DELETION.value in category_str:
            data["affected_artifacts"] = ["/var/log/syslog", "/var/log/audit/audit.log", "/var/log/auth.log"]
            data["impact_score"] = "CRITICAL"
            data["trust_penalty"] = "-20% TCS Penalty"
        elif AntiForensicCategory.HISTORY_CLEARING.value in category_str:
            data["affected_artifacts"] = ["~/.bash_history", "~/.zsh_history", "HISTFILE memory buffer"]
            data["impact_score"] = "HIGH"
            data["trust_penalty"] = "-10% TCS Penalty"
        elif AntiForensicCategory.AUDIT_SHUTDOWN.value in category_str:
            data["affected_artifacts"] = ["auditd daemon process", "kauditd kernel ring buffer", "auditctl rules"]
            data["impact_score"] = "CRITICAL"
            data["trust_penalty"] = "-25% TCS Penalty"
        elif AntiForensicCategory.SECURE_DELETION.value in category_str:
            data["affected_artifacts"] = ["Payload binary", "Filesystem block sectors", "/tmp/stager.sh"]
            data["impact_score"] = "HIGH"
            data["trust_penalty"] = "-15% TCS Penalty"
        elif AntiForensicCategory.TIMESTAMP_MANIPULATION.value in category_str:
            data["affected_artifacts"] = ["Inode mtime/atime attributes", "/tmp/agent.bin stat struct"]
            data["impact_score"] = "MEDIUM"
            data["trust_penalty"] = "-10% TCS Penalty"
        elif AntiForensicCategory.TIME_CHANGE.value in category_str:
            data["affected_artifacts"] = ["System wall clock", "NTP synchronization state", "RTC hardware clock"]
            data["impact_score"] = "HIGH"
            data["trust_penalty"] = "-15% TCS Penalty"
        elif AntiForensicCategory.AGENT_TERMINATION.value in category_str:
            data["affected_artifacts"] = ["CHRONOS Agent Process", "eBPF Ring Buffer Probe"]
            data["impact_score"] = "CRITICAL"
            data["trust_penalty"] = "-25% TCS Penalty"
        else:
            data["affected_artifacts"] = ["System Telemetry"]
            data["impact_score"] = "MEDIUM"
            data["trust_penalty"] = "-5% TCS Penalty"

        enriched.append(data)
    return enriched


@router.get("/api/gaps")
def get_evidence_gaps():
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    return [g.to_dict() for g in gaps]


@router.get("/api/snapshots")
def get_snapshots():
    return [snap.to_dict() for snap in snapshot_recorder.snapshots]


@router.get("/api/ledger")
def get_ledger():
    is_valid, issues = ledger_storage.verify_integrity()
    return {
        "is_valid": is_valid,
        "issues": issues,
        "chunks": [c.to_dict() for c in ledger_storage.chunks],
        "entries": ledger_storage.get_ledger_entries(),
    }


@router.post("/api/ledger/tamper-test")
def tamper_ledger_test():
    if not ledger_storage.chunks:
        ledger_storage.commit_chunk()
    if ledger_storage.chunks:
        ledger_storage.tamper_with_chunk(chunk_index=0, modified_event_index=0, key="cmdline", new_value="/bin/innocent_cmd")
        is_valid, issues = ledger_storage.verify_integrity()
        return {"status": "tampered", "is_valid": is_valid, "issues": issues}
    return {"status": "error", "message": "No ledger chunks to tamper"}


@router.post("/api/ledger/reset")
def reset_ledger():
    collector.clear()
    timeline_engine.timeline_items.clear()
    causality_engine.g.clear()
    detection_engine.clear()
    gap_detector.clear()
    snapshot_recorder.clear()
    ledger_storage.clear()
    return {"status": "reset_successful"}


@router.get("/api/ess")
def get_ess():
    ess_res = trust_engine.compute_ess(detection_engine.alerts)
    return ess_res.to_dict()


@router.get("/api/tcs")
def get_tcs():
    ess_res = trust_engine.compute_ess(detection_engine.alerts)
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    is_valid, issues = ledger_storage.verify_integrity()
    tcs_res = trust_engine.compute_tcs(ess_res, detection_engine.alerts, gaps=gaps, ledger_valid=is_valid, ledger_issues=issues)
    return tcs_res.to_dict()


@router.get("/api/trust/scores")
def get_trust_scores():
    ess_res = trust_engine.compute_ess(detection_engine.alerts)
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    is_valid, issues = ledger_storage.verify_integrity()
    tcs_res = trust_engine.compute_tcs(ess_res, detection_engine.alerts, gaps=gaps, ledger_valid=is_valid, ledger_issues=issues)
    return {
        "ess": ess_res.to_dict(),
        "tcs": tcs_res.to_dict(),
    }


@router.get("/api/incidents")
def get_incidents():
    ess_res = trust_engine.compute_ess(detection_engine.alerts)
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    is_valid, issues = ledger_storage.verify_integrity()
    tcs_res = trust_engine.compute_tcs(ess_res, detection_engine.alerts, gaps=gaps, ledger_valid=is_valid, ledger_issues=issues)

    return {
        "case_state": case_state,
        "summary": {
            "total_events": len(collector.events),
            "anti_forensic_alerts_count": len(detection_engine.alerts),
            "evidence_gaps_count": len(gaps),
            "snapshots_count": len(snapshot_recorder.snapshots),
            "ledger_integrity": "INTACT" if is_valid else "TAMPERED",
            "ess_score": ess_res.ess_score,
            "tcs_score": tcs_res.tcs_score,
            "confidence_level": tcs_res.confidence_level,
        },
    }


@router.post("/api/heartbeat")
def record_heartbeat(agent_id: str = "victim_host_01"):
    evt = heartbeat_monitor.receive_heartbeat(agent_id=agent_id)
    return {"status": "heartbeat_received", "event_id": evt.event_id}


@router.post("/api/ai-investigator/query")
def query_ai_investigator(payload: AIQueryModel):
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    ess_res = trust_engine.compute_ess(detection_engine.alerts)
    is_valid, issues = ledger_storage.verify_integrity()
    tcs_res = trust_engine.compute_tcs(ess_res, detection_engine.alerts, gaps=gaps, ledger_valid=is_valid, ledger_issues=issues)

    res = ai_investigator.query(
        user_query=payload.query,
        events=collector.events,
        timeline=timeline_engine.timeline_items,
        alerts=detection_engine.alerts,
        gaps=gaps,
        ess_result=ess_res,
        tcs_result=tcs_res,
        graph_dict=causality_engine.to_dict(),
    )
    return res


@router.get("/api/cases")
def get_cases():
    return case_state


@router.post("/api/cases/notes")
def update_notes(payload: NoteUpdateModel):
    case_state["analyst_notes"] = payload.notes
    return {"status": "success", "notes": case_state["analyst_notes"]}


@router.get("/api/export/report")
def export_report():
    ess_res = trust_engine.compute_ess(detection_engine.alerts)
    gaps = gap_detector.analyze_timeline_gaps(collector.events, detection_engine.alerts)
    is_valid, issues = ledger_storage.verify_integrity()
    tcs_res = trust_engine.compute_tcs(ess_res, detection_engine.alerts, gaps=gaps, ledger_valid=is_valid, ledger_issues=issues)

    return {
        "report_id": f"REP-{int(time.time())}",
        "generated_at": time.time(),
        "case": case_state,
        "trust_assessment": {
            "ess": ess_res.to_dict(),
            "tcs": tcs_res.to_dict(),
            "ledger_integrity": "INTACT" if is_valid else "TAMPERED",
        },
        "timeline_events_count": len(timeline_engine.timeline_items),
        "anti_forensic_alerts_count": len(detection_engine.alerts),
        "evidence_gaps_count": len(gaps),
        "snapshots_captured_count": len(snapshot_recorder.snapshots),
        "timeline_summary": [t.to_dict() for t in timeline_engine.timeline_items],
        "anti_forensics_alerts": [a.to_dict() for a in detection_engine.alerts],
        "evidence_gaps": [g.to_dict() for g in gaps],
    }


@router.get("/", response_class=HTMLResponse)
def get_dashboard_ui():
    template_path = os.path.join(os.path.dirname(__file__), "..", "ui", "index.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>CHRONOS-FL Workstation UI Error: Template index.html not found</h1>", status_code=500)
