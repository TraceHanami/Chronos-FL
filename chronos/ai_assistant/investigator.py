"""
Research Module: AI Investigator (RAG Assistant).

RAG-based AI assistant that synthesizes evidence, explains trust scores, constructs attack paths,
and answers investigation queries strictly grounded in collected telemetry.
"""

from __future__ import annotations
import re
from typing import Dict, Any, List, Optional
from chronos.shared.models import Event, TimelineItem, AntiForensicAlert, ESSResult, TCSResult, EvidenceGap
from chronos.shared.logging import get_logger

logger = get_logger("chronos.ai_assistant")


class AIInvestigator:
    """RAG-based AI Forensic Investigator Assistant."""

    def __init__(self):
        pass

    def query(
        self,
        user_query: str,
        events: List[Event],
        timeline: List[TimelineItem],
        alerts: List[AntiForensicAlert],
        gaps: List[EvidenceGap],
        ess_result: ESSResult,
        tcs_result: TCSResult,
        graph_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Answer investigator questions with strict evidence grounding and citation."""
        q_lower = user_query.lower()

        answer = ""
        citations: Dict[str, List[str]] = {
            "evidence_ids": [],
            "graph_nodes": [],
            "timeline_items": [],
            "alert_ids": [],
        }

        # Collect key entities for grounding
        suspicious_timeline = [t for t in timeline if t.suspicious]
        critical_alerts = [a for a in alerts if a.severity in ["HIGH", "CRITICAL"]]

        if "what happened" in q_lower or "summary" in q_lower or "attack path" in q_lower:
            answer, citations = self._explain_what_happened(events, timeline, alerts, graph_dict)
        elif "why was ess reduced" in q_lower or "ess" in q_lower or "survivability" in q_lower:
            answer, citations = self._explain_ess(ess_result, alerts)
        elif "why was tcs reduced" in q_lower or "tcs" in q_lower or "confidence" in q_lower:
            answer, citations = self._explain_tcs(tcs_result, ess_result, alerts, gaps)
        elif "evidence supports" in q_lower or "evidence" in q_lower:
            answer, citations = self._explain_supporting_evidence(events, timeline, alerts)
        else:
            answer, citations = self._general_forensic_response(user_query, events, timeline, alerts, ess_result, tcs_result, graph_dict)

        return {
            "query": user_query,
            "answer": answer,
            "citations": citations,
            "confidence_assessment": {
                "tcs_score": tcs_result.tcs_score,
                "confidence_level": tcs_result.confidence_level,
                "ess_score": ess_result.ess_score,
            },
        }

    def _explain_what_happened(
        self,
        events: List[Event],
        timeline: List[TimelineItem],
        alerts: List[AntiForensicAlert],
        graph_dict: Dict[str, Any]
    ) -> tuple[str, Dict[str, List[str]]]:
        citations = {"evidence_ids": [], "graph_nodes": [], "timeline_items": [], "alert_ids": []}

        lines = ["### Reconstructed Attack Summary & Execution Path:\n"]

        if not timeline:
            lines.append("No telemetry events have been recorded yet.")
            return "\n".join(lines), citations

        for item in timeline:
            citations["timeline_items"].append(item.item_id)
            if item.evidence_id:
                citations["evidence_ids"].append(item.evidence_id)
            flag = "[SUSPICIOUS] " if item.suspicious else ""
            lines.append(f"- **Stage ({item.stage})**: {flag}{item.summary} (Timeline Item ID: `{item.item_id}`)")

        lines.append("\n### Causal Lineage Graph Nodes:")
        for node in graph_dict.get("nodes", []):
            node_id = node.get("id", "")
            citations["graph_nodes"].append(node_id)
            lines.append(f"- Node `{node_id}` ({node.get('type')}: {node.get('label')})")

        if alerts:
            lines.append("\n### Anti-Forensics & Visibility Destruction:")
            for a in alerts:
                citations["alert_ids"].append(a.alert_id)
                lines.append(f"- Alert ID `{a.alert_id}` [{a.category}]: {a.description}")

        return "\n".join(lines), citations

    def _explain_ess(self, ess: ESSResult, alerts: List[AntiForensicAlert]) -> tuple[str, Dict[str, List[str]]]:
        citations = {"evidence_ids": [], "graph_nodes": [], "timeline_items": [], "alert_ids": []}
        lines = [f"### Evidence Survivability Score (ESS) Analysis: {ess.ess_score:.1f}%\n"]
        lines.append(f"**Summary**: {ess.summary}\n")
        lines.append("#### Evidence Source Health Breakdown:")

        for src in ess.sources:
            status_symbol = "✓ INTACT" if src.status == "Present" else "✗ DESTROYED / LOST"
            lines.append(f"- **{src.source_name}** (Weight: {src.weight}): {status_symbol} - {src.details}")

        if alerts:
            lines.append("\n#### Contributing Anti-Forensic Events:")
            for a in alerts:
                citations["alert_ids"].append(a.alert_id)
                lines.append(f"- Alert ID `{a.alert_id}` ({a.category}): {a.description}")

        return "\n".join(lines), citations

    def _explain_tcs(
        self,
        tcs: TCSResult,
        ess: ESSResult,
        alerts: List[AntiForensicAlert],
        gaps: List[EvidenceGap]
    ) -> tuple[str, Dict[str, List[str]]]:
        citations = {"evidence_ids": [], "graph_nodes": [], "timeline_items": [], "alert_ids": []}
        lines = [f"### Timeline Confidence Score (TCS) Analysis: {tcs.tcs_score:.1f}% ({tcs.confidence_level})\n"]
        lines.append(f"**Summary**: {tcs.summary}\n")
        lines.append("#### Applied Deductions & Penalties:")

        for p in tcs.penalties:
            lines.append(f"- **{p.get('factor')}**: -{p.get('penalty')}% penalty. Reason: {p.get('details')}")

        if gaps:
            lines.append("\n#### Telemetry Gaps Impact:")
            for g in gaps:
                lines.append(f"- Gap from `{g.start_time}` to `{g.end_time}` ({g.duration_seconds}s). Hypotheses: {'; '.join(g.hypotheses)}")

        for a in alerts:
            citations["alert_ids"].append(a.alert_id)

        return "\n".join(lines), citations

    def _explain_supporting_evidence(
        self,
        events: List[Event],
        timeline: List[TimelineItem],
        alerts: List[AntiForensicAlert]
    ) -> tuple[str, Dict[str, List[str]]]:
        citations = {"evidence_ids": [], "graph_nodes": [], "timeline_items": [], "alert_ids": []}
        lines = ["### Supporting Evidence Inventory:\n"]

        for evt in events[:10]:
            citations["evidence_ids"].append(evt.event_id)
            lines.append(f"- Event ID `{evt.event_id}` | PID {evt.pid} ({evt.comm}): `{evt.cmdline or evt.target_path}` [SHA256: {evt.evidence_hash[:12]}...]")

        return "\n".join(lines), citations

    def _general_forensic_response(
        self,
        query: str,
        events: List[Event],
        timeline: List[TimelineItem],
        alerts: List[AntiForensicAlert],
        ess: ESSResult,
        tcs: TCSResult,
        graph_dict: Dict[str, Any]
    ) -> tuple[str, Dict[str, List[str]]]:
        citations = {"evidence_ids": [], "graph_nodes": [], "timeline_items": [], "alert_ids": []}

        for evt in events[:5]:
            citations["evidence_ids"].append(evt.event_id)
        for t in timeline[:5]:
            citations["timeline_items"].append(t.item_id)
        for a in alerts[:5]:
            citations["alert_ids"].append(a.alert_id)

        answer = (
            f"Forensic Assessment Query: '{query}'\n"
            f"- Total Telemetry Events Recorded: {len(events)}\n"
            f"- Evidence Survivability (ESS): {ess.ess_score:.1f}%\n"
            f"- Timeline Confidence (TCS): {tcs.tcs_score:.1f}% ({tcs.confidence_level})\n"
            f"- Anti-Forensic Alerts Detected: {len(alerts)}\n"
            f"- Causality Nodes: {len(graph_dict.get('nodes', []))}"
        )
        return answer, citations
