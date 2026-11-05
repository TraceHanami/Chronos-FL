from __future__ import annotations
from typing import List, Dict, Optional
from chronos.shared.models import (
    EvidenceSourceStatus,
    EvidenceStatus,
    ESSResult,
    TCSResult,
    AntiForensicAlert,
    AntiForensicCategory,
    EvidenceGap,
)
from chronos.config.settings import get_settings


class TrustAnalysisEngine:
    def __init__(self):
        self.settings = get_settings()

    def compute_ess(
        self,
        anti_forensic_alerts: List[AntiForensicAlert],
        custom_statuses: Optional[Dict[str, str]] = None
    ) -> ESSResult:
        sources_status: List[EvidenceSourceStatus] = []

        log_deleted = any(AntiForensicCategory.LOG_DELETION.value in str(a.category) for a in anti_forensic_alerts)
        history_cleared = any(AntiForensicCategory.HISTORY_CLEARING.value in str(a.category) for a in anti_forensic_alerts)
        audit_stopped = any(AntiForensicCategory.AUDIT_SHUTDOWN.value in str(a.category) for a in anti_forensic_alerts)
        agent_terminated = any(AntiForensicCategory.AGENT_TERMINATION.value in str(a.category) for a in anti_forensic_alerts)

        for src_name, weight in self.settings.EVIDENCE_SOURCE_WEIGHTS.items():
            status = EvidenceStatus.PRESENT.value
            details = "Source intact, available, independent, and verified."

            if custom_statuses and src_name in custom_statuses:
                status = custom_statuses[src_name]
                details = f"Verified status: {status}"
            else:
                if "Audit Logs" in src_name:
                    if log_deleted or audit_stopped:
                        status = EvidenceStatus.LOST.value
                        details = "Audit daemon disabled or log files wiped by adversary."
                elif "Systemd Journal" in src_name:
                    if log_deleted:
                        status = EvidenceStatus.LOST.value
                        details = "Journald / syslog destroyed via rm -rf /var/log."
                elif "Shell Command History" in src_name:
                    if history_cleared:
                        status = EvidenceStatus.LOST.value
                        details = "Shell history wiped via history -c or HISTFILE truncation."
                elif "eBPF Flight Recorder" in src_name:
                    if agent_terminated:
                        status = EvidenceStatus.LOST.value
                        details = "Flight recorder agent process killed or probe unattached."

            sources_status.append(EvidenceSourceStatus(
                source_name=src_name,
                status=status,
                weight=weight,
                details=details,
            ))

        total_weight = sum(s.weight for s in sources_status)
        surviving_weight = sum(s.weight for s in sources_status if s.status == EvidenceStatus.PRESENT.value)

        ess_score = (surviving_weight / total_weight) * 100.0 if total_weight > 0 else 100.0
        surviving_count = sum(1 for s in sources_status if s.status == EvidenceStatus.PRESENT.value)

        summary = f"{surviving_count}/{len(sources_status)} expected evidence sources survived ({ess_score:.1f}% survivability)."

        return ESSResult(
            ess_score=ess_score,
            surviving_sources=surviving_count,
            total_sources=len(sources_status),
            sources=sources_status,
            summary=summary,
        )

    def compute_tcs(
        self,
        ess_result: ESSResult,
        anti_forensic_alerts: List[AntiForensicAlert],
        gaps: Optional[List[EvidenceGap]] = None,
        ledger_valid: bool = True,
        ledger_issues: Optional[List[str]] = None
    ) -> TCSResult:
        score = 100.0
        penalties: List[Dict[str, str]] = []

        missing_pct = 100.0 - ess_result.ess_score
        if missing_pct > 0:
            penalty = missing_pct * self.settings.TCS_MISSING_EVIDENCE_WEIGHT
            score -= penalty
            penalties.append({
                "factor": "Missing / Destroyed Evidence Sources",
                "penalty": round(penalty, 1),
                "details": f"ESS score is {ess_result.ess_score:.1f}% ({ess_result.surviving_sources}/{ess_result.total_sources} sources survived)."
            })

        log_del_count = sum(1 for a in anti_forensic_alerts if AntiForensicCategory.LOG_DELETION.value in str(a.category))
        if log_del_count > 0:
            penalty = min(20.0, log_del_count * self.settings.TCS_LOG_DELETION_PENALTY)
            score -= penalty
            penalties.append({
                "factor": "Log Deletion Anti-Forensics Impact",
                "penalty": round(penalty, 1),
                "details": f"Detected {log_del_count} log deletion attempt(s)."
            })

        hist_del_count = sum(1 for a in anti_forensic_alerts if AntiForensicCategory.HISTORY_CLEARING.value in str(a.category))
        if hist_del_count > 0:
            penalty = min(10.0, hist_del_count * self.settings.TCS_HISTORY_CLEARING_PENALTY)
            score -= penalty
            penalties.append({
                "factor": "History Wiping Anti-Forensics Impact",
                "penalty": round(penalty, 1),
                "details": f"Detected {hist_del_count} command history wiping attempt(s)."
            })

        time_manip_count = sum(1 for a in anti_forensic_alerts if any(c in str(a.category) for c in [
            AntiForensicCategory.TIMESTAMP_MANIPULATION.value, AntiForensicCategory.TIME_CHANGE.value
        ]))
        if time_manip_count > 0:
            penalty = min(15.0, time_manip_count * self.settings.TCS_TIME_MANIPULATION_PENALTY)
            score -= penalty
            penalties.append({
                "factor": "Timestamp Manipulation / Clock Tampering",
                "penalty": round(penalty, 1),
                "details": f"Detected {time_manip_count} clock/timestamp alteration attempt(s)."
            })

        agent_term_count = sum(1 for a in anti_forensic_alerts if AntiForensicCategory.AGENT_TERMINATION.value in str(a.category))
        if agent_term_count > 0:
            penalty = min(25.0, agent_term_count * 25.0)
            score -= penalty
            penalties.append({
                "factor": "Agent Termination / Flight Recorder Shutdown",
                "penalty": round(penalty, 1),
                "details": f"Detected {agent_term_count} agent termination event(s)."
            })

        if gaps:
            total_gap_sec = sum(g.duration_seconds for g in gaps)
            gap_penalty = min(20.0, len(gaps) * 5.0 + (total_gap_sec / 60.0) * 2.0)
            score -= gap_penalty
            penalties.append({
                "factor": "Telemetry Silence & Evidence Gaps",
                "penalty": round(gap_penalty, 1),
                "details": f"Detected {len(gaps)} telemetry gap(s) totaling {total_gap_sec:.1f}s silence."
            })

        if not ledger_valid:
            penalty = self.settings.TCS_BROKEN_LEDGER_PENALTY
            score -= penalty
            issues_str = "; ".join(ledger_issues) if ledger_issues else "Hash chain verification failed."
            penalties.append({
                "factor": "Broken Cryptographic Ledger Integrity",
                "penalty": round(penalty, 1),
                "details": f"Ledger tamper check failed: {issues_str}"
            })

        final_score = max(0.0, min(100.0, score))

        if final_score >= 90.0:
            level = "HIGH"
            summary_msg = "The reconstructed timeline is highly trustworthy, verified, and complete."
        elif final_score >= 75.0:
            level = "MEDIUM"
            summary_msg = "The timeline is moderately trustworthy; minor evidence missing or anti-forensic activity detected."
        elif final_score >= 50.0:
            level = "LOW"
            summary_msg = "Low timeline confidence! Significant anti-forensic evidence destruction or telemetry gaps."
        else:
            level = "CRITICAL_TAMPERING"
            summary_msg = "Timeline confidence severely compromised! Major evidence destruction, telemetry loss, or ledger tampering."

        return TCSResult(
            tcs_score=final_score,
            confidence_level=level,
            penalties=penalties,
            summary=summary_msg,
        )
