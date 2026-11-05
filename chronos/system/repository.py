"""
System Infrastructure Module: Evidence Repository Storage & Retrieval.

Implements persistent database repository for Events, Snapshots, Alerts, Evidence Gaps, and Metadata
using SQLAlchemy for PostgreSQL / SQLite.
"""

from __future__ import annotations
import json
import time
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, Column, String, Float, Integer, Text, Boolean, select
from sqlalchemy.orm import declarative_base, sessionmaker

from chronos.shared.models import Event, Snapshot, AntiForensicAlert, EvidenceGap, NormalizedEvent
from chronos.config.settings import get_settings

Base = declarative_base()


class DBEventRecord(Base):
    __tablename__ = "evidence_events"

    event_id = Column(String(64), primary_key=True)
    timestamp = Column(Float, index=True)
    host_id = Column(String(64), index=True)
    user = Column(String(64), index=True)
    pid = Column(Integer, index=True)
    ppid = Column(Integer)
    event_type = Column(String(64), index=True)
    comm = Column(String(128))
    cmdline = Column(Text)
    target_path = Column(Text, nullable=True)
    target_ip = Column(String(64), nullable=True)
    target_port = Column(Integer, nullable=True)
    evidence_source = Column(String(64))
    evidence_hash = Column(String(128))
    normalized_json = Column(Text)
    metadata_json = Column(Text)


class DBSnapshotRecord(Base):
    __tablename__ = "evidence_snapshots"

    snapshot_id = Column(String(64), primary_key=True)
    timestamp = Column(Float, index=True)
    trigger_reason = Column(Text)
    trigger_alert_id = Column(String(64), nullable=True)
    data_json = Column(Text)
    remote_object_url = Column(Text, nullable=True)


class DBAlertRecord(Base):
    __tablename__ = "evidence_alerts"

    alert_id = Column(String(64), primary_key=True)
    timestamp = Column(Float, index=True)
    category = Column(String(64), index=True)
    severity = Column(String(32))
    description = Column(Text)
    pid = Column(Integer)
    comm = Column(String(128))
    cmdline = Column(Text)
    evidence_source = Column(String(64))
    metadata_json = Column(Text)


class DBGapRecord(Base):
    __tablename__ = "evidence_gaps"

    gap_id = Column(String(64), primary_key=True)
    start_time = Column(Float, index=True)
    end_time = Column(Float)
    duration_seconds = Column(Float)
    potential_causes_json = Column(Text)
    hypotheses_json = Column(Text)


class EvidenceRepository:
    """SQLAlchemy Repository for Module 3 Evidence Management."""

    def __init__(self, db_url: Optional[str] = None):
        settings = get_settings()
        url = db_url or getattr(settings, "DATABASE_URL", "sqlite:///:memory:")
        if url.startswith("postgres"):
            # Driver fallback if psycopg2 is missing
            try:
                import psycopg2  # noqa
            except ImportError:
                url = "sqlite:///:memory:"

        self.engine = create_engine(url, echo=False, connect_args={"check_same_thread": False} if "sqlite" in url else {})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def store_event(self, event: Event) -> None:
        session = self.Session()
        try:
            norm = event.to_normalized()
            rec = DBEventRecord(
                event_id=event.event_id,
                timestamp=event.timestamp,
                host_id=event.host_id,
                user=event.user,
                pid=event.pid,
                ppid=event.ppid,
                event_type=event.event_type,
                comm=event.comm,
                cmdline=event.cmdline,
                target_path=event.target_path,
                target_ip=event.target_ip,
                target_port=event.target_port,
                evidence_source=event.evidence_source,
                evidence_hash=event.evidence_hash or "",
                normalized_json=json.dumps(norm.model_dump()),
                metadata_json=json.dumps(event.metadata),
            )
            session.merge(rec)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def store_alert(self, alert: AntiForensicAlert) -> None:
        session = self.Session()
        try:
            rec = DBAlertRecord(
                alert_id=alert.alert_id,
                timestamp=alert.timestamp,
                category=alert.category,
                severity=alert.severity,
                description=alert.description,
                pid=alert.pid,
                comm=alert.comm,
                cmdline=alert.cmdline,
                evidence_source=alert.evidence_source,
                metadata_json=json.dumps(alert.metadata),
            )
            session.merge(rec)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def store_snapshot(self, snapshot: Snapshot) -> None:
        session = self.Session()
        try:
            rec = DBSnapshotRecord(
                snapshot_id=snapshot.snapshot_id,
                timestamp=snapshot.timestamp,
                trigger_reason=snapshot.trigger_reason,
                trigger_alert_id=snapshot.trigger_alert_id,
                data_json=json.dumps(snapshot.to_dict()),
                remote_object_url=snapshot.remote_object_url,
            )
            session.merge(rec)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def store_gap(self, gap: EvidenceGap) -> None:
        session = self.Session()
        try:
            rec = DBGapRecord(
                gap_id=gap.gap_id,
                start_time=gap.start_time,
                end_time=gap.end_time,
                duration_seconds=gap.duration_seconds,
                potential_causes_json=json.dumps(gap.potential_causes),
                hypotheses_json=json.dumps(gap.hypotheses),
            )
            session.merge(rec)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def search_events(
        self,
        event_type: Optional[str] = None,
        user: Optional[str] = None,
        pid: Optional[int] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        query: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        session = self.Session()
        try:
            stmt = select(DBEventRecord)
            if event_type:
                stmt = stmt.where(DBEventRecord.event_type == event_type)
            if user:
                stmt = stmt.where(DBEventRecord.user == user)
            if pid:
                stmt = stmt.where(DBEventRecord.pid == pid)
            if start_time:
                stmt = stmt.where(DBEventRecord.timestamp >= start_time)
            if end_time:
                stmt = stmt.where(DBEventRecord.timestamp <= end_time)
            if query:
                stmt = stmt.where(
                    DBEventRecord.cmdline.contains(query) | DBEventRecord.comm.contains(query) | DBEventRecord.target_path.contains(query)
                )

            stmt = stmt.order_by(DBEventRecord.timestamp.desc()).limit(limit)
            results = session.execute(stmt).scalars().all()
            return [json.loads(r.normalized_json) for r in results]
        finally:
            session.close()

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        session = self.Session()
        try:
            results = session.execute(select(DBAlertRecord).order_by(DBAlertRecord.timestamp.asc())).scalars().all()
            return [
                {
                    "alert_id": r.alert_id,
                    "timestamp": r.timestamp,
                    "category": r.category,
                    "severity": r.severity,
                    "description": r.description,
                    "pid": r.pid,
                    "comm": r.comm,
                    "cmdline": r.cmdline,
                    "evidence_source": r.evidence_source,
                    "metadata": json.loads(r.metadata_json or "{}"),
                }
                for r in results
            ]
        finally:
            session.close()

    def export_repository_archive(self) -> Dict[str, Any]:
        session = self.Session()
        try:
            events = [json.loads(r.normalized_json) for r in session.execute(select(DBEventRecord)).scalars().all()]
            alerts = [r.alert_id for r in session.execute(select(DBAlertRecord)).scalars().all()]
            snapshots = [r.snapshot_id for r in session.execute(select(DBSnapshotRecord)).scalars().all()]
            return {
                "exported_at": time.time(),
                "total_events": len(events),
                "total_alerts": len(alerts),
                "total_snapshots": len(snapshots),
                "events": events,
            }
        finally:
            session.close()
