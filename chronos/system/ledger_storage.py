from __future__ import annotations
import hashlib
import json
import time
from typing import List, Dict, Any, Tuple, Optional
from chronos.shared.models import Event, LedgerChunk
from chronos.shared.logging import get_logger
from chronos.config.settings import get_settings

logger = get_logger("chronos.system.ledger")
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class EventLedgerEntry:
    def __init__(
        self,
        event_id: str,
        timestamp: float,
        previous_hash: str,
        current_hash: str,
        signature: str,
        event_data: Dict[str, Any]
    ):
        self.event_id = event_id
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.current_hash = current_hash
        self.signature = signature
        self.event_data = event_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "signature": self.signature,
            "event_data": self.event_data,
        }


class EvidenceLedgerStorage:
    def __init__(self, chunk_size: Optional[int] = None, hmac_secret: str = "chronos_ledger_secret_key"):
        settings = get_settings()
        self.chunk_size = chunk_size or settings.LEDGER_CHUNK_SIZE
        self.secret = hmac_secret
        self.chunks: List[LedgerChunk] = []
        self.event_chain: List[EventLedgerEntry] = []
        self.pending_events: List[Dict[str, Any]] = []
        self.last_event_hash: str = GENESIS_HASH

    def compute_signature(self, data_str: str) -> str:
        return hashlib.sha256(f"{self.secret}:{data_str}".encode("utf-8")).hexdigest()

    def compute_event_hash(self, event_id: str, timestamp: float, prev_hash: str, event_data: Dict[str, Any]) -> str:
        serialized = json.dumps(event_data, sort_keys=True)
        raw = f"{event_id}:{timestamp:.4f}:{prev_hash}:{serialized}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def compute_chunk_hash(self, chunk_id: int, timestamp: float, events: List[Dict[str, Any]], prev_hash: str) -> str:
        serialized_events = json.dumps(events, sort_keys=True)
        data_to_hash = f"{chunk_id}:{timestamp:.4f}:{prev_hash}:{serialized_events}".encode("utf-8")
        return hashlib.sha256(data_to_hash).hexdigest()

    def add_event(self, event: Event) -> Optional[LedgerChunk]:
        evt_dict = event.to_dict()
        prev_h = self.last_event_hash
        curr_h = self.compute_event_hash(event.event_id, event.timestamp, prev_h, evt_dict)
        sig = self.compute_signature(curr_h)

        entry = EventLedgerEntry(
            event_id=event.event_id,
            timestamp=event.timestamp,
            previous_hash=prev_h,
            current_hash=curr_h,
            signature=sig,
            event_data=evt_dict,
        )
        self.event_chain.append(entry)
        self.last_event_hash = curr_h

        self.pending_events.append(evt_dict)
        if len(self.pending_events) >= self.chunk_size:
            return self.commit_chunk()
        return None

    def commit_chunk(self) -> Optional[LedgerChunk]:
        if not self.pending_events:
            return None

        chunk_id = len(self.chunks) + 1
        prev_hash = self.chunks[-1].chunk_hash if self.chunks else GENESIS_HASH
        timestamp = time.time()
        events_to_commit = list(self.pending_events)
        self.pending_events.clear()

        chunk_hash = self.compute_chunk_hash(chunk_id, timestamp, events_to_commit, prev_hash)
        signature = self.compute_signature(chunk_hash)

        metadata = {
            "chunk_id": chunk_id,
            "events_count": len(events_to_commit),
            "created_at": timestamp,
            "integrity_sealed": True,
            "algorithm": "SHA-256 Hash Chain + HMAC-SHA256 Signature",
        }

        chunk = LedgerChunk(
            chunk_id=chunk_id,
            timestamp=timestamp,
            events=events_to_commit,
            prev_hash=prev_hash,
            chunk_hash=chunk_hash,
            signature=signature,
            metadata=metadata,
        )
        self.chunks.append(chunk)
        logger.info(f"Sealed Ledger Chunk #{chunk_id} (Hash: {chunk_hash[:12]}..., Sig: {signature[:8]}...)")
        return chunk

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        issues = []

        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(self.event_chain):
            if entry.previous_hash != expected_prev:
                issues.append(
                    f"BROKEN EVENT CHAIN at Event #{idx} ({entry.event_id}): Expected prev_hash '{expected_prev[:12]}...', got '{entry.previous_hash[:12]}...'"
                )

            comp_hash = self.compute_event_hash(entry.event_id, entry.timestamp, entry.previous_hash, entry.event_data)
            if entry.current_hash != comp_hash:
                issues.append(
                    f"TAMPERED EVENT CONTENT at Event #{idx} ({entry.event_id}): Stored hash '{entry.current_hash[:12]}...' != Recomputed '{comp_hash[:12]}...'"
                )

            comp_sig = self.compute_signature(entry.current_hash)
            if entry.signature != comp_sig:
                issues.append(f"INVALID SIGNATURE at Event #{idx} ({entry.event_id})")

            expected_prev = entry.current_hash

        expected_chunk_prev = GENESIS_HASH
        for chunk in self.chunks:
            if chunk.prev_hash != expected_chunk_prev:
                issues.append(
                    f"BROKEN CHUNK CHAIN at Chunk {chunk.chunk_id}: Expected prev_hash '{expected_chunk_prev[:12]}...', got '{chunk.prev_hash[:12]}...'"
                )

            computed_hash = self.compute_chunk_hash(chunk.chunk_id, chunk.timestamp, chunk.events, chunk.prev_hash)
            if chunk.chunk_hash != computed_hash:
                issues.append(
                    f"TAMPERED CHUNK CONTENT at Chunk {chunk.chunk_id}: Stored hash '{chunk.chunk_hash[:12]}...' != Recomputed '{computed_hash[:12]}...'"
                )

            expected_chunk_prev = chunk.chunk_hash

        is_valid = len(issues) == 0
        return is_valid, issues

    def tamper_with_chunk(self, chunk_index: int, modified_event_index: int, key: str, new_value: Any) -> None:
        if 0 <= chunk_index < len(self.chunks):
            chunk = self.chunks[chunk_index]
            if 0 <= modified_event_index < len(chunk.events):
                chunk.events[modified_event_index][key] = new_value

        if 0 <= modified_event_index < len(self.event_chain):
            self.event_chain[modified_event_index].event_data[key] = new_value

    def get_ledger_entries(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.event_chain]

    def clear(self) -> None:
        self.chunks.clear()
        self.event_chain.clear()
        self.pending_events.clear()
        self.last_event_hash = GENESIS_HASH
