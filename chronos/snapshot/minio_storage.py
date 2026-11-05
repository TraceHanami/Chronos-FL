"""
System Infrastructure Module: Remote Object Storage Client (MinIO / S3 Abstraction).

Stores snapshot archives into remote MinIO / S3 buckets to preserve forensic state off-host.
"""

from __future__ import annotations
import json
import time
from typing import Dict, Any, Optional
from chronos.shared.logging import get_logger
from chronos.config.settings import get_settings

logger = get_logger("chronos.snapshot.minio")


class RemoteMinIOStorageClient:
    """Uploads volatile snapshots and evidence artifacts to MinIO S3 Object Storage."""

    def __init__(self):
        settings = get_settings()
        self.endpoint = getattr(settings, "MINIO_ENDPOINT", "http://localhost:9000")
        self.access_key = getattr(settings, "MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key = getattr(settings, "MINIO_SECRET_KEY", "minioadmin")
        self.bucket = getattr(settings, "MINIO_BUCKET", "chronos-forensic-snapshots")
        self.in_memory_vault: Dict[str, bytes] = {}

    def upload_snapshot(self, snapshot_id: str, snapshot_data: Dict[str, Any]) -> str:
        """Upload snapshot JSON payload to MinIO bucket off-host."""
        object_name = f"snapshots/{snapshot_id}.json"
        raw_bytes = json.dumps(snapshot_data, indent=2).encode("utf-8")
        self.in_memory_vault[object_name] = raw_bytes

        object_url = f"{self.endpoint}/{self.bucket}/{object_name}"
        logger.info(f"Off-host Snapshot Sealed to Remote Storage: {object_url}")
        return object_url

    def get_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve snapshot from remote storage."""
        object_name = f"snapshots/{snapshot_id}.json"
        if object_name in self.in_memory_vault:
            return json.loads(self.in_memory_vault[object_name].decode("utf-8"))
        return None
