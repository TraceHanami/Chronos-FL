"""
Centralized Configuration Isolation for CHRONOS-FL.

Uses Pydantic settings with environment variable override support.
"""

from __future__ import annotations
import os
from functools import lru_cache
from typing import Dict, Any
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHRONOS_", case_sensitive=True)

    # Host & Server Settings
    HOST_ID: str = Field(default="victim_host_01", description="Identifier of the monitored system host")
    API_HOST: str = Field(default="0.0.0.0", description="FastAPI server binding host")
    API_PORT: int = Field(default=8050, description="FastAPI server binding port")
    LOG_LEVEL: str = Field(default="INFO", description="Logging verbosity level")

    # Forensic Ledger Settings
    LEDGER_CHUNK_SIZE: int = Field(default=3, description="Number of events sealed per cryptographic ledger chunk")
    LEDGER_HASH_ALGORITHM: str = Field(default="SHA-256", description="Cryptographic hash algorithm for ledger chunks")

    # Evidence Survivability Source Weights
    EVIDENCE_SOURCE_WEIGHTS: Dict[str, float] = Field(
        default={
            "Audit Logs (/var/log/audit)": 2.5,
            "Systemd Journal / Syslog": 1.5,
            "eBPF Trace Sensor": 3.0,
            "Network Packet / Flow Logs": 3.0,
            "Shell Command History": 1.0,
        },
        description="Weighting factors for calculating Evidence Survivability Score (ESS)",
    )

    # TCS Penalty Thresholds
    TCS_MISSING_EVIDENCE_WEIGHT: float = 0.35
    TCS_LOG_DELETION_PENALTY: float = 10.0
    TCS_HISTORY_CLEARING_PENALTY: float = 5.0
    TCS_TIME_MANIPULATION_PENALTY: float = 7.5
    TCS_BROKEN_LEDGER_PENALTY: float = 40.0


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
