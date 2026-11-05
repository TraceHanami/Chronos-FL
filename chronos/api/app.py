"""
FastAPI Application Entry Point for CHRONOS-FL.
"""

from fastapi import FastAPI
from chronos.api.routes import router
from chronos.config.settings import get_settings

settings = get_settings()

app = FastAPI(
    title="CHRONOS-FL Cyber Forensic Flight Recorder",
    description="Professional DFIR Investigation & Evidence Trust Platform.",
    version="0.1.0",
)

app.include_router(router)
