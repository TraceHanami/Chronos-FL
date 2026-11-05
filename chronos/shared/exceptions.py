"""
Domain Exceptions for CHRONOS-FL.
"""

class ChronosException(Exception):
    """Base exception for all CHRONOS-FL domain errors."""
    pass


class LedgerIntegrityError(ChronosException):
    """Raised when cryptographic ledger hash chain verification fails."""
    pass


class TamperDetectionError(ChronosException):
    """Raised when active tamper detection algorithm triggers."""
    pass


class SensorIngestError(ChronosException):
    """Raised when incoming telemetry payload validation or processing fails."""
    pass
