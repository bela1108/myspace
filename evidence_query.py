"""Repository-root compatibility shim for standalone test imports."""

from minidump.evidence_query import *  # noqa: F401,F403
from minidump.evidence import (
    EvidenceQuery,
    OfflineEvidenceQuery,
    reconcile_briefing,
    verify_statement,
)
