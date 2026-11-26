"""Compatibility name for callers looking for an evidence query module."""

from minidump.evidence import *  # noqa: F401,F403
from minidump.evidence import (
    EvidenceQuery,
    OfflineEvidenceQuery,
    ReconciliationResult,
    reconcile_briefing,
    verify_identity,
)


async def open_evidence_query(*paths, **kwargs):
    return await EvidenceQuery.open_async(*paths, **kwargs)
