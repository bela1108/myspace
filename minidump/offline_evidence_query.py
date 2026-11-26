"""Named entry point for offline evidence queries."""

from minidump.evidence import *  # noqa: F401,F403
from minidump.evidence import EvidenceQuery, reconcile_briefing, verify_statement


async def open_query(*paths, **kwargs):
    return await EvidenceQuery.open_async(*paths, **kwargs)
