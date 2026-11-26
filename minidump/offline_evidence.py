"""Offline evidence query entry point."""

from minidump.evidence import *  # noqa: F401,F403
from minidump.evidence import EvidenceQuery, OfflineEvidenceQuery, reconcile_briefing


OfflineEvidenceQuery = EvidenceQuery
