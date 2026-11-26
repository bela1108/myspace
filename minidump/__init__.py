name = "minidump"


_LAZY_EVIDENCE_EXPORTS = {
    "EvidenceQuery",
    "OfflineEvidenceQuery",
    "EvidenceRecord",
    "ReconciliationResult",
    "reconcile_briefing",
    "verify_statement",
    "extract_evidence",
    "open_evidence_async",
    "attribute_evidence",
}


def __getattr__(name):
    if name in _LAZY_EVIDENCE_EXPORTS:
        from minidump import evidence

        return getattr(evidence, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
