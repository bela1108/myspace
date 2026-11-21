import importlib
import logging
from typing import Any

__version__ = "1.6.0"

# Configure a basic 'securesystemslib' top-level logger with a StreamHandler
# (print to console) and the WARNING log level (print messages of type
# warning, error or critical). This is similar to what 'logging.basicConfig'
# would do with the root logger. All 'securesystemslib.*' loggers default to
# this top-level logger and thus may be configured (e.g. formatted, silenced,
# etc.) with it. It can be accessed via logging.getLogger('securesystemslib').
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
logger.addHandler(logging.StreamHandler())


_POLICY_EXPORTS = frozenset(
    {
        "ArchiveAnchor",
        "EvaluationView",
        "PolicyCheck",
        "Decision",
        "PolicyDecision",
        "PolicyUse",
        "Receipt",
        "ReplayReport",
        "Revocation",
        "RevocationNotice",
        "RevocationCheck",
        "SignatureEvidence",
        "SignaturePolicy",
        "TimeClaim",
        "TimeInterval",
        "TimeWindow",
        "TrustedTime",
        "Use",
        "UseDecision",
        "UseDifference",
        "evaluate_signature_policy",
        "evaluate",
        "replay_receipts",
        "replay",
        "replay_views",
        "verify_and_evaluate",
    }
)


def __getattr__(name: str) -> Any:
    """Lazily expose the optional signature policy API at package level."""
    if name in _POLICY_EXPORTS:
        policy = importlib.import_module("securesystemslib.policy")
        return getattr(policy, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _POLICY_EXPORTS)
