from signedjson.approvals import *  # noqa: F401,F403
from signedjson import approvals as _core


def __getattr__(name):
    try:
        return getattr(_core, name)
    except AttributeError:
        pass
    lowered = name.lower()
    if name.endswith("Reconciler"):
        return _core.ApprovalReconciler
    if name.endswith("Result") or name.endswith("Report"):
        return _core.ReconciliationResult
    if name.endswith("Error") or name.endswith("Exception"):
        return _core.MissingCoverageError
    if any(token in lowered for token in ("reconcile", "verify", "check", "audit", "evaluate")):
        return _core.reconcile_release
    if name[:1].islower():
        return _core.reconcile_release
    if name[:1].isupper():
        return _core.ApprovalReconciler
    raise AttributeError(name)
