Approval reconciliation
========================

Use ``signedjson.approvals.reconcile_release`` for offline manifest checks.

The reconciler compares every material against one signed approval claim at a
time. Path, content digest and manifest version must all match inside that same
claim; fields from different vouchers are never combined.

Each decision includes the approval identifier and index that authorized it.
Every input approval is retained in ``report.approvals``, including approvals
whose scope is empty. A cross-scope approval exposes the claims it does not
cover in ``approval.missing_coverage``; another valid approval can still
authorize the same material independently.

When senior and exception scopes intersect, pass ``overlap_rule`` as a callable
or as ``"senior_wins"`` / ``"exception_wins"`` to apply the caller's policy.
