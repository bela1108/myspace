Security Exception Exchange
===========================

The exception exchange layer translates Bandit findings into the rule
numbering used by an external security scanner.  It consumes a normal
Bandit JSON report together with an exception mapping document and derives
two views from the same evaluation pass:

* the **local** view stays keyed on Bandit rule IDs (``Bxxx``) and keeps
  historical baselines readable; and
* the **exchange** view is keyed on the external scanner rule IDs.

Mapping document
-----------------

Each mapping connects one Bandit source rule to one or more external target
rules (one-to-many), carries a validity period and states the context
conditions that every target finding has to satisfy::

    {
        "document": "bandit-exception-mappings",
        "version": 1,
        "mappings": [
            {
                "id": "EXC-001",
                "source_rule": "B602",
                "target_rules": [
                    {
                        "rule_id": "EXT-SHELL-20",
                        "conditions": {
                            "filename": {"op": "glob", "value": "pkg/*.py"},
                            "severity": "HIGH"
                        }
                    },
                ],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "rationale": "accepted launch wrapper",
                "owner": "security-team"
            }
        ]
    }

Context conditions
------------------

A bare scalar is an equality check.  A dictionary selects an explicit
operator so conditions stay readable in JSON:

``eq``, ``ne``, ``in``, ``gt``, ``gte``, ``lt``, ``lte``, ``glob``,
``regex`` and ``contains``.  A mapping may also define shared ``context``
conditions that every target rule inherits in addition to its own.  Each
target is evaluated independently, so one target can approve a finding that
a sibling target rejects.

Decision states
---------------

Every mapping target produces one of the following decisions:

``APPROVED``
    A finding satisfied all context conditions inside the validity period.
``EXPIRED``
    The mapping is outside its ``valid_from`` / ``valid_until`` window.
``NO_MATCH``
    Findings exist for the source rule but none satisfy the conditions.
``MISSING_EVIDENCE``
    No finding exists for the source rule; the check was not evidenced in
    the report and no approval is granted.
``CONFLICT``
    Two active mappings claim the same external rule through different
    Bandit source rules.  Both opinions are retained for human review.

When mappings disagree the layer keeps the disagreement instead of picking
a winner: every conflicting decision is flagged and listed under the
exchange view ``conflicts`` array.

Legacy baselines
-----------------

Older Bandit JSON baselines use the same ``results`` envelope and remain
readable.  Optional fields may be missing and are treated as empty values;
a ``legacy`` marker is exposed on the loaded report and propagated to both
exported views.

Command line
------------

The ``bandit-exchange`` script ships with Bandit::

    bandit -f json -o report.json -r myproject/
    bandit-exchange views report.json mappings.json -o views.json
    bandit-exchange local report.json mappings.json
    bandit-exchange exchange report.json mappings.json
    bandit-exchange validate mappings.json
    bandit-exchange drop report.json mappings.json EXC-001

``views`` exports both views from one scan output.  ``drop`` rebuilds the
views after an auditor deletes one or more comma-separated mapping ids and
only the approvals produced by the removed mappings disappear.  Use ``--at``
with an ISO-8601 UTC timestamp to evaluate validity at a fixed point in time.
