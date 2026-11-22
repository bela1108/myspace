Offline Shift Handover Audit
============================

A detection notification can reach more people than the set of people allowed to
act on it. This guide describes the offline handover audit in
``sigma.audit.handover``, which uses pySigma rule identity and a processing
pipeline trace to answer three separate questions for every rule:

* Is the shift allowed to be notified about this rule?
* Is the shift allowed to handle this rule?
* Is a required notify or handle role absent without an approved substitute?

The audit is deterministic and offline. It does not call a backend or a
notification system.

Rule identity
-------------

Permissions are keyed by :class:`sigma.audit.handover.RuleIdentity`. The key is
built from the Sigma UUID and a digest of the canonical rule content. A rule
without a UUID gets a content digest key.

Rule ``name`` and ``title`` are display attributes only. This matters because a
Sigma collection can contain two different rules with the same name. For example,
a correlation reference label can be reused. Granting a permission to one rule
by name would silently grant it to the other. The audit therefore:

* rejects selectors that use ``name`` or ``title``,
* keeps same-name rules as separate audit entries, and
* rejects a selector that uses a Sigma UUID which appears with different rule
  contents.

States
------

Each rule receives one :class:`sigma.audit.handover.HandoverState`:

``actionable``
   At least one on-duty role, or an effective approved substitute, may handle the
   rule, and no disabled branch suspends handling.

``notifiable``
   The shift may be notified for reference, but no effective handler is
   available. This includes a handling duty suspended by a disabled branch.

``no_substitute``
   A required notify or handle role is off duty and no approved substitute covers
   the rule, or no shift duty covers the rule at all.

The booleans ``can_notify``, ``can_handle``, and ``no_substitute`` are also
available on each entry.

Explicit duties and approved substitutes
----------------------------------------

A :class:`sigma.audit.handover.Shift` contains explicit duties. A duty names a
role, a selector, and whether that role may notify, handle, or serve as a release
basis. A selector can use:

* ``rule_ids`` or ``rule_keys`` for identity-level grants,
* ``tags``, ``levels``, or ``statuses`` for operational scopes, or
* logsource fields for environment scopes.

Broad selectors are reported as warnings.

A :class:`sigma.audit.handover.SubstituteApproval` is effective only when all of
the following are true:

* it names a non-empty approver,
* its validity window covers the entire shift,
* the substitute is on duty,
* its selector matches the rule, and
* it carries every authority required by the covered duty.

Example::

    shift = Shift.from_dict(
        {
            "shift_id": "2026-11-23-night",
            "starts_at": "2026-11-23T00:00:00+08:00",
            "ends_at": "2026-11-23T08:00:00+08:00",
            "on_duty": ["responder", "observer"],
            "duties": [
                {
                    "id": "responder-handle",
                    "role": "responder",
                    "selector": {"rule_ids": ["11111111-1111-4111-8111-111111111111"]},
                    "notify": True,
                    "handle": True,
                },
                {
                    "id": "observer-notify",
                    "role": "observer",
                    "selector": {"rule_ids": ["11111111-1111-4111-8111-111111111111"]},
                    "notify": True,
                    "handle": False,
                    "release_basis": False,
                },
            ],
        }
    )

Processing chain and disabled branches
--------------------------------------

The audit applies a ``ProcessingPipeline`` to a private copy of each rule. It
records only processing items that actually changed the rule: a field mapping
counts only when the pipeline recorded a source-to-target mapping, and a
detection-item transformation counts only when a detection item recorded it.

A :class:`sigma.audit.handover.ProcessingBranch` groups processing item ids.
When a rule traverses a branch with ``state: disabled``:

* the report names the branch,
* the report names the ``historical_role`` that must countersign, and
* handling is suspended, so the chain becomes reference-only.

``historical_role`` is mandatory for a disabled branch. Omitting it is a
configuration error.

Notification chains
-------------------

Each audited rule produces a :class:`sigma.audit.handover.NotificationChain`.
The chain lists every role that is notified, the source duty and approval ids,
and a deterministic chain id. A chain is a release basis only when:

* it has at least one notification recipient,
* handling is effective,
* at least one handler is authorized for release, and
* no required handler has a substitute gap.

A chain without a release basis is marked ``reference_only``. The filter helper
returns only those chains::

    reference_chains = report.filter_chains(reference_only=True)

The Markdown renderer has a matching filter::

    report.to_markdown(reference_only_only=True)

Demo
----

The runnable demo lives in ``examples/handover_audit``. It contains two same-name
rules, one approved substitute, one disabled branch, and one handler role with no
substitute. Run it from the repository root::

    python examples/handover_audit/run_demo.py
    python examples/handover_audit/run_demo.py --reference-only
    python examples/handover_audit/run_demo.py --format json

The ``--reference-only`` output labels the selected chain as reference material
that must not be used as a shift release basis.
