Offline Handover Auditing
=========================

Detection notifications and handling authority are not the same thing. A night shift can
notify two people while only one role is allowed to act. The handover audit layer in
``sigma.audit.handover`` evaluates that gap offline, using pySigma rule UUIDs and the
processing items that were actually applied to each rule.

The audit is deliberately data-driven. Shift duties, approved substitutions, branch
ownership and branch closures are supplied explicitly; they are never inferred from a
rule title or from a notification recipient list.

Identity and scope
------------------

* A rule is keyed by its Sigma UUID. Two rules that share a title remain two separate
  chains with separate permissions.
* A duty is scoped by rule UUID and/or branch id. A ``notify`` duty never implies
  ``handle`` authority.
* A substitution is usable only when it carries ``approved_by`` and ``approval_ref``
  metadata, matches the duty role and rule scope, and is valid at the audit time.
* A branch is open only when its pySigma processing item was applied and the branch is
  enabled. A disabled or non-matching branch is reported as closed.

Statuses
--------

Each notification chain receives exactly one status:

=================  ===========================================================
Status             Meaning
=================  ===========================================================
``actionable``     A notify path and a handling path are covered, and every
                   release-required branch is open.
``notifiable``     The chain can notify, but it is not release-eligible. This is
                   a reference-only chain and must not be used for on-call
                   release.
``no_substitute``  A handling duty exists but has no available assignee and no
                   active approved substitute. The chain requires escalation.
=================  ===========================================================

Closed branches are reported separately. Each closed branch names the historical role
that must countersign (``countersign_role``), either explicitly or from the branch's
stewardship history.

Programmatic use
----------------

.. code-block:: python

   from sigma.audit.handover import HandoverAuditConfig, HandoverAuditor

   config = HandoverAuditConfig.from_yaml_file("scenario.yml")
   report = HandoverAuditor(config).audit(collection.rules, pipeline)

   release_ready = report.filter(release_basis=True)
   reference_only = report.reference_only_chains()
   blocked = report.filter(status="no_substitute")

``HandoverAuditReport.to_dict()``, ``to_json()`` and ``to_markdown()`` produce
machine-readable and human-readable evidence. The report keeps the same-title grouping
visible without merging any chains.

Runnable demo
-------------

The demo under ``examples/handover_audit`` contains four rules, two of which share a
title. It shows an active approved substitute, an expired substitute, one temporarily
disabled branch, and exactly one reference-only chain:

.. code-block:: console

   python examples/handover_audit/run_demo.py --check
   python examples/handover_audit/run_demo.py --reference-only
   python examples/handover_audit/run_demo.py --status no_substitute

The script writes ``report.json`` and ``report.md`` next to the demo inputs.
