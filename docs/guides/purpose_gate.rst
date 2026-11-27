Purpose Gate: Sample Provenance and Formal Coverage
====================================================

Detection teams often reuse the same event sample in more than one place: a training package
and the evidence bundle that accompanies a rule release. A sample used for training must never
be treated as formally approved coverage evidence. The :mod:`sigma.governance` package provides
a purpose gate that keeps sample provenance, rule match results, and dual-person confirmations
independent, and emits formal coverage reports containing only explicitly approved evidence.

Sources and Composite Identity
------------------------------

Every sample carries an explicit :class:`~sigma.governance.SampleSource` and its source-local
identifier. Identity is always the composite :class:`~sigma.governance.SampleKey` of
``(source, sample_id)``, so two records that share fields or even the same sample id are never
folded together when their provenance differs:

.. code-block:: python

    from sigma.governance import SampleKey, SampleSource

    training = SampleSource("training-package")
    release = SampleSource("rule-release-evidence")
    assert SampleKey(training, "event-42") != SampleKey(release, "event-42")

Independent Purpose Grants
--------------------------

A :class:`~sigma.governance.PurposeGate` stores grants per evidence kind
(:class:`~sigma.governance.EvidenceKind`: sample source, match result, dual-person
confirmation), per source, and per :class:`~sigma.governance.SamplePurpose` (``TRAINING`` or
``FORMAL``). Granting one kind never grants another, and a training grant never satisfies a
formal request:

.. code-block:: python

    from sigma.governance import EvidenceKind, PurposeGate, SamplePurpose

    gate = PurposeGate()
    gate.grant(EvidenceKind.SAMPLE_SOURCE, release, SamplePurpose.FORMAL)
    gate.grant(EvidenceKind.MATCH_RESULT, release, SamplePurpose.FORMAL)
    gate.grant(EvidenceKind.DUAL_CONFIRMATION, release, SamplePurpose.FORMAL)

    # Raises SigmaGovernanceError: no formal approval for the training source.
    gate.require_allowed(EvidenceKind.MATCH_RESULT, training, SamplePurpose.FORMAL)

Registering evidence (samples, match results, dual-person confirmations) checks the matching
grant first, so unapproved evidence can never enter the governed registry.

Offline Runs and the Formal Report
----------------------------------

:func:`~sigma.governance.run_offline_coverage` parses the same rule YAML twice into independent
collections and runs each with its own matcher, then verifies that both runs produced the same
match outcome per sample. The returned :class:`~sigma.governance.RuleCoverageReport` lists only
samples that:

* are registered with a formal purpose and a granted source,
* matched the rule in both offline runs,
* have all three evidence kinds approved for their source, and
* carry a :class:`~sigma.governance.DualPersonConfirmation` from two distinct reviewers.

Excluded samples appear in the report's ``rejected`` list with an explicit reason, never in the
formal ``entries`` listing.
