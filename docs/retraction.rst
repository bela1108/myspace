Retraction impact review
========================

When an advisory is withdrawn, a maintenance console may already have closed
assets based on the original CPE match.  Re-review needs to separate three
different states instead of treating "did not match" as "not affected":

``confirmed_closed``
    A verified component replacement shows that the previously matching
    component is gone, or the complete asset manifest contains no matching
    CPE.

``still_affected``
    At least one observed CPE still matches the advisory condition.  A
    positive match is sufficient even when the rest of the manifest is
    incomplete.

``insufficient_evidence``
    The available inventory is incomplete and there is no positive match or
    verified replacement.  A non-match from a partial manifest is not proof
    of absence.

The implementation lives in :mod:`cpe.impact` and builds on
:class:`cpe.cpeset2_3.CPESet2_3` name matching and
:class:`cpe.cpelang2_3.CPELanguage2_3` conditional expressions.

Example
-------

.. code-block:: python

    from cpe.impact import (
        Advisory, Asset, ComponentObservation, FamilyCoverage,
        InventoryScope, ReplacementEvidence, assess_retraction,
    )

    advisory = Advisory.from_cpe_names(
        "CVE-2026-0001",
        ["cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*"],
        applies_from="2026-09-01T00:00:00Z",
        applies_until="2026-10-01T00:00:00Z",
        retracted_at="2026-10-03T00:00:00Z",
    )

    scope = InventoryScope(
        approved_families=("oracle_weblogic",),
        coverage={
            "oracle_weblogic": FamilyCoverage(
                "oracle_weblogic", True, "complete CMDB export"),
        },
    )

    asset = Asset(
        "wls-02",
        "oracle_weblogic",
        observations=(
            ComponentObservation(
                "cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*",
                "2026-10-20T00:00:00Z",
            ),
        ),
        manifest_complete=True,
    )

    report = assess_retraction(
        [asset], advisory, scope, as_of="2026-11-01T00:00:00Z")
    assert report.assessments[0].status.value == "affected"

Family exclusion
----------------

A family is excluded only when the caller supplies ``FamilyCoverage`` with
``complete=True`` and supporting evidence.  ``InventoryScope`` never derives
coverage from an empty match result: an asset family with incomplete coverage
remains in the review and produces ``insufficient_evidence`` if its assets
cannot be assessed.

NVD JSON expressions
--------------------

:class:`cpe.impact.Advisory` also accepts NVD-style JSON configuration nodes.
The evaluator understands ``operator``, ``children``, ``cpe_match``,
``vulnerable`` and the four ``versionStart/EndIncluding/Excluding`` fields.
The evaluator is three-valued internally, so an unknown CPE or version keeps
the result unknown instead of collapsing to a false match.

The runnable three-result inventory is in
``examples/retraction_review.py``; running it writes
``reports/retraction-impact.json`` and ``reports/retraction-impact.md``.
