from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from pip_audit._reconcile import (
    Audience,
    EvidenceBundle,
    Reason,
    Status,
    TemporalError,
    _dedupe_closures,
    compare_views,
    load_bundle,
    reconcile,
    render_json,
    views_document,
)
from pip_audit._reconcile_cli import main

EXAMPLE = Path(__file__).parent.parent / "examples" / "temporal-reconciliation"
BUNDLE = EXAMPLE / "bundle.json"
AS_OF = "2026-11-23"
EARLIER = "2026-11-15T10:00:00Z"
LATER = "2026-11-23T10:00:00Z"
RESTRICTED_CLOSURE_REASON = (
    "The vendor snapshot available on the closure date did not list demo-lib versions as affected."
)
RESTRICTED_SUPPLEMENT_REASON = (
    "Vendor supplement: demo-lib versions 1.0.0 through 1.1.x are affected."
)


def _bundle() -> EvidenceBundle:
    return load_bundle(BUNDLE)


def test_reconcile_reopens_only_staging() -> None:
    bundle = _bundle()
    earlier = reconcile(bundle, as_of=AS_OF, visible_at=EARLIER, audience=Audience.INTERNAL)
    later = reconcile(bundle, as_of=AS_OF, visible_at=LATER, audience=Audience.INTERNAL)

    assert earlier.reopen_environments == ()
    assert later.reopen_environments == ("staging",)
    assert earlier.environments["staging"].closures[0].reopen_required is False
    assert later.environments["staging"].closures[0].reopen_required is True
    assert later.environments["prod"].closures[0].reopen_required is False


def test_closure_keeps_its_decision_and_current_status() -> None:
    bundle = _bundle()
    later = reconcile(bundle, as_of=AS_OF, visible_at=LATER, audience=Audience.INTERNAL)
    review = later.environments["staging"].closures[0]

    assert review.closure_id == "INC-2026-1114-staging"
    assert review.decision_status is Status.NOT_AFFECTED
    assert review.current_status is Status.AFFECTED
    assert review.closed_at.isoformat() == "2026-11-14T12:00:00+00:00"
    assert review.as_of.isoformat() == "2026-11-14T23:59:59.999999+00:00"
    assert review.evidence == "advisory snapshot 2026-11-14"


def test_new_snapshot_is_not_visible_before_retrieval() -> None:
    bundle = _bundle()
    earlier = reconcile(bundle, as_of=AS_OF, visible_at=EARLIER, audience=Audience.INTERNAL)
    later = reconcile(bundle, as_of=AS_OF, visible_at=LATER, audience=Audience.INTERNAL)

    assert earlier.environments["staging"].findings == ()
    finding = later.environments["staging"].findings[0]
    assert finding.advisory_id == "EXAMPLE-2026-0001"
    assert finding.status is Status.AFFECTED
    assert finding.snapshot_version == "2026-11-23"
    assert finding.effective_at.isoformat() == "2026-11-20T00:00:00+00:00"
    assert finding.retrieved_at.isoformat() == "2026-11-23T09:00:00+00:00"


def test_effective_time_is_respected_independently_of_retrieval() -> None:
    bundle = _bundle()
    before_effective = reconcile(
        bundle,
        as_of="2026-11-19",
        visible_at=LATER,
        audience=Audience.INTERNAL,
    )

    assert before_effective.environments["staging"].findings == ()
    assert before_effective.reopen_environments == ()


def test_external_view_redacts_license_restricted_reasons() -> None:
    bundle = _bundle()
    later = reconcile(bundle, as_of=AS_OF, visible_at=LATER, audience=Audience.EXTERNAL)
    external = render_json(views_document([later]))
    assert RESTRICTED_CLOSURE_REASON not in external
    assert RESTRICTED_SUPPLEMENT_REASON not in external
    assert "redacted: license restriction" not in external
    assert later.redactions > 0
    assert later.environments["staging"].closures[0].decision_reason is None
    assert later.environments["staging"].closures[0].decision_reason_redacted is True

    internal = reconcile(bundle, as_of=AS_OF, visible_at=LATER, audience=Audience.INTERNAL)
    internal_text = render_json(views_document([internal]))
    assert RESTRICTED_CLOSURE_REASON in internal_text
    assert RESTRICTED_SUPPLEMENT_REASON in internal_text


def test_compare_views_requires_one_as_of_date() -> None:
    bundle = _bundle()
    earlier = reconcile(bundle, as_of=AS_OF, visible_at=EARLIER, audience=Audience.INTERNAL)
    other = reconcile(bundle, as_of="2026-11-22", visible_at=LATER, audience=Audience.INTERNAL)

    with pytest.raises(TemporalError):
        compare_views(earlier, other)


def test_compare_views_reports_reopen_and_same_date() -> None:
    bundle = _bundle()
    earlier = reconcile(bundle, as_of=AS_OF, visible_at=EARLIER, audience=Audience.INTERNAL)
    later = reconcile(bundle, as_of=AS_OF, visible_at=LATER, audience=Audience.INTERNAL)
    comparison = compare_views(earlier, later)

    assert comparison.earlier.as_of == comparison.later.as_of
    assert len(comparison.reopen) == 1
    assert comparison.reopen[0].environment == "staging"
    assert comparison.reopen[0].previous_closure == "INC-2026-1114-staging"
    assert comparison.changes[0].before is Status.NOT_AFFECTED
    assert comparison.changes[0].after is Status.AFFECTED


def test_duplicate_closure_id_with_different_content_is_rejected() -> None:
    bundle = _bundle()
    closure = bundle.closures[0]
    changed = replace(closure, reason=Reason("different", license="LicenseRef-Example-Internal"))
    with pytest.raises(Exception, match="conflicting duplicate"):
        _dedupe_closures([closure, changed])


def test_lockfiles_and_offline_audits_are_loaded() -> None:
    bundle = _bundle()
    prod = bundle.environments["prod"]
    staging = bundle.environments["staging"]

    assert str(prod.artifacts["demo-lib"].version) == "1.3.0"
    assert str(staging.artifacts["demo-lib"].version) == "1.1.0"
    assert len(prod.offline_audits) == 2
    assert prod.offline_audits[0].retrieved_at.isoformat() == "2026-11-15T08:05:00+00:00"
    assert staging.offline_audits[-1].reported["demo-lib"] == frozenset({"EXAMPLE-2026-0001"})


def test_cli_keeps_two_comparable_views(tmp_path: Path) -> None:
    output_dir = tmp_path / "views"
    report = tmp_path / "report.json"
    status = main(
        [
            str(BUNDLE),
            "--as-of",
            AS_OF,
            "--visible-at",
            EARLIER,
            "--visible-at",
            LATER,
            "--audience",
            "external",
            "--format",
            "json",
            "--output",
            str(report),
            "--write-views",
            str(output_dir),
        ]
    )

    assert status == 0
    first = json.loads((output_dir / "view-1.json").read_text())
    second = json.loads((output_dir / "view-2.json").read_text())
    comparison = json.loads((output_dir / "comparison.json").read_text())
    assert first["as_of_date"] == second["as_of_date"] == "2026-11-23"
    assert first["views"][0]["visible_at"] == "2026-11-15T10:00:00Z"
    assert second["views"][0]["visible_at"] == "2026-11-23T10:00:00Z"
    assert comparison["same_as_of"] is True
    assert comparison["reopen"][0]["environment"] == "staging"
    assert (output_dir / "review.md").exists()
    combined = report.read_text()
    assert RESTRICTED_CLOSURE_REASON not in combined
    assert RESTRICTED_SUPPLEMENT_REASON not in combined


def test_cli_fail_on_reopen_exit_code() -> None:
    status = main(
        [
            str(BUNDLE),
            "--as-of",
            AS_OF,
            "--visible-at",
            EARLIER,
            "--visible-at",
            LATER,
            "--audience",
            "external",
            "--format",
            "json",
            "--fail-on-reopen",
        ]
    )

    assert status == 2
