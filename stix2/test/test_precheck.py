import pytest

from stix2.precheck import (
    ACTION_HOLD_ORIGINAL, ACTION_INVESTIGATE, INVALID_NOT_TESTIMONY,
    INVALID_UNKNOWN_OBJECT, REASON_INCOMPLETE_HANDOVER,
    REASON_LATE_RETENTION_SLIP, REASON_MISSING_HANDOVER, Directive,
    HandoverEntry, NonFictionalBundleError, run_precheck,
)

FICTIONAL_MARKING = "marking-definition--3f327e2a-9c5a-4c1a-9f2d-1a2b3c4d5e6f"
TESTIMONY_MARKING = "marking-definition--7b8c9d0e-1f2a-4b3c-8d9e-0f1a2b3c4d5e"
TESTIMONY_NOTE = "note--9c0a1b2c-3d4e-4f5a-8b6c-7d8e9f0a1b2c"
REDACTED_NOTE = "note--5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b"

NOTE_V1 = "2026-03-01T00:00:00.000Z"
NOTE_V2 = "2026-04-01T00:00:00.000Z"


def _marking(marking_id, statement):
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2026-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": statement},
    }


def _note(note_id, modified, marking_refs):
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": note_id,
        "created": NOTE_V1,
        "modified": modified,
        "abstract": "Fictional witness statement",
        "content": "Synthetic testimony original for precheck tests.",
        "object_refs": [note_id],
        "object_marking_refs": marking_refs,
    }


def _fictional_bundle():
    return {
        "type": "bundle",
        "id": "bundle--1c4f6e2a-5b7d-4e8f-9a0b-2c3d4e5f6a7b",
        "objects": [
            _marking(FICTIONAL_MARKING, "FICTIONAL-SYNTHETIC training data"),
            _marking(TESTIMONY_MARKING, "TESTIMONY-ORIGINAL:witness-statement"),
            _note(TESTIMONY_NOTE, NOTE_V1,
                  [FICTIONAL_MARKING, TESTIMONY_MARKING]),
            _note(TESTIMONY_NOTE, NOTE_V2,
                  [FICTIONAL_MARKING, TESTIMONY_MARKING]),
            _note(REDACTED_NOTE, NOTE_V1,
                  [FICTIONAL_MARKING, TESTIMONY_MARKING]),
            _note(REDACTED_NOTE, NOTE_V2, [FICTIONAL_MARKING]),
        ],
    }


def _hold(directive_id, agency, effective_at, object_id=TESTIMONY_NOTE,
          object_version=None):
    return Directive(
        directive_id=directive_id,
        agency=agency,
        action=ACTION_HOLD_ORIGINAL,
        object_id=object_id,
        effective_at=effective_at,
        object_version=object_version,
    )


def _handover(entry_id, from_agency, to_agency, effective_at, recorded_at,
              releases_retention=True):
    return HandoverEntry(
        entry_id=entry_id,
        object_id=TESTIMONY_NOTE,
        from_agency=from_agency,
        to_agency=to_agency,
        effective_at=effective_at,
        recorded_at=recorded_at,
        releases_retention=releases_retention,
    )


def test_non_fictional_bundle_rejected():
    bundle = {
        "type": "bundle",
        "id": "bundle--1c4f6e2a-5b7d-4e8f-9a0b-2c3d4e5f6a7b",
        "objects": [_note(TESTIMONY_NOTE, NOTE_V1, [])],
    }
    with pytest.raises(NonFictionalBundleError):
        run_precheck(bundle, [])


def test_directive_on_unmarked_object_rejected():
    bundle = _fictional_bundle()
    bundle["objects"].append({
        "type": "note",
        "spec_version": "2.1",
        "id": "note--11111111-2222-4333-8444-555555555555",
        "created": NOTE_V1,
        "modified": NOTE_V1,
        "abstract": "Not fictional",
        "content": "Missing the fictional marking.",
        "object_refs": ["note--11111111-2222-4333-8444-555555555555"],
    })
    directive = Directive(
        directive_id="dir-x",
        agency="agency-a",
        action=ACTION_INVESTIGATE,
        object_id="note--11111111-2222-4333-8444-555555555555",
        effective_at="2026-05-01T00:00:00Z",
    )
    with pytest.raises(NonFictionalBundleError):
        run_precheck(bundle, [directive])


def test_investigate_directives_from_two_agencies_are_compatible():
    directives = [
        Directive("dir-1", "agency-a", ACTION_INVESTIGATE, TESTIMONY_NOTE,
                  "2026-05-01T00:00:00Z"),
        Directive("dir-2", "agency-b", ACTION_INVESTIGATE, TESTIMONY_NOTE,
                  "2026-05-02T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives)
    assert report.ok
    assert ("dir-1", "dir-2") in report.compatible_pairs
    assert report.conflicts == []


def test_hold_directives_without_handover_are_mutually_exclusive():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z"),
        _hold("dir-2", "agency-b", "2026-05-02T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives)
    assert not report.ok
    assert ("dir-1", "dir-2") in report.mutually_exclusive_pairs
    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.object_id == TESTIMONY_NOTE
    assert conflict.testimony_class == "witness-statement"
    assert conflict.directive_ids == ("dir-1", "dir-2")
    assert conflict.reason == REASON_MISSING_HANDOVER
    assert conflict.handover_entry_id is None


def test_timely_handover_makes_hold_directives_compatible():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z"),
        _hold("dir-2", "agency-b", "2026-05-10T00:00:00Z"),
    ]
    registry = [
        _handover("ho-1", "agency-a", "agency-b",
                  "2026-05-05T00:00:00Z", "2026-05-06T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives, registry)
    assert report.ok
    assert ("dir-1", "dir-2") in report.compatible_pairs
    assert report.conflicts == []


def test_late_retention_slip_reports_testimony_and_minimal_set():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z"),
        _hold("dir-2", "agency-b", "2026-05-10T00:00:00Z"),
    ]
    registry = [
        _handover("ho-late", "agency-a", "agency-b",
                  "2026-05-05T00:00:00Z", "2026-05-20T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives, registry)
    assert not report.ok
    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.object_id == TESTIMONY_NOTE
    assert conflict.directive_ids == ("dir-1", "dir-2")
    assert conflict.reason == REASON_LATE_RETENTION_SLIP
    assert conflict.handover_entry_id == "ho-late"


def test_handover_must_release_prior_retention_obligation():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z"),
        _hold("dir-2", "agency-b", "2026-05-10T00:00:00Z"),
    ]
    registry = [
        _handover("ho-silent", "agency-a", "agency-b",
                  "2026-05-05T00:00:00Z", "2026-05-06T00:00:00Z",
                  releases_retention=False),
    ]
    report = run_precheck(_fictional_bundle(), directives, registry)
    assert not report.ok
    assert report.incomplete_handovers == ["ho-silent"]
    assert report.conflicts[0].reason == REASON_INCOMPLETE_HANDOVER
    assert report.conflicts[0].handover_entry_id == "ho-silent"


def test_minimal_conflicting_permission_sets_with_three_agencies():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z"),
        _hold("dir-2", "agency-b", "2026-05-10T00:00:00Z"),
        _hold("dir-3", "agency-c", "2026-05-15T00:00:00Z"),
    ]
    registry = [
        _handover("ho-1", "agency-a", "agency-b",
                  "2026-05-05T00:00:00Z", "2026-05-06T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives, registry)
    conflict_sets = {conflict.directive_ids for conflict in report.conflicts}
    assert conflict_sets == {("dir-1", "dir-3"), ("dir-2", "dir-3")}
    assert all(len(ids) == 2 for ids in conflict_sets)
    assert ("dir-1", "dir-2") in report.compatible_pairs
    assert all(
        conflict.object_id == TESTIMONY_NOTE
        for conflict in report.conflicts
    )


def test_same_agency_reissue_is_compatible():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z"),
        _hold("dir-2", "agency-a", "2026-05-10T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives)
    assert report.ok
    assert ("dir-1", "dir-2") in report.compatible_pairs


def test_hold_on_version_without_testimony_marking_is_invalid():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z",
              object_id=REDACTED_NOTE, object_version=NOTE_V2),
    ]
    report = run_precheck(_fictional_bundle(), directives)
    assert not report.ok
    assert report.invalid_directives == {"dir-1": INVALID_NOT_TESTIMONY}


def test_hold_pinned_to_testimony_version_resolves_that_version():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z",
              object_id=REDACTED_NOTE, object_version=NOTE_V1),
    ]
    report = run_precheck(_fictional_bundle(), directives)
    assert report.ok
    assert str(report.resolved_directives["dir-1"]).startswith("2026-03-01")


def test_unpinned_hold_resolves_latest_version():
    directives = [
        _hold("dir-1", "agency-a", "2026-05-01T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives)
    assert report.ok
    assert str(report.resolved_directives["dir-1"]).startswith("2026-04-01")


def test_unknown_object_is_invalid():
    directives = [
        Directive("dir-1", "agency-a", ACTION_INVESTIGATE,
                  "note--00000000-0000-4000-8000-000000000000",
                  "2026-05-01T00:00:00Z"),
    ]
    report = run_precheck(_fictional_bundle(), directives)
    assert report.invalid_directives == {"dir-1": INVALID_UNKNOWN_OBJECT}
