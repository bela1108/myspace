"""Walk through the two local source-independence exhibits.

Run from the repository root::

    .venv/bin/python examples/provenance_independence.py

The public JSON printed by this script contains no restricted identifier or
name.  The custodian view is only used to assert the exact local count.
"""

import json
import os
import sys

if __package__ in (None, ""):
    sys.path.insert(
        0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

import stix2
from stix2.provenance import CUSTODIAN_VIEW, PUBLIC_VIEW, check_independence


CREATED = "2026-01-01T00:00:00.000Z"
OBSERVED = "2026-01-01T00:00:00Z"
PUBLISHED = "2026-01-02T00:00:00Z"

OBS_A1 = "observed-data--00000000-0000-4000-8000-000000000001"
OBS_A2 = "observed-data--00000000-0000-4000-8000-000000000002"
OBS_A3 = "observed-data--00000000-0000-4000-8000-000000000003"
OBS_B1 = "observed-data--00000000-0000-4000-8000-000000000004"
OBS_B2 = "observed-data--00000000-0000-4000-8000-000000000005"
OBS_HIDDEN = "observed-data--00000000-0000-4000-8000-000000000006"
OBS_MISSING = "observed-data--00000000-0000-4000-8000-000000000099"

MARKING_ID = "marking-definition--00000000-0000-4000-8000-000000000077"
REPORT_IDS = (
    "report--00000000-0000-4000-8000-000000000011",
    "report--00000000-0000-4000-8000-000000000012",
    "report--00000000-0000-4000-8000-000000000013",
    "report--00000000-0000-4000-8000-000000000014",
    "report--00000000-0000-4000-8000-000000000015",
)


def _observation(observation_id, name, **kwargs):
    kwargs.setdefault("created", CREATED)
    kwargs.setdefault("modified", CREATED)
    if "objects" not in kwargs and "object_refs" not in kwargs:
        kwargs["object_refs"] = [
            "file--" + observation_id.split("--", 1)[1],
        ]
    return stix2.v21.ObservedData(
        id=observation_id,
        first_observed=OBSERVED,
        last_observed=OBSERVED,
        number_observed=1,
        name=name,
        allow_custom=True,
        **kwargs,
    )


def _report(report_id, refs):
    return stix2.v21.Report(
        id=report_id,
        created=CREATED,
        modified=CREATED,
        name="case report " + report_id,
        published=PUBLISHED,
        report_types=["threat-report"],
        object_refs=refs,
    )


def _custodian_marking():
    return stix2.v21.MarkingDefinition(
        id=MARKING_ID,
        created=CREATED,
        name="CUSTODIAN-ONLY EVIDENCE",
        definition_type="statement",
        definition=stix2.v21.StatementMarking(
            statement="Custodian team only",
        ),
    )


def _bundle(objects):
    return stix2.v21.Bundle(objects=objects, allow_custom=True)


def _public_json(result):
    return json.dumps(
        result.as_dict(), ensure_ascii=False, indent=2, sort_keys=True,
    )


def independent_collections():
    """Exhibit A: three reports backed by three separate observations."""

    objects = [
        _observation(OBS_A1, "collection alpha"),
        _observation(OBS_A2, "collection bravo"),
        _observation(OBS_A3, "collection charlie"),
        _report(REPORT_IDS[0], [OBS_A1]),
        _report(REPORT_IDS[1], [OBS_A2]),
        _report(REPORT_IDS[2], [OBS_A3]),
    ]
    return _bundle(objects)


def shared_hidden_source():
    """Exhibit B: two transcripts both relay one restricted original."""

    marking = _custodian_marking()
    original = _observation(
        OBS_HIDDEN,
        "sealed original seizure record",
        object_marking_refs=[marking.id],
    )
    first = _observation(
        OBS_B1,
        "first transcript",
        citation_refs=[OBS_HIDDEN],
    )
    second = _observation(
        OBS_B2,
        "second transcript",
        citation_refs=[OBS_HIDDEN],
    )
    return _bundle([
        marking,
        original,
        first,
        second,
        _report(REPORT_IDS[3], [OBS_B1]),
        _report(REPORT_IDS[4], [OBS_B2]),
    ])


def public_views_do_not_distinguish_missing_from_restricted():
    """The same visible citation must look identical in both situations."""

    visible = _observation(
        OBS_B1,
        "relay transcript",
        citation_refs=[OBS_MISSING],
    )
    missing = check_independence(_bundle([visible]), view=PUBLIC_VIEW)

    marking = _custodian_marking()
    restricted = _observation(
        OBS_MISSING,
        "sealed original",
        object_marking_refs=[marking.id],
    )
    hidden = check_independence(
        _bundle([visible, marking, restricted]),
        view=PUBLIC_VIEW,
    )

    assert _public_json(missing) == _public_json(hidden)
    return hidden


def three_report_narrative():
    """Three reports: two relay one restricted source, one is independent."""

    marking = _custodian_marking()
    original = _observation(
        OBS_HIDDEN,
        "sealed shared original",
        object_marking_refs=[marking.id],
    )
    first = _observation(
        OBS_B1, "first relay", citation_refs=[OBS_HIDDEN],
    )
    second = _observation(
        OBS_B2, "second relay", citation_refs=[OBS_HIDDEN],
    )
    independent = _observation(OBS_A1, "independent collection")
    return _bundle([
        marking,
        original,
        first,
        second,
        independent,
        _report(REPORT_IDS[0], [OBS_B1]),
        _report(REPORT_IDS[1], [OBS_B2]),
        _report(REPORT_IDS[2], [OBS_A1]),
    ])


def main():
    independent = independent_collections()
    shared = shared_hidden_source()

    independent_public = check_independence(independent, view=PUBLIC_VIEW)
    independent_custodian = check_independence(
        independent, view=CUSTODIAN_VIEW,
    )
    shared_public = check_independence(shared, view=PUBLIC_VIEW)
    shared_custodian = check_independence(shared, view=CUSTODIAN_VIEW)
    narrative = three_report_narrative()
    narrative_public = check_independence(narrative, view=PUBLIC_VIEW)
    narrative_custodian = check_independence(
        narrative, view=CUSTODIAN_VIEW,
    )

    assert independent_public.report_count == 3
    assert independent_public.independent_sources_lower_bound == 3
    assert independent_public.independent_sources is None
    assert independent_custodian.independent_sources == 3

    assert shared_public.report_count == 2
    assert shared_public.independent_sources_lower_bound == 1
    assert shared_public.independent_sources is None
    assert shared_public.open_component_count == 1
    assert len(shared_public.gaps) == 2
    assert all(gap.target_ref is None for gap in shared_public.gaps)
    assert all(gap.reason == "unresolved" for gap in shared_public.gaps)
    assert shared_custodian.independent_sources == 1

    assert narrative_public.report_count == 3
    assert narrative_public.independent_sources_lower_bound == 2
    assert narrative_public.conservative_lower_bound == 1
    assert narrative_public.independent_sources is None
    assert narrative_custodian.independent_sources == 2

    serialized = _public_json(shared_public)
    assert OBS_HIDDEN not in serialized
    assert "sealed original seizure record" not in serialized
    assert MARKING_ID not in serialized

    public_views_do_not_distinguish_missing_from_restricted()

    print("Exhibit A: three genuinely independent collections")
    print("  public lower bound :", independent_public.independent_sources_lower_bound)
    print("  public exact       :", independent_public.independent_sources)
    print("  custodian exact    :", independent_custodian.independent_sources)
    print()
    print("Exhibit B: two transcripts of one restricted original")
    print("  public lower bound :", shared_public.independent_sources_lower_bound)
    print("  public exact       :", shared_public.independent_sources)
    print("  public gaps        :", len(shared_public.gaps), "(targets redacted)")
    print("  custodian exact    :", shared_custodian.independent_sources)
    print("  hidden identity in public JSON: no")
    print()
    print("Narrative exhibit: three reports, two relay one restricted source")
    print("  reports            :", narrative_public.report_count)
    print("  public lower bound :", narrative_public.independent_sources_lower_bound)
    print("  conservative bound :", narrative_public.conservative_lower_bound)
    print("  custodian exact    :", narrative_custodian.independent_sources)
    print()
    print("Privacy check: a missing target and a restricted target produce")
    print("identical public output.")
    print()
    print("Public result for Exhibit B:")
    print(serialized)


if __name__ == "__main__":
    main()
