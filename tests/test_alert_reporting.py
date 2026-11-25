from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sigma.matching import Event, EventLogSource, SigmaMatch, SigmaMatcher
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.tracking import FieldMappingTracking
from sigma.processing.transformations.fields import FieldMappingTransformation
from sigma.reporting import (
    Alert,
    PublicationGate,
    PublicationHoldError,
    build_audience_reports,
    build_report,
    verify_report,
)
from sigma.collection import SigmaCollection

RULE_YAML = """
title: Credential Use
name: credential_use
status: test
logsource:
  category: authentication
  product: test
detection:
  selection:
    User: alice
    Password|contains: secret
  condition: selection
"""


def _event() -> Event:
    return Event(
        timestamp=datetime(2026, 11, 25, tzinfo=timezone.utc),
        logsource=EventLogSource(category="authentication", product="test"),
        data={
            "User": "alice",
            "Password": "top-secret-value",
        },
    )


def _match() -> SigmaMatch:
    collection = SigmaCollection.from_yaml(RULE_YAML)
    with SigmaMatcher(collection) as matcher:
        results = matcher.match(_event())
    assert len(results) == 1
    return results[0]


def test_field_mapping_tracks_alias_merge_and_derived_sources() -> None:
    tracking = FieldMappingTracking()
    tracking.add_mapping("User", "user_name")
    tracking.add_alias_merge("account_identity", sources=["user_name", "upn"])
    tracking.add_derived_field(
        "display_name",
        sources=["first_name", "last_name"],
        expression="first_name + ' ' + last_name",
    )

    user_trace = tracking.trace_field("account_identity")
    display_trace = tracking.trace_field("display_name")

    assert user_trace.complete
    assert set(tracking.alias_merges["account_identity"].sources) == {"user_name", "upn"}
    assert set(user_trace.origins) == {"User", "upn"}
    assert display_trace.complete
    assert set(display_trace.origins) == {"first_name", "last_name"}
    assert "account_identity" in tracking.alias_merges
    assert "display_name" in tracking.derived_fields


def test_matcher_connects_processing_tracking_to_match_output() -> None:
    collection = SigmaCollection.from_yaml(RULE_YAML)
    pipeline = ProcessingPipeline(
        items=[
            ProcessingItem(
                identifier="map_user",
                transformation=FieldMappingTransformation(mapping={"User": "user_name"}),
            )
        ]
    )
    event = _event()
    event.data["user_name"] = event.data.pop("User")

    with SigmaMatcher(collection, pipeline=pipeline) as matcher:
        match = matcher.match(event)[0]

    assert match.processing_tracking is pipeline.field_mappings or (
        match.field_mappings is not None and "User" in match.field_mappings
    )
    assert match.field_mappings is not None
    assert match.field_mappings["User"] == {"user_name"}
    assert match.provenance is match.field_mappings.provenance


def test_same_alert_produces_different_verifiable_audience_reports() -> None:
    match = _match()
    pair = build_audience_reports(
        match,
        restricted_fields=["Password"],
        signing_key="test-secret",
    )

    assert pair.internal.alert_id == pair.external.alert_id
    assert pair.internal["audience"] == "internal"
    assert pair.external["audience"] == "external"
    assert pair.internal != pair.external
    assert pair.verify("test-secret")

    external_text = str(pair.external.to_dict())
    assert "top-secret-value" not in external_text
    assert "Password" not in external_text
    assert "alice" in external_text
    assert pair.external["public_evidence"]
    assert pair.external["evidence"][0]["proof"]
    assert pair.external["evidence"][0]["leaf_hash"]

    tampered = dict(pair.external)
    tampered_evidence = [dict(item) for item in tampered["evidence"]]
    tampered_evidence[0]["value"] = "mallory"
    tampered["evidence"] = tampered_evidence
    assert not verify_report(tampered, "test-secret")


def test_incomplete_provenance_holds_publication() -> None:
    match = _match()
    tracking = FieldMappingTracking()
    tracking.add_alias_merge("broken_alias", sources=(), complete=False)
    match.processing_tracking = tracking
    match.provenance = tracking.provenance

    internal = build_report(match, "internal", restricted_fields=["Password"])
    external = build_report(match, "external", restricted_fields=["Password"])

    assert internal.status == "held"
    assert not internal.publishable
    assert external.status == "held"
    assert "provenance_gap:broken_alias" in internal["publication"]["reasons"]

    gate = PublicationGate(restricted_fields=["Password"])
    assert gate.publish(internal) is None
    with pytest.raises(PublicationHoldError):
        gate.publish(internal, raise_on_hold=True)


def test_external_report_held_when_only_restricted_evidence_exists() -> None:
    alert = Alert(
        alert_id="alert-restricted-only",
        evidence=[
            {
                "evidence_id": "evidence-001",
                "field": "Password",
                "value": "secret",
                "classification": "restricted",
            }
        ],
    )
    report = build_report(alert, "external", restricted_fields=["Password"])
    assert report.status == "held"
    assert "no_public_evidence" in report["publication"]["reasons"]
    assert "secret" not in str(report.to_dict())


def test_keyless_report_detects_tampering_through_digest() -> None:
    match = _match()
    report = build_report(match, "internal")
    assert report.verify()
    report["title"] = "changed"
    assert not report.verify()
