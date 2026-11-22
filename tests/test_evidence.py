"""Offline evidence review tests with fictional telemetry."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationFieldAliases
from sigma.evidence import (
    Audience,
    ConversionRecord,
    EvidenceClaim,
    EvidenceReviewer,
    FactExtractor,
    FieldProvenance,
    PublicProjection,
)
from sigma.matching import Event, EventLogSource, SigmaMatcher
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

TS = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)


PAYROLL_RULE = """
title: Restricted payroll export
name: payroll_export
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        action: export
        payroll_table: restricted_payroll
    condition: selection
"""


COMMAND_RULE = """
title: Suspicious command
name: suspicious_command
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: mimikatz
        action: export
    condition: selection
"""


OR_RULE = """
title: Either branch
name: either_branch
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains: mimikatz
        - User: alice
    condition: selection
"""


def make_event(data):
    return Event(
        timestamp=TS,
        logsource=EventLogSource(category="process_creation", product="windows"),
        data=data,
    )


def make_match(yaml_text, data, pipeline=None):
    collection = SigmaCollection.from_yaml(yaml_text)
    with SigmaMatcher(collection, pipeline=pipeline) as matcher:
        matches = matcher.match(make_event(data))
    assert len(matches) == 1
    return matches[0]


def payroll_claims():
    return [
        EvidenceClaim(
            id="restricted_export",
            statement="The restricted payroll table was exported",
            sources={"action", "payroll_table"},
        ),
        EvidenceClaim(
            id="export_observed",
            statement="An export action was observed",
            sources={"action"},
        ),
        EvidenceClaim(
            id="source_ip",
            statement="The export came from 203.0.113.9",
            sources={"src_ip"},
        ),
    ]


class TestAudienceReports:
    def test_same_alert_has_different_internal_and_external_reports(self):
        match = make_match(
            PAYROLL_RULE,
            {
                "action": "export",
                "payroll_table": "restricted_payroll",
                "src_ip": "203.0.113.9",
            },
        )
        reviewer = EvidenceReviewer()
        internal = reviewer.review(
            match, Audience.internal("soc-internal"), claims=payroll_claims()
        )
        external = reviewer.review(
            match,
            Audience.external(
                "finance-partner",
                {"action", "src_ip"},
                {
                    "restricted_export": None,
                    "export_observed": "An export action was observed.",
                    "source_ip": "The export came from a monitored source.",
                },
            ),
            claims=payroll_claims(),
        )

        assert internal.suspended is False
        assert {finding.fact_id for finding in internal.published} == {
            "restricted_export",
            "export_observed",
            "source_ip",
        }

        assert external.public_statements == [
            "An export action was observed.",
            "The export came from a monitored source.",
        ]
        assert external.suspended is True
        assert "restricted_export" not in {finding.fact_id for finding in external.published}
        pending = {item.fact_id: item for item in external.pending}
        assert pending["restricted_export"].restricted_sources == frozenset({"payroll_table"})

    def test_public_view_redacts_restricted_evidence(self):
        match = make_match(
            PAYROLL_RULE,
            {
                "action": "export",
                "payroll_table": "restricted_payroll",
                "src_ip": "203.0.113.9",
            },
        )
        report = EvidenceReviewer().review(
            match,
            Audience.external(
                "partner",
                {"action"},
                {"export_observed": "An export action was observed."},
            ),
            claims=payroll_claims(),
        )

        public_json = json.dumps(report.as_public_dict())
        internal_json = json.dumps(report.as_internal_dict())

        assert "restricted_payroll" not in public_json
        assert "payroll_table" not in public_json
        assert "payroll_table" in internal_json
        assert report.public_statements == ["An export action was observed."]
        assert report.pending[0].fact_id == "restricted_export"

    def test_public_projection_can_use_field_selector_and_value(self):
        match = make_match(
            COMMAND_RULE, {"CommandLine": "C:\\\\x\\\\mimikatz.exe", "action": "export"}
        )
        report = EvidenceReviewer().review(
            match,
            Audience.external(
                "partner",
                {"action"},
                {"field:action": PublicProjection("Observed action: {value}")},
            ),
        )
        assert report.public_statements == ["Observed action: export"]
        assert "CommandLine" in {source for item in report.pending for source in item.fields}


class TestProvenance:
    def test_alias_merge_reports_every_source(self):
        provenance = FieldProvenance()
        provenance.add_alias("user", ["src_user", "dst_user"])

        assert provenance.root_sources("user") == frozenset({"src_user", "dst_user"})
        resolution = provenance.resolve("user", {"src_user": "alice", "dst_user": "bob"})
        assert resolution.sources == frozenset({"src_user", "dst_user"})
        assert resolution.required == frozenset({"src_user", "dst_user"})

    def test_alias_with_single_observed_branch_requires_only_that_branch(self):
        provenance = FieldProvenance()
        provenance.add_alias("user", ["src_user", "dst_user"])

        resolution = provenance.resolve("user", {"src_user": "alice"})
        assert resolution.sources == frozenset({"src_user", "dst_user"})
        assert resolution.required == frozenset({"src_user"})
        assert resolution.missing == frozenset()

    def test_alias_merge_is_enforced_for_external_audience(self):
        provenance = FieldProvenance()
        provenance.add_alias("user", ["src_user", "dst_user"])
        claim = EvidenceClaim("user_activity", "User activity was observed", {"user"})
        match = make_match(
            PAYROLL_RULE,
            {"action": "export", "payroll_table": "restricted_payroll"},
        )

        internal = EvidenceReviewer(provenance=provenance).review(
            match,
            Audience.internal(),
            claims=[claim],
            derived_fields={},
        )
        assert internal.findings[0].sources == frozenset({"src_user", "dst_user"})
        assert internal.findings[0].status == "pending"
        assert internal.findings[0].missing_sources == frozenset({"src_user", "dst_user"})

    def test_derived_field_suspends_when_a_source_is_missing(self):
        provenance = FieldProvenance()
        provenance.add_derived("endpoint", ["host", "ip"])
        claim = EvidenceClaim("endpoint_seen", "The endpoint was observed", {"endpoint"})
        match = make_match(
            PAYROLL_RULE,
            {"action": "export", "payroll_table": "restricted_payroll", "host": "ws-17"},
        )

        report = EvidenceReviewer(provenance=provenance).review(
            match, Audience.internal(), claims=[claim]
        )

        assert report.suspended is True
        assert report.published == []
        assert report.findings[0].missing_sources == frozenset({"ip"})
        assert report.pending[0].missing_sources == frozenset({"ip"})

    def test_derived_field_withholds_when_a_source_is_restricted(self):
        provenance = FieldProvenance()
        provenance.add_derived("endpoint", ["host", "ip"])
        claim = EvidenceClaim("endpoint_seen", "The endpoint was observed", {"endpoint"})
        match = make_match(
            PAYROLL_RULE,
            {
                "action": "export",
                "payroll_table": "restricted_payroll",
                "host": "ws-17",
                "ip": "203.0.113.9",
            },
        )

        report = EvidenceReviewer(provenance=provenance).review(
            match,
            Audience.external("partner", {"host"}, "*"),
            claims=[claim],
        )

        assert report.suspended is True
        assert report.published == []
        assert report.findings[0].restricted_sources == frozenset({"ip"})
        assert report.pending[0].restricted_sources == frozenset({"ip"})


class TestConversionIntegration:
    def test_conversion_record_expands_mapped_field_to_original_source(self):
        pipeline = ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation({"payroll_table": "data.table"}),
                    identifier="map_table",
                )
            ]
        )
        collection = SigmaCollection.from_yaml(PAYROLL_RULE)
        backend = TextQueryTestBackend(pipeline)
        queries = backend.convert(collection)
        record = ConversionRecord.capture(backend, collection.rules[0])

        assert record.queries == queries
        assert record.field_provenance.root_sources("data.table") == frozenset({"payroll_table"})

        match = make_match(
            PAYROLL_RULE,
            {"action": "export", "data.table": "restricted_payroll"},
            pipeline=pipeline,
        )
        claim = EvidenceClaim("table_used", "A table was read", {"data.table"})
        internal = EvidenceReviewer().review(
            match, Audience.internal(), claims=[claim], conversion=record
        )
        external = EvidenceReviewer().review(
            match,
            Audience.external("partner", {"action"}, {"table_used": "A table was read."}),
            claims=[claim],
            conversion=record,
        )

        assert internal.findings[0].sources == frozenset({"payroll_table"})
        assert internal.findings[0].status == "confirmed"
        assert external.findings[0].restricted_sources == frozenset({"payroll_table"})
        assert external.pending[0].fields == frozenset({"payroll_table"})

    def test_correlation_aliases_expose_all_mapped_fields(self):
        aliases = SigmaCorrelationFieldAliases.from_dict(
            {"user": {"rule_a": "username", "rule_b": "account_name"}}
        )
        provenance = FieldProvenance.from_correlation_aliases(aliases)

        assert provenance.root_sources("user") == frozenset({"username", "account_name"})


class TestFactExtraction:
    def test_auto_facts_only_include_true_or_branch(self):
        match = make_match(OR_RULE, {"User": "alice"})
        facts = FactExtractor().extract(match)

        detection_sources = {
            source for fact in facts if fact.kind == "detection" for source in fact.sources
        }
        assert detection_sources == frozenset({"User"})
        assert "CommandLine" not in detection_sources

    def test_internal_report_exposes_pending_and_external_only_confirmed(self):
        match = make_match(
            COMMAND_RULE,
            {"CommandLine": "C:\\\\x\\\\mimikatz.exe", "action": "export"},
        )
        reviewer = EvidenceReviewer()
        internal = reviewer.review(match, Audience.internal())
        external = reviewer.review(
            match,
            Audience.external("partner", {"action"}, {"field:action": True}),
        )

        assert internal.suspended is False
        assert any(finding.kind == "detection" for finding in internal.findings)
        assert external.public_statements == ["action equals 'export'"]
        assert external.suspended is True
        assert all("CommandLine" in item.fields for item in external.pending)


NEGATED_RULE = """
title: Export without approved user
name: export_without_approved_user
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        action: export
    filter:
        User: alice
    condition: selection and not filter
"""


def test_negated_condition_uses_absence_as_evidence():
    match = make_match(NEGATED_RULE, {"action": "export"})
    report = EvidenceReviewer().review(match, Audience.internal())

    assert report.suspended is False
    negated = [finding for finding in report.findings if "not (" in finding.statement]
    assert negated
    assert negated[0].missing_sources == frozenset()
