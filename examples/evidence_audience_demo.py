"""Offline evidence review demo with fictional SOC telemetry.

The same alert is reviewed twice:

* the internal SOC audience may see the restricted payroll table and actor;
* the external audience may only see the export action and source address.

A derived field (endpoint = host + ip) is intentionally missing its IP source in the
fictional event, so internal review exposes the pending evidence while the public
report only contains conclusions that are independently confirmable.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.evidence import (
    Audience,
    ConversionRecord,
    EvidenceClaim,
    EvidenceReviewer,
    FieldProvenance,
)
from sigma.matching import Event, EventLogSource, SigmaMatcher
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

RULE = """
title: Restricted payroll export
name: restricted_payroll_export
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        action: export
        payroll_table: payroll_restricted
        actor_id: svc_payroll
    condition: selection
"""

TIMESTAMP = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
TELEMETRY = {
    "action": "export",
    "data.table_name": "payroll_restricted",
    "data.actor": "svc_payroll",
    "src_ip": "203.0.113.9",
    "host": "soc-demo-ws17",
}


def build_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        [
            ProcessingItem(
                FieldMappingTransformation(
                    {
                        "payroll_table": "data.table_name",
                        "actor_id": "data.actor",
                    }
                ),
                identifier="fictional_field_map",
            )
        ]
    )


def main() -> None:
    pipeline = build_pipeline()

    # Conversion side: keep the field mapping snapshot with the generated query.
    collection = SigmaCollection.from_yaml(RULE)
    backend = TextQueryTestBackend(pipeline)
    queries = backend.convert(collection)
    conversion = ConversionRecord.capture(backend, collection.rules[0])

    # Matching side: the same telemetry is evaluated against the processed rule.
    match_collection = SigmaCollection.from_yaml(RULE)
    with SigmaMatcher(match_collection, pipeline=pipeline) as matcher:
        matches = matcher.match(
            Event(
                timestamp=TIMESTAMP,
                logsource=EventLogSource(category="process_creation", product="windows"),
                data=TELEMETRY,
            )
        )
    assert len(matches) == 1

    provenance = FieldProvenance()
    provenance.add_derived("endpoint", ["host", "ip"])

    claims = [
        EvidenceClaim(
            id="restricted_export",
            statement="The restricted payroll table was exported by svc_payroll",
            sources={"action", "data.table_name", "data.actor"},
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
        EvidenceClaim(
            id="endpoint_attribution",
            statement="The export was attributed to the endpoint",
            sources={"endpoint"},
        ),
    ]

    reviewer = EvidenceReviewer(provenance=provenance)
    internal = reviewer.review(
        matches[0],
        Audience.internal("soc-internal"),
        claims=claims,
        conversion=conversion,
    )
    external = reviewer.review(
        matches[0],
        Audience.external(
            "external-partner",
            {"action", "src_ip"},
            {
                "restricted_export": None,
                "export_observed": "An export action was observed.",
                "source_ip": "The export came from 203.0.113.9.",
                "endpoint_attribution": None,
            },
        ),
        claims=claims,
        conversion=conversion,
    )

    # The external artifact contains no restricted field names.
    public_json = json.dumps(external.as_public_dict(), indent=2)
    assert "payroll_table" not in public_json
    assert "actor_id" not in public_json

    print("converted query:", queries[0])
    print("\n=== INTERNAL REVIEW (SOC) ===")
    print(internal.to_text())
    print("\n=== EXTERNAL REPORT ===")
    print(external.to_text(view="public"))
    print("\n=== EXTERNAL JSON ===")
    print(public_json)


if __name__ == "__main__":
    main()
