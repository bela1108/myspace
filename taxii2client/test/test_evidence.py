import datetime

import pytz

from taxii2client.evidence import (
    deduplicate_evidence_records, extract_evidence,
    extract_manifest_evidence
)


OBJECT_ID = "indicator--252c7c11-daf2-42bd-843b-be65edca9f61"
OBJECT_VERSION = "2016-11-03T12:30:59.000Z"


class MockManifestResponse(object):
    def __init__(self, url, payload, received_at):
        self.json_dict = payload
        self.received_at = received_at

        class Request(object):
            pass

        self.request = Request()
        self.request.url = url


def manifest_v20(date_added):
    return {
        "objects": [
            {
                "id": OBJECT_ID,
                "date_added": date_added,
                "versions": [OBJECT_VERSION],
                "media_types": [
                    "application/vnd.oasis.stix+json; version=2.0"
                ]
            }
        ]
    }


def manifest_v21(date_added):
    return {
        "objects": [
            {
                "id": OBJECT_ID,
                "date_added": date_added,
                "version": OBJECT_VERSION,
                "media_type": "application/stix+json;version=2.1"
            }
        ]
    }


def test_extract_evidence_supports_both_manifest_generations():
    response = MockManifestResponse(
        "https://example.org/v20/manifest/",
        manifest_v20("2016-11-01T03:04:05Z"),
        datetime.datetime(2016, 11, 1, 4, 5, 6, tzinfo=pytz.utc)
    )

    records = extract_manifest_evidence(response)

    assert records == [
        {
            "object_id": OBJECT_ID,
            "object_version": OBJECT_VERSION,
            "source_identity": "https://example.org/v20/manifest/",
            "source_url": "https://example.org/v20/manifest/",
            "source_arrival_time": "2016-11-01T03:04:05Z",
            "local_received_at": "2016-11-01T04:05:06.000000Z",
            "media_type": (
                "application/vnd.oasis.stix+json; version=2.0"
            ),
            "receipt_count": 1,
            "local_received_ats": [
                "2016-11-01T04:05:06.000000Z"
            ],
            "raw_manifest_entry": response.json_dict["objects"][0]
        }
    ]

    v21_records = extract_evidence(manifest_v21(
        "2016-11-04T03:04:05Z"
    ))

    assert v21_records[0]["object_version"] == OBJECT_VERSION
    assert v21_records[0]["media_type"] == (
        "application/stix+json;version=2.1"
    )
    assert v21_records[0]["source_arrival_time"] == (
        "2016-11-04T03:04:05Z"
    )
    assert v21_records[0]["source_identity"] == "unknown"


def test_three_sources_and_one_retry_remain_three_testimonies():
    first_received = datetime.datetime(
        2016, 11, 1, 4, 0, 0, tzinfo=pytz.utc
    )
    retry_received = datetime.datetime(
        2016, 11, 1, 5, 0, 0, tzinfo=pytz.utc
    )
    responses = [
        MockManifestResponse(
            "https://unit-a.example/manifest/",
            manifest_v20("2016-11-01T03:00:00Z"),
            first_received
        ),
        MockManifestResponse(
            "https://unit-b.example/manifest/",
            manifest_v21("2016-11-01T03:10:00Z"),
            datetime.datetime(
                2016, 11, 1, 4, 10, 0, tzinfo=pytz.utc
            )
        ),
        MockManifestResponse(
            "https://unit-c.example/manifest/",
            manifest_v21("2016-11-01T03:20:00Z"),
            datetime.datetime(
                2016, 11, 1, 4, 20, 0, tzinfo=pytz.utc
            )
        ),
        MockManifestResponse(
            "https://unit-a.example/manifest/",
            manifest_v20("2016-11-01T03:00:00Z"),
            retry_received
        )
    ]

    records = extract_evidence(responses)

    assert len(records) == 3
    by_source = {
        record["source_identity"]: record for record in records
    }
    assert set(by_source) == {
        "https://unit-a.example/manifest/",
        "https://unit-b.example/manifest/",
        "https://unit-c.example/manifest/"
    }

    retry_record = by_source["https://unit-a.example/manifest/"]
    assert retry_record["receipt_count"] == 2
    assert retry_record["source_arrival_time"] == (
        "2016-11-01T03:00:00Z"
    )
    assert retry_record["local_received_at"] == (
        "2016-11-01T04:00:00.000000Z"
    )
    assert retry_record["local_received_ats"] == [
        "2016-11-01T04:00:00.000000Z",
        "2016-11-01T05:00:00.000000Z"
    ]


def test_deduplicate_evidence_records_keeps_independent_sources():
    records = extract_manifest_evidence(
        manifest_v20("2016-11-01T03:00:00Z"),
        source_identity="unit-a"
    )
    records.extend(extract_manifest_evidence(
        manifest_v21("2016-11-01T03:10:00Z"),
        source_identity="unit-b"
    ))

    deduped = deduplicate_evidence_records(records)

    assert len(deduped) == 2
    assert {record["source_identity"] for record in deduped} == {
        "unit-a", "unit-b"
    }


def test_manifest_entry_without_version_produces_no_evidence():
    response = {
        "objects": [
            {
                "id": OBJECT_ID,
                "date_added": "2016-11-01T03:00:00Z"
            }
        ]
    }

    assert extract_evidence(response) == []
