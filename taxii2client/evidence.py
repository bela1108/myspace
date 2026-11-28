"""Helpers for extracting handoff evidence from TAXII manifest responses."""
import datetime

import pytz


def _utc_now():
    return datetime.datetime.now(tz=pytz.utc)


def _format_datetime(value):
    if value.tzinfo is None:
        value = pytz.utc.localize(value)
    else:
        value = value.astimezone(pytz.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _response_url(response):
    request = getattr(response, "request", None)
    return getattr(request, "url", None) or getattr(response, "url", None)


def _source_identity(response, source_identity=None):
    if source_identity:
        return source_identity

    url = _response_url(response)
    if url:
        return url.split("?", 1)[0].split("#", 1)[0]

    return "unknown"


def _manifest_versions(entry):
    if "versions" in entry:
        return list(entry.get("versions") or [])
    if "version" in entry:
        version = entry.get("version")
        return [version] if version is not None else []
    return []


def _manifest_media_types(entry):
    if "media_types" in entry:
        return list(entry.get("media_types") or [])
    if "media_type" in entry:
        media_type = entry.get("media_type")
        return [media_type] if media_type is not None else []
    return [None]


def _local_received_at(response, now=None):
    received_at = getattr(response, "received_at", None)
    if received_at is None:
        received_at = now or _utc_now()
    if isinstance(received_at, datetime.datetime):
        return _format_datetime(received_at)
    return received_at


def extract_manifest_evidence(response, source_identity=None, now=None):
    """Extract evidence records from one TAXII 2.0 or 2.1 manifest response.

    date_added is retained as source-attested arrival time. The local receipt
    timestamp is captured from the response wrapper or now and is explicitly
    marked as a local observation.
    """
    if hasattr(response, "json_dict"):
        manifest = response.json_dict
    elif hasattr(response, "json") and callable(response.json):
        manifest = response.json()
    else:
        manifest = response

    source_url = _response_url(response)
    origin = _source_identity(response, source_identity)
    observed_at = _local_received_at(response, now)
    records = []

    for entry in manifest.get("objects", []):
        versions = _manifest_versions(entry)
        media_types = _manifest_media_types(entry)

        for version in versions:
            for media_type in media_types:
                records.append({
                    "object_id": entry.get("id"),
                    "object_version": version,
                    "source_identity": origin,
                    "source_url": source_url,
                    "source_arrival_time": entry.get("date_added"),
                    "local_received_at": observed_at,
                    "media_type": media_type,
                    "receipt_count": 1,
                    "local_received_ats": [observed_at],
                    "raw_manifest_entry": dict(entry),
                })

    return records


def deduplicate_evidence_records(records):
    """Merge retries from the same source without making them new testimony."""
    deduped = {}

    for record in records:
        key = (
            record["source_identity"],
            record["object_id"],
            record["object_version"],
        )
        existing = deduped.get(key)

        if existing is None:
            deduped[key] = dict(record)
            deduped[key]["local_received_ats"] = list(
                record["local_received_ats"]
            )
            deduped[key]["raw_manifest_entry"] = dict(
                record["raw_manifest_entry"]
            )
            continue

        existing["receipt_count"] += record.get("receipt_count", 1)
        existing["local_received_ats"].extend(record.get("local_received_ats", []))
        existing["local_received_at"] = min(existing["local_received_ats"])

    return list(deduped.values())


def extract_evidence(responses, source_identity=None, now=None):
    """Extract and deduplicate evidence from one or many manifest responses."""
    if isinstance(responses, dict) or hasattr(responses, "json_dict") or \
            not hasattr(responses, "__iter__"):
        responses = [responses]

    records = []
    for response in responses:
        records.extend(extract_manifest_evidence(
            response, source_identity=source_identity, now=now
        ))
    return deduplicate_evidence_records(records)
