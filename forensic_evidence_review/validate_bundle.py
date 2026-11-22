"""Validate the evidence-comparison bundle independently of the builder."""

import base64
import hashlib
from pathlib import Path

import stix2

from custom_types import CAPABILITY_VALUES, REVIEW_CLASSIFICATION_VALUES

HERE = Path(__file__).resolve().parent
BUNDLE_PATH = HERE / "bundle" / "evidence-comparison-bundle.json"
SAMPLE_PATH = HERE / "evidence" / "statement-2023-0518.txt"

REF_PROPS = (
    "source_ref", "target_ref", "created_by_ref", "object_refs",
    "content_ref", "x_report_refs", "x_evidence_refs",
    "x_capability_table_ref", "x_short_text_ref", "object_marking_refs",
)


def iter_refs(obj):
    for prop in REF_PROPS:
        if prop not in obj:
            continue
        value = obj[prop]
        if isinstance(value, list):
            for item in value:
                yield prop, item
        else:
            yield prop, value


def main():
    bundle = stix2.parse(BUNDLE_PATH.read_text(encoding="utf-8"), allow_custom=True)
    assert bundle["type"] == "bundle"
    objects = {obj["id"]: obj for obj in bundle["objects"]}
    print("parsed objects:", len(objects))

    failures = []
    for obj in bundle["objects"]:
        for prop, ref in iter_refs(obj):
            if ref == stix2.TLP_RED.id:
                continue
            if ref not in objects:
                failures.append(obj["id"] + " -> " + prop + " -> " + ref + " dangling")
    assert not failures, failures
    print("reference integrity: OK (all local refs resolve inside the bundle)")

    sample_bytes = SAMPLE_PATH.read_bytes()
    expected = {
        "MD5": hashlib.md5(sample_bytes).hexdigest(),
        "SHA-1": hashlib.sha1(sample_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(sample_bytes).hexdigest(),
        "SHA-512": hashlib.sha512(sample_bytes).hexdigest(),
    }

    table = next(o for o in bundle["objects"] if o["type"] == "x-hash-capability-table")
    entries = table["x_algorithm_capability_entries"]
    assert len(entries) == 12, len(entries)
    for entry in entries:
        assert entry["capability"] in CAPABILITY_VALUES, entry
    counts = {}
    for entry in entries:
        counts[entry["capability"]] = counts.get(entry["capability"], 0) + 1
    print("capability entries:", len(entries), counts)

    confirm_recomputed = [
        e for e in entries
        if e["capability"] == "confirm" and e.get("recomputed")
    ]
    assert {e["algorithm"] for e in confirm_recomputed} == {"SHA-256", "SHA-512"}
    inconclusive = [e for e in entries if e["capability"] == "inconclusive"]
    assert {e["algorithm"] for e in inconclusive} == {"SHA-256", "SHA-512", "SSDEEP"}
    assert all(not e["recomputed"] for e in inconclusive)
    print("confirm recomputed algos:", sorted({e["algorithm"] for e in confirm_recomputed}))
    print("inconclusive (kept open):", sorted({e["algorithm"] for e in inconclusive}))

    file_b = objects["file--b1000000-0000-4000-8000-000000000002"]
    for algo, value in expected.items():
        assert file_b["hashes"][algo] == value, algo
    artifact = objects["artifact--c1000000-0000-4000-8000-000000000003"]
    assert base64.b64decode(artifact["payload_bin"]) == sample_bytes
    print("recomputed digests match sample and embedded artifact payload: OK")

    file_a = objects["file--a1000000-0000-4000-8000-000000000001"]
    assert set(file_a["hashes"]) == {"MD5"}
    assert file_a["hashes"]["MD5"] == expected["MD5"]
    print("report-A file keeps only the legacy MD5, equal to recomputed value: OK")

    review = next(o for o in bundle["objects"] if o["type"] == "x-digest-cross-date-review")
    review_entries = review["x_algorithm_date_entries"]
    assert len(review_entries) == 5
    for item in review_entries:
        assert item["review_classification"] in REVIEW_CLASSIFICATION_VALUES
    by_algo = {item["algorithm"]: item for item in review_entries}
    assert by_algo["MD5"]["review_classification"] == "lead_only"
    assert by_algo["SHA-256"]["review_classification"] == "recomputed"
    assert by_algo["SHA-512"]["review_classification"] == "recomputed"
    assert by_algo["SSDEEP"]["review_classification"] == "missing_original_or_version"
    assert by_algo["SSDEEP"]["digest_value"] is None
    print("cross-date review classifications: OK")

    det_file = stix2.v21.File(
        name="statement-2023-0518.txt",
        size=len(sample_bytes),
        hashes=expected,
        content_ref="artifact--c1000000-0000-4000-8000-000000000003",
        allow_custom=True,
    )
    det_file_again = stix2.v21.File(name="statement-2023-0518.txt", size=len(sample_bytes), hashes=expected, content_ref="artifact--c1000000-0000-4000-8000-000000000003", allow_custom=True)
    assert det_file.id == det_file_again.id and det_file.id.startswith("file--")
    assert file_b.id.startswith("file--")
    det_artifact = stix2.v21.Artifact(
        mime_type="text/plain",
        payload_bin=base64.b64encode(sample_bytes).decode("ascii"),
    )
    det_artifact_again = stix2.v21.Artifact(mime_type="text/plain", payload_bin=base64.b64encode(sample_bytes).decode("ascii"))
    assert det_artifact.id == det_artifact_again.id and det_artifact.id.startswith("artifact--")
    assert artifact.id.startswith("artifact--")
    print("SCO deterministic ids stable; bundle fixed local ids valid: OK")

    note = next(o for o in bundle["objects"] if o["type"] == "note")
    assert set(note["object_refs"]) == {
        table["id"], review["id"],
        "report--10000000-0000-4000-8000-000000000001",
        "report--10000000-0000-4000-8000-000000000002",
    }
    print("note links table, review and both reports: OK")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
