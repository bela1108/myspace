"""Chain-level acceptance rules."""

import copy

import pytest

from signedjson.acceptance import status
from signedjson.acceptance.events import build_event, sign_event
from signedjson.acceptance.materials import material_id, signature_fingerprint
from signedjson.sign import sign_json


def test_confirmed_chain(verifier, make_event, originals, material_ids):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    step = make_event(
        "e2",
        originals["appendix-a"],
        predecessor="e1",
        declared=material_ids["appendix-a"],
    )
    report = verifier.ingest([root, step])
    assert report.accepted == ["e1", "e2"]
    statuses = verifier.recompute()
    assert statuses == {"e1": status.CONFIRMED, "e2": status.CONFIRMED}


def test_out_of_order_predecessor_then_recovery(
    verifier, make_event, originals, material_ids
):
    pending = make_event(
        "e2",
        originals["rider"],
        predecessor="e1",
        declared=material_ids["rider"],
    )
    verifier.ingest([pending])
    assert verifier.recompute()["e2"] == status.AWAITING_PREDECESSOR

    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    verifier.ingest([root])
    assert verifier.recompute()["e2"] == status.CONFIRMED


def test_replay_same_signature_does_not_advance(
    verifier, make_event, originals, material_ids
):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    first = verifier.ingest([root])
    assert first.accepted == ["e1"]
    replay = verifier.ingest([copy.deepcopy(root)])
    assert replay.duplicates == ["e1"]
    assert replay.accepted == []
    assert len(verifier.events) == 1


def test_relabeled_copy_fails_signature_check(
    verifier, signer, signing_key, originals, material_ids
):
    root = sign_json(
        build_event(
            "e1",
            signer,
            originals["contract"],
            material_id=material_ids["contract"],
        ),
        signer,
        signing_key,
    )
    verifier.ingest([root])
    relabeled = copy.deepcopy(root)
    relabeled["event_id"] = "e9"
    report = verifier.ingest([relabeled])
    assert report.invalid_signatures == ["e9"]
    assert set(verifier.events) == {"e1"}


def test_identical_redelivery_is_deduplicated(
    verifier, make_event, originals, material_ids
):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    verifier.ingest([root])
    report = verifier.ingest([copy.deepcopy(root)])
    assert report.duplicates == ["e1"]
    assert set(verifier.events) == {"e1"}


def test_tampered_signature_is_rejected(
    verifier, signer, signing_key, originals, material_ids
):
    event = sign_event(
        build_event(
            "e1",
            signer,
            originals["contract"],
            material_id=material_ids["contract"],
        ),
        signer,
        signing_key,
    )
    event["material_digest"] = "0" * 64
    report = verifier.ingest([event])
    assert report.invalid_signatures == ["e1"]
    assert verifier.events == {}


def test_unknown_signer_is_rejected(make_event, originals, material_ids, materials):
    from signedjson.key import generate_signing_key, get_verify_key

    other_key = get_verify_key(generate_signing_key("2"))
    from signedjson.acceptance.verifier import AcceptanceVerifier

    verifier = AcceptanceVerifier(materials=materials, keys={"someone": other_key})
    event = make_event("e1", originals["contract"], declared=material_ids["contract"])
    report = verifier.ingest([event])
    assert report.unknown_signers == ["e1"]



def test_fork_keeps_both_branches_and_flags_only_competitors(
    verifier, make_event, originals, material_ids
):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    branch_a = make_event(
        "e2",
        originals["appendix-a"],
        predecessor="e1",
        declared=material_ids["appendix-a"],
    )
    branch_b = make_event(
        "e3",
        originals["appendix-b"],
        predecessor="e1",
        declared=material_ids["appendix-b"],
    )
    downstream = make_event(
        "e4",
        originals["rider"],
        predecessor="e2",
        declared=material_ids["rider"],
    )
    verifier.ingest([root, branch_a, branch_b, downstream])
    statuses = verifier.recompute()
    assert statuses["e1"] == status.CONFIRMED
    assert statuses["e2"] == status.FORK
    assert statuses["e3"] == status.FORK
    assert statuses["e4"] == status.BLOCKED
    review = {item["event_id"] for item in verifier.review_queue()}
    assert review == {"e2", "e3"}
    labels = verifier.branches()
    assert labels["e1>e2"] == ["e2", "e4"]
    assert labels["e1>e3"] == ["e3"]


def test_misbound_original_is_flagged_and_blocks_descendants(
    verifier, make_event, originals, material_ids
):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    misbound = make_event(
        "e2",
        originals["rider"],
        predecessor="e1",
        declared=material_ids["appendix-a"],
    )
    descendant = make_event(
        "e3",
        originals["contract"],
        predecessor="e2",
        declared=material_ids["contract"],
    )
    verifier.ingest([root, misbound, descendant])
    statuses = verifier.recompute()
    assert statuses["e2"] == status.MISBOUND
    assert statuses["e3"] == status.BLOCKED
    audit = {row["event_id"]: row for row in verifier.chain_audit()}
    assert audit["e2"]["declared_material"] == material_ids["appendix-a"]
    assert audit["e2"]["acknowledged_material"] == material_ids["rider"]


def test_unknown_digest_is_misbound(
    verifier, make_event, originals, material_ids, signing_key
):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    ghost = build_event(
        "e2",
        "desk-1",
        {"doc": "ghost"},
        predecessor="e1",
        material_id=material_ids["contract"],
    )
    verifier.ingest([root, sign_event(ghost, "desk-1", signing_key)])
    assert verifier.recompute()["e2"] == status.MISBOUND


def test_snapshot_names_acknowledged_originals(
    verifier, make_event, originals, material_ids
):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    verifier.ingest([root])
    snapshot = verifier.snapshot(run=1)
    node = snapshot["nodes"][0]
    assert node["acknowledged_material"] == material_ids["contract"]
    assert node["branch"] == "e1"
    assert snapshot["status_counts"] == {status.CONFIRMED: 1}


def test_signature_fingerprint_stable(make_event, originals, material_ids):
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    assert signature_fingerprint(root) == signature_fingerprint(copy.deepcopy(root))


@pytest.mark.parametrize("payload", [{"a": 1, "b": 2}, {"b": 2, "a": 1}])
def test_material_id_order_independent(payload):
    assert material_id(payload) == material_id({"b": 2, "a": 1})


def test_predecessor_loop_cannot_confirm(
    verifier, signer, signing_key, originals, material_ids
):
    first = build_event(
        "e1",
        signer,
        originals["contract"],
        predecessor="e2",
        material_id=material_ids["contract"],
    )
    second = build_event(
        "e2",
        signer,
        originals["rider"],
        predecessor="e1",
        material_id=material_ids["rider"],
    )
    verifier.ingest([
        sign_event(first, signer, signing_key),
        sign_event(second, signer, signing_key),
    ])
    statuses = verifier.recompute()
    assert statuses["e1"] == status.MISBOUND
    assert statuses["e2"] == status.BLOCKED
    review = {item["event_id"] for item in verifier.review_queue()}
    assert review == {"e1"}
