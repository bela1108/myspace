"""Offline demo: repeated acceptance runs over signed delivery events.

Scenario
--------
Run 1: a confirmed chain root, two validly signed events that both claim to
       succeed the same predecessor (a fork; both stay on record for review),
       and an event whose predecessor has not arrived yet.
Run 2: the late predecessor arrives so the pending chain recovers, and a
       replay of an already admitted signature is rejected (no second step).
Run 3: a misbound acknowledgement whose main-archive binding names the wrong
       original; its successor hangs pending human review.
Run 4: one more run proving only the last three node summaries are retained.

Everything is generated and verified locally; no network is used.
"""

import json
import os

from signedjson.acceptance.events import build_event, sign_event
from signedjson.acceptance.materials import material_id
from signedjson.acceptance.store import AcceptanceStore
from signedjson.key import (
    encode_verify_key_base64,
    generate_signing_key,
    get_verify_key,
)

OUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def write_json(name, payload):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
    return path


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    signing_key = generate_signing_key("1")
    verify_key = get_verify_key(signing_key)
    signer = "desk-12"
    key_config = {
        signer: {
            "key_id": "ed25519:1",
            "key": encode_verify_key_base64(verify_key),
        }
    }

    originals = {
        "contract": {"doc": "contract", "v": 1},
        "appendix-a": {"doc": "appendix-a", "v": 1},
        "appendix-b": {"doc": "appendix-b", "v": 1},
        "rider": {"doc": "rider", "v": 1},
        "note": {"doc": "note", "v": 1},
    }
    materials = {material_id(payload): payload for payload in originals.values()}
    contract_id = material_id(originals["contract"])
    appendix_a_id = material_id(originals["appendix-a"])
    appendix_b_id = material_id(originals["appendix-b"])
    rider_id = material_id(originals["rider"])
    note_id = material_id(originals["note"])
    write_json("keys.json", key_config)
    write_json("materials.json", materials)

    def event(event_id, material, predecessor=None, declared_material=None):
        unsigned = build_event(
            event_id,
            signer,
            material,
            predecessor=predecessor,
            material_id=declared_material,
        )
        return sign_event(unsigned, signer, signing_key)

    root = event("e1", originals["contract"], declared_material=contract_id)
    fork_a = event(
        "e2",
        originals["appendix-a"],
        predecessor="e1",
        declared_material=appendix_a_id,
    )
    fork_b = event(
        "e3",
        originals["appendix-b"],
        predecessor="e1",
        declared_material=appendix_b_id,
    )
    branch_a_step = event(
        "e4",
        originals["note"],
        predecessor="e2",
        declared_material=note_id,
    )
    pending = event(
        "e5",
        originals["rider"],
        predecessor="e6",
        declared_material=rider_id,
    )

    late_predecessor = event(
        "e6",
        originals["contract"],
        declared_material=contract_id,
    )
    misbound = build_event(
        "e7",
        signer,
        originals["rider"],
        predecessor="e4",
        material_id=appendix_a_id,
    )
    after_review_item = event(
        "e8",
        originals["note"],
        predecessor="e7",
        declared_material=note_id,
    )

    batches = [
        [root, fork_a, fork_b, branch_a_step, pending],
        [late_predecessor, dict(fork_a)],
        [sign_event(misbound, signer, signing_key)],
        [after_review_item],
    ]

    state_path = os.path.join(OUT_DIR, "acceptance-state.json")
    store = AcceptanceStore(state_path)
    store.register_keys(key_config)
    store.register_materials(materials)
    store.save()

    for index, batch in enumerate(batches, start=1):
        snapshot = store.run(batch)
        write_json("run-%s-snapshot.json" % index, snapshot)
        print(
            "run %s: counts=%s review=%s duplicates=%s"
            % (
                index,
                snapshot["status_counts"],
                [
                    item["event_id"] + ":" + item["reason"]
                    for item in snapshot["review_queue"]
                ],
                snapshot["ingest_report"]["duplicates"],
            )
        )

    print("retained snapshots: %d (limit 3)" % len(store.snapshots))
    for snapshot in store.snapshots:
        print("  run %s nodes=%d" % (snapshot["run"], snapshot["event_count"]))


if __name__ == "__main__":
    main()
