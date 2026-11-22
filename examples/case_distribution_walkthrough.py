"""Offline walkthrough for case-scoped STIX2 local summaries.

Run from the repository root::

    python examples/case_distribution_walkthrough.py

The script keeps one public subgraph fixed, builds two different private
branches, and verifies that an unauthorized recipient gets item-by-item
identical summaries, pages, references and exported bundles in both cases.
It also records a receiver-facing policy-switch notice and the internal
rule-level audit for the same switch.
"""

import hashlib
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stix2.visibility import (
    PUBLIC_CASE, DistributionPolicy, LocalBundleSummary, ObjectAssignment,
    SubjectGrant,
)

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "case_distribution_records.json",
)


def sid(stix_type, label):
    return "{}--{}".format(stix_type, uuid.uuid5(uuid.NAMESPACE_URL, label))


def common(stix_type, label, name):
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": sid(stix_type, label),
        "created": "2026-11-01T00:00:00Z",
        "modified": "2026-11-01T00:00:00Z",
        "name": name,
    }


PUBLIC_IDENTITY = common("identity", "walkthrough-public-identity", "Public Identity")
PUBLIC_INDICATOR = common("indicator", "walkthrough-public-indicator", "public-indicator")
PUBLIC_INDICATOR.update({
    "pattern": "[file:name = 'public-indicator']",
    "pattern_type": "stix",
    "valid_from": "2026-11-01T00:00:00Z",
})
PUBLIC_MALWARE = common("malware", "walkthrough-public-malware", "Public Malware")
PUBLIC_RELATIONSHIP = common(
    "relationship", "walkthrough-public-relationship", "public-relationship",
)
PUBLIC_RELATIONSHIP.pop("name")
PUBLIC_RELATIONSHIP.update({
    "relationship_type": "related-to",
    "source_ref": PUBLIC_INDICATOR["id"],
    "target_ref": PUBLIC_MALWARE["id"],
})


def branch(label, size):
    actor = common("threat-actor", label + "-actor", label + " Actor")
    indicators = []
    for index in range(size):
        indicator = common(
            "indicator", "{}-indicator-{}".format(label, index),
            "{}-indicator-{}".format(label, index),
        )
        indicator.update({
            "pattern": "[file:name = '{}-{}']".format(label, index),
            "pattern_type": "stix",
            "valid_from": "2026-11-01T00:00:00Z",
        })
        indicators.append(indicator)

    cross_edge = common("relationship", label + "-cross-edge", label + "-cross-edge")
    cross_edge.pop("name")
    cross_edge.update({
        "relationship_type": "related-to",
        "source_ref": PUBLIC_INDICATOR["id"],
        "target_ref": indicators[0]["id"],
    })
    return [actor] + indicators + [cross_edge]


BRANCH_A = branch("case-a", 3)
BRANCH_B = branch("case-b", 12)
BRANCH_C = branch("case-c", 2)


def public_objects(private_ref_id):
    report = common("report", "walkthrough-public-report", "Public Report")
    report.update({
        "published": "2026-11-01T00:00:00Z",
        "object_refs": [
            PUBLIC_INDICATOR["id"],
            private_ref_id,
            "indicator--not-a-real-uuid",
        ],
    })
    return [
        PUBLIC_IDENTITY, PUBLIC_INDICATOR, PUBLIC_MALWARE,
        PUBLIC_RELATIONSHIP, report,
    ]


def bundle_for(branch_objects):
    return public_objects(branch_objects[1]["id"]) + list(branch_objects)


def policy(version, extra_rules=()):
    rules = [
        SubjectGrant("group-a-case-a", ["case-group-a"], ["case-a"]),
        SubjectGrant("group-b-case-b", ["case-group-b"], ["case-b"]),
        ObjectAssignment(
            "public-objects", PUBLIC_CASE,
            [obj["id"] for obj in public_objects(BRANCH_A[1]["id"])],
        ),
        ObjectAssignment("case-a-objects", "case-a", [o["id"] for o in BRANCH_A]),
        ObjectAssignment("case-b-objects", "case-b", [o["id"] for o in BRANCH_B]),
        ObjectAssignment("case-c-objects", "case-c", [o["id"] for o in BRANCH_C]),
    ]
    rules.extend(extra_rules)
    return DistributionPolicy(version, rules)


def digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def page_records(view, page_size):
    return [page.to_dict() for page in view.pages(page_size)]


def regression_record():
    old_policy = policy("2026.11-a")
    summary_a = LocalBundleSummary(bundle_for(BRANCH_A), old_policy)
    summary_b = LocalBundleSummary(bundle_for(BRANCH_B), old_policy)
    view_a = summary_a.view("outsider")
    view_b = summary_b.view("outsider")

    pages_a = page_records(view_a, 2)
    pages_b = page_records(view_b, 2)
    refs_a = view_a.references()
    refs_b = view_b.references()
    export_a = view_a.to_bundle()
    export_b = view_b.to_bundle()

    return {
        "subject": "outsider",
        "public_subgraph_fixed": True,
        "summary": view_a.summary(),
        "summary_identical": view_a.summary() == view_b.summary(),
        "pagination": {
            "page_size": 2,
            "page_count": len(pages_a),
            "page_digests_a": [digest(page) for page in pages_a],
            "page_digests_b": [digest(page) for page in pages_b],
            "identical": pages_a == pages_b,
        },
        "references": refs_a,
        "references_identical": refs_a == refs_b,
        "bundle_id": export_a["id"],
        "bundle_identical": export_a == export_b,
    }


def switch_record():
    old_policy = policy("2026.11-a")
    new_policy = policy(
        "2026.11-b",
        extra_rules=[SubjectGrant("group-a-case-b", ["case-group-a"], ["case-b"])],
    )
    objects = bundle_for(BRANCH_A) + BRANCH_B + BRANCH_C
    summary = LocalBundleSummary(objects, old_policy)

    switch = summary.switch(new_policy, "case-group-a")
    notice = switch.receiver_notice().to_dict()
    audit = switch.audit().to_dict()
    unchanged_notice = summary.switch(
        new_policy, "case-group-b",
    ).receiver_notice().to_dict()

    return {
        "receiver_notice": notice,
        "receiver_notice_has_private_case_c": any(
            obj["id"] in json.dumps(notice)
            for obj in BRANCH_C
        ),
        "internal_audit": audit,
        "unchanged_subject_notice": unchanged_notice,
    }


def main():
    records = {
        "regression": regression_record(),
        "policy_switch": switch_record(),
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2, sort_keys=True)
        handle.write("\n")

    regression = records["regression"]
    print("public summary:", json.dumps(regression["summary"], sort_keys=True))
    print("summary identical:", regression["summary_identical"])
    print("pagination identical:", regression["pagination"]["identical"])
    print("references identical:", regression["references_identical"])
    print("bundle identical:", regression["bundle_identical"])
    print("policy audit rules:", records["policy_switch"]["internal_audit"]["changed_rule_ids"])
    print("receiver notice:", records["policy_switch"]["receiver_notice"]["message"])
    print("wrote", OUTPUT_PATH)


if __name__ == "__main__":
    main()
