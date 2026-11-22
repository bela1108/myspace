import json
import uuid

import pytest

import stix2
from stix2.visibility import (
    DistributionPolicy, LocalBundleSummary, ObjectAssignment, PublicCase,
    SubjectGrant, audit_policy_change, local_summary,
)


def _sid(stix_type, label):
    return "{}--{}".format(
        stix_type, uuid.uuid5(uuid.NAMESPACE_URL, label),
    )


def _common(stix_type, label, name):
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": _sid(stix_type, label),
        "created": "2026-11-01T00:00:00Z",
        "modified": "2026-11-01T00:00:00Z",
        "name": name,
    }


def _identity(label, name):
    return _common("identity", label, name)


def _malware(label, name):
    return _common("malware", label, name)


def _threat_actor(label, name):
    return _common("threat-actor", label, name)


def _indicator(label, name):
    obj = _common("indicator", label, name)
    obj.update({
        "pattern": "[file:name = '{}']".format(name),
        "pattern_type": "stix",
        "valid_from": "2026-11-01T00:00:00Z",
    })
    return obj


def _relationship(label, source_ref, target_ref):
    obj = _common("relationship", label, label)
    obj.pop("name")
    obj.update({
        "relationship_type": "related-to",
        "source_ref": source_ref,
        "target_ref": target_ref,
    })
    return obj


def _report(label, name, object_refs):
    obj = _common("report", label, name)
    obj.update({
        "published": "2026-11-01T00:00:00Z",
        "object_refs": list(object_refs),
    })
    return obj


PUBLIC_IDENTITY = _identity("public-identity", "Public Identity")
PUBLIC_INDICATOR = _indicator("public-indicator", "public-indicator")
PUBLIC_MALWARE = _malware("public-malware", "Public Malware")
PUBLIC_RELATIONSHIP = _relationship(
    "public-relationship",
    PUBLIC_INDICATOR["id"],
    PUBLIC_MALWARE["id"],
)


def _public_objects(private_indicator_id, dangling_ref):
    report = _report(
        "public-report",
        "Public Report",
        [PUBLIC_INDICATOR["id"], private_indicator_id, dangling_ref],
    )
    report["x_dangling_ref"] = dangling_ref
    return [
        PUBLIC_IDENTITY,
        PUBLIC_INDICATOR,
        PUBLIC_MALWARE,
        PUBLIC_RELATIONSHIP,
        report,
    ]


def _branch(label, size=4):
    actor = _threat_actor(label + "-actor", label + " Actor")
    indicators = [
        _indicator(
            "{}-indicator-{}".format(label, index),
            "{}-indicator-{}".format(label, index),
        )
        for index in range(size)
    ]
    cross_edge = _relationship(
        label + "-cross-edge",
        PUBLIC_INDICATOR["id"],
        indicators[0]["id"],
    )
    return [actor] + indicators + [cross_edge]


BRANCH_A = _branch("case-a", size=3)
BRANCH_B = _branch("case-b", size=12)
BRANCH_C = _branch("case-c", size=2)


def _base_policy(version="2026.11-a", extra_rules=()):
    public = _public_objects(
        BRANCH_A[1]["id"], "indicator--not-a-real-uuid",
    )
    rules = [
        SubjectGrant("group-a-case", ["group-a"], ["case-a"]),
        SubjectGrant("group-b-case", ["group-b"], ["case-b"]),
        ObjectAssignment(
            "public-objects", PublicCase,
            [obj["id"] for obj in public],
        ),
        ObjectAssignment(
            "case-a-objects", "case-a",
            [obj["id"] for obj in BRANCH_A],
        ),
        ObjectAssignment(
            "case-b-objects", "case-b",
            [obj["id"] for obj in BRANCH_B],
        ),
        ObjectAssignment(
            "case-c-objects", "case-c",
            [obj["id"] for obj in BRANCH_C],
        ),
    ]
    rules.extend(extra_rules)
    return DistributionPolicy(version, rules)


def _bundle_for_branch(branch):
    # The public report deliberately references a branch-specific object.
    # A receiver-safe view must prune that reference without changing any
    # other part of the report.
    public = _public_objects(
        branch[1]["id"], "indicator--not-a-real-uuid",
    )
    return public + branch


def _assert_view_is_stable(left, right):
    assert left.summary() == right.summary()
    assert left.references() == right.references()
    assert left.to_bundle() == right.to_bundle()

    for page_size in (1, 2, 3, 5, 100):
        left_pages = [page.to_dict() for page in left.pages(page_size)]
        right_pages = [page.to_dict() for page in right.pages(page_size)]
        assert left_pages == right_pages

    assert left.page(1, 2).to_dict() == right.page(1, 2).to_dict()


def test_public_case_alias_is_exported():
    assert PublicCase == "public"


def test_unauthorized_view_ignores_private_branch_contents():
    policy = _base_policy()
    summary_a = LocalBundleSummary(_bundle_for_branch(BRANCH_A), policy)
    summary_b = LocalBundleSummary(_bundle_for_branch(BRANCH_B), policy)

    _assert_view_is_stable(
        summary_a.view("outsider"), summary_b.view("outsider"),
    )

    serialized = json.dumps(
        summary_a.export("outsider"), sort_keys=True,
    )
    for private_obj in BRANCH_A + BRANCH_B:
        assert private_obj["id"] not in serialized


def test_visible_nodes_keep_normal_content_and_visible_refs():
    policy = _base_policy()
    view = LocalBundleSummary(_bundle_for_branch(BRANCH_A), policy).view(
        "outsider",
    )

    report = view.object(_sid("report", "public-report"))
    assert report is not None
    assert report["name"] == "Public Report"
    assert report["published"] == "2026-11-01T00:00:00Z"
    assert report["object_refs"] == [PUBLIC_INDICATOR["id"]]
    assert "x_dangling_ref" not in report

    relationship = view.object(PUBLIC_RELATIONSHIP["id"])
    assert relationship is not None
    assert relationship["source_ref"] == PUBLIC_INDICATOR["id"]
    assert relationship["target_ref"] == PUBLIC_MALWARE["id"]

    # The public-to-private cross edge is itself visible, but its private
    # endpoint is not, so the edge must be omitted entirely.
    assert view.object(BRANCH_A[-1]["id"]) is None


def test_two_case_groups_only_see_their_own_branch():
    policy = _base_policy()
    bundle = (
        _bundle_for_branch(BRANCH_A) + BRANCH_B
    )
    summary = LocalBundleSummary(bundle, policy)

    group_a_ids = summary.view("group-a").ids
    group_b_ids = summary.view("group-b").ids

    for obj in BRANCH_A:
        assert obj["id"] in group_a_ids
        assert obj["id"] not in group_b_ids

    for obj in BRANCH_B:
        assert obj["id"] in group_b_ids
        assert obj["id"] not in group_a_ids


def test_pagination_counts_only_visible_objects():
    policy = _base_policy()
    summary_a = LocalBundleSummary(_bundle_for_branch(BRANCH_A), policy)
    summary_b = LocalBundleSummary(_bundle_for_branch(BRANCH_B), policy)

    outsider_a = summary_a.view("outsider")
    outsider_b = summary_b.view("outsider")

    page_a = outsider_a.page(1, page_size=2)
    page_b = outsider_b.page(1, page_size=2)
    assert page_a.to_dict() == page_b.to_dict()
    assert page_a.total == outsider_a.summary()["total"]
    assert page_a.page_count == page_b.page_count

    beyond = outsider_a.page(page_a.page_count + 5, page_size=2)
    assert beyond.items == []
    assert beyond.total == page_a.total
    assert beyond.page_count == page_a.page_count
    assert not beyond.has_next


def test_malformed_hidden_and_missing_refs_are_indistinguishable():
    policy = _base_policy()

    visible = _identity("ref-source", "Ref Source")
    hidden_target = BRANCH_A[1]

    with_hidden = dict(visible)
    with_hidden["x_object_ref"] = hidden_target["id"]
    with_hidden["x_object_refs"] = [hidden_target["id"]]

    with_missing = dict(visible)
    with_missing["x_object_ref"] = "indicator--deadbeef"
    with_missing["x_object_refs"] = ["not-an-id", "indicator--deadbeef"]

    rules = [
        ObjectAssignment(
            "visible", PublicCase,
            [visible["id"]],
        ),
        ObjectAssignment(
            "hidden", "case-a", [hidden_target["id"]],
        ),
    ]
    policy = DistributionPolicy("refs", rules)

    summary_hidden = local_summary([with_hidden], policy)
    summary_missing = local_summary([with_missing], policy)

    assert summary_hidden.view("outsider").objects == summary_missing.view(
        "outsider",
    ).objects
    assert summary_hidden.references("outsider") == \
        summary_missing.references("outsider")


def test_policy_switch_gives_receiver_notice_and_internal_audit():
    old_policy = _base_policy("2026.11-a")
    new_policy = _base_policy(
        "2026.11-b",
        extra_rules=[SubjectGrant("group-a-case-b", ["group-a"], ["case-b"])],
    )
    bundle = (
        _bundle_for_branch(BRANCH_A) + BRANCH_B + BRANCH_C
    )
    summary = LocalBundleSummary(bundle, old_policy)
    switch = summary.switch(new_policy, "group-a")

    notice = switch.receiver_notice()
    assert notice.changed
    assert set(notice.added_ids) == {obj["id"] for obj in BRANCH_B}
    assert notice.removed_ids == ()

    notice_dict = notice.to_dict()
    serialized = json.dumps(notice_dict, sort_keys=True)
    for obj in BRANCH_C:
        assert obj["id"] not in serialized
    assert notice_dict["summary_before"] != notice_dict["summary_after"]

    audit = switch.audit()
    assert audit.changed_rule_ids == ("group-a-case-b",)
    assert [rule.rule_id for rule in audit.added] == ["group-a-case-b"]
    assert audit.removed == []
    assert audit.modified == []
    assert "group-a" in audit.changed_subjects
    assert "case-b" in audit.changed_cases
    assert audit.is_empty is False

    # A subject whose own rules did not change must not learn about the
    # other group's newly granted case.
    unchanged = summary.switch(new_policy, "group-b").receiver_notice()
    assert unchanged.changed is False
    assert unchanged.to_dict()["added"] == []
    assert unchanged.to_dict()["removed"] == []


def test_policy_audit_reports_modified_rules():
    old_policy = _base_policy("2026.11-a")
    moved_id = BRANCH_A[1]["id"]
    new_rules = [
        rule for rule in old_policy.rules
        if rule.rule_id != "case-a-objects"
    ]
    new_rules.append(
        ObjectAssignment(
            "case-a-objects", "case-c",
            [obj["id"] for obj in BRANCH_A if obj["id"] != moved_id],
        ),
    )
    new_rules.append(
        ObjectAssignment("case-c-moved", "case-c", [moved_id]),
    )
    new_policy = DistributionPolicy("2026.11-b", new_rules)

    audit = audit_policy_change(old_policy, new_policy)
    assert audit.changed_rule_ids == ("case-a-objects", "case-c-moved")
    assert audit.version_changed

    modified = audit.to_dict()["modified"]
    assert len(modified) == 1
    assert modified[0]["rule_id"] == "case-a-objects"
    assert moved_id in modified[0]["before"]["object_ids"]
    assert moved_id not in modified[0]["after"]["object_ids"]
    assert [rule.rule_id for rule in audit.added] == ["case-c-moved"]
    assert "case-c" in audit.changed_cases


def test_policy_round_trip_and_validation():
    policy = _base_policy()
    restored = DistributionPolicy.from_dict(policy.to_dict())
    assert restored == policy

    with pytest.raises(ValueError):
        DistributionPolicy(
            "duplicate",
            [
                SubjectGrant("same", ["a"], ["x"]),
                SubjectGrant("same", ["b"], ["y"]),
            ],
        )
    with pytest.raises(ValueError):
        SubjectGrant("bad", [], ["x"])
    with pytest.raises(ValueError):
        ObjectAssignment("bad", "case", [])


def test_stix_base_objects_are_accepted():
    identity = stix2.Identity(name="STIX Identity")
    indicator = stix2.Indicator(
        name="stix-indicator",
        pattern="[file:name = 'stix-indicator']",
        pattern_type="stix",
        valid_from="2026-11-01T00:00:00Z",
    )
    relationship = stix2.Relationship(
        relationship_type="related-to",
        source_ref=indicator.id,
        target_ref=identity.id,
    )
    policy = DistributionPolicy(
        "stix-objects",
        [
            ObjectAssignment(
                "public", PublicCase,
                [identity.id, indicator.id, relationship.id],
            ),
        ],
    )

    summary = LocalBundleSummary(
        [identity, indicator, relationship], policy,
    )
    view = summary.view("outsider")

    assert view.summary()["total"] == 3
    assert {
        ref["target_id"] for ref in view.references()
    } == {identity.id, indicator.id}

    # STIX objects carry STIXdatetime values; exporting must normalize them
    # rather than leaking a non-JSON-serializable type into the bundle.
    exported = summary.export("outsider")
    assert exported["type"] == "bundle"
    assert len(exported["objects"]) == 3
