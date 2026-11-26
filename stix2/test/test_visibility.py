import json
import uuid

import pytest

import stix2
from stix2.visibility import (
    PUBLIC_CASE,
    DistributionPolicy,
    LocalBundleSummary,
    ObjectAssignment,
    PublicCase,
    SubjectGrant,
    audit_policy_change,
    local_summary,
)


def _id(stix_type, label):
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, label)}"


def _common(stix_type, label, name):
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": _id(stix_type, label),
        "created": "2026-11-01T00:00:00Z",
        "modified": "2026-11-01T00:00:00Z",
        "name": name,
    }


def _identity(label, name):
    return _common("identity", label, name)


def _indicator(label, name):
    obj = _common("indicator", label, name)
    obj.update({
        "pattern": f"[file:name = '{name}']",
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
PUBLIC_MALWARE = _indicator("public-malware", "public-malware")
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
    empty_refs = _identity("empty-refs", "Empty Refs")
    empty_refs["x_refs"] = []
    return [
        PUBLIC_IDENTITY,
        PUBLIC_INDICATOR,
        PUBLIC_MALWARE,
        PUBLIC_RELATIONSHIP,
        report,
        empty_refs,
    ]


def _branch(label, size):
    actor = _common("threat-actor", f"{label}-actor", f"{label} Actor")
    indicators = [
        _indicator(
            f"{label}-indicator-{index}",
            f"{label}-indicator-{index}",
        )
        for index in range(size)
    ]
    cross_edge = _relationship(
        f"{label}-cross-edge",
        PUBLIC_INDICATOR["id"],
        indicators[0]["id"],
    )
    return [actor] + indicators + [cross_edge]


BRANCH_A = _branch("case-a", 3)
BRANCH_B = _branch("case-b", 6)
BRANCH_C = _branch("case-c", 2)


def _bundle_for_branch(branch):
    return _public_objects(
        branch[1]["id"],
        "indicator--not-a-real-uuid",
    ) + branch


def _policy(version="2026.11-a", extra_rules=()):
    public = _public_objects(
        BRANCH_A[1]["id"],
        "indicator--not-a-real-uuid",
    )
    rules = [
        SubjectGrant("group-a-case-a", ["group-a"], ["case-a"]),
        SubjectGrant("group-b-case-b", ["group-b"], ["case-b"]),
        ObjectAssignment(
            "public-objects",
            PublicCase,
            [obj["id"] for obj in public],
        ),
        ObjectAssignment(
            "case-a-objects",
            "case-a",
            [obj["id"] for obj in BRANCH_A],
        ),
        ObjectAssignment(
            "case-b-objects",
            "case-b",
            [obj["id"] for obj in BRANCH_B],
        ),
        ObjectAssignment(
            "case-c-objects",
            "case-c",
            [obj["id"] for obj in BRANCH_C],
        ),
    ]
    rules.extend(extra_rules)
    return DistributionPolicy(version, rules)


def _assert_receiver_views_equal(left, right):
    assert left.summary() == right.summary()
    assert left.references() == right.references()
    assert left.to_bundle() == right.to_bundle()

    for page_size in (1, 2, 3, 5, 100, None):
        left_pages = [page.to_dict() for page in left.pages(page_size)]
        right_pages = [page.to_dict() for page in right.pages(page_size)]
        assert left_pages == right_pages

    assert left.page(1, 2).to_dict() == right.page(1, 2).to_dict()


def test_public_case_alias_is_exported():
    assert PUBLIC_CASE == "public"
    assert PublicCase == PUBLIC_CASE


def test_unauthorized_view_is_identical_after_private_branch_swap():
    policy = _policy()
    summary_a = LocalBundleSummary(_bundle_for_branch(BRANCH_A), policy)
    summary_b = LocalBundleSummary(_bundle_for_branch(BRANCH_B), policy)

    _assert_receiver_views_equal(
        summary_a.view("outsider"),
        summary_b.view("outsider"),
    )

    serialized = json.dumps(summary_a.export("outsider"), sort_keys=True)
    for private_obj in BRANCH_A + BRANCH_B:
        assert private_obj["id"] not in serialized

    switch_policy = _policy(
        "2026.11-b",
        extra_rules=[
            SubjectGrant("group-a-case-b", ["group-a"], ["case-b"]),
        ],
    )
    notice_a = summary_a.switch(
        switch_policy, "outsider",
    ).receiver_notice().to_dict()
    notice_b = summary_b.switch(
        switch_policy, "outsider",
    ).receiver_notice().to_dict()
    assert notice_a == notice_b
    assert notice_a["changed"] is False

    audit_a = summary_a.switch(switch_policy, "outsider").audit().to_dict()
    audit_b = summary_b.switch(switch_policy, "outsider").audit().to_dict()
    assert audit_a == audit_b


def test_receiver_summary_pagination_and_references_only_use_visible_objects():
    policy = _policy()
    summary = LocalBundleSummary(_bundle_for_branch(BRANCH_A), policy)
    view = summary.view("outsider")

    assert summary.external_summary("outsider") == view.summary()
    assert view.summary()["total"] == len(_public_objects(
        BRANCH_A[1]["id"],
        "indicator--not-a-real-uuid",
    ))

    page = view.page(1, page_size=2)
    assert page.total == view.summary()["total"]
    assert page.page_count == 3
    assert len(page.items) == 2
    assert page.page == 1
    assert page.has_next is True
    assert page.has_previous is False

    beyond = view.page(20, page_size=2)
    assert beyond.items == []
    assert beyond.total == page.total
    assert beyond.page_count == page.page_count
    assert beyond.has_next is False

    assert summary.page(2, 5).to_dict() == view.page(2, 5).to_dict()


def test_empty_view_still_has_stable_pagination_metadata():
    policy = DistributionPolicy("empty")
    view = LocalBundleSummary([], policy).view("outsider")

    page = view.page(1, 10)
    assert page.to_dict() == {
        "items": [],
        "page": 1,
        "page_size": 10,
        "total": 0,
        "page_count": 0,
        "has_next": False,
        "has_previous": False,
    }
    assert list(view.pages(10)) == []
    assert view.page(1, None).to_dict()["page_size"] == 1


def test_visible_nodes_keep_content_and_visible_refs():
    policy = _policy()
    view = LocalBundleSummary(_bundle_for_branch(BRANCH_A), policy).view(
        "outsider",
    )

    report = view.object(_id("report", "public-report"))
    assert report is not None
    assert report["name"] == "Public Report"
    assert report["published"] == "2026-11-01T00:00:00Z"
    assert report["object_refs"] == [PUBLIC_INDICATOR["id"]]
    assert "x_dangling_ref" not in report

    relationship = view.object(PUBLIC_RELATIONSHIP["id"])
    assert relationship is not None
    assert relationship["source_ref"] == PUBLIC_INDICATOR["id"]
    assert relationship["target_ref"] == PUBLIC_MALWARE["id"]

    empty_refs = view.object(_id("identity", "empty-refs"))
    assert empty_refs is not None
    assert empty_refs["x_refs"] == []

    assert view.object(BRANCH_A[-1]["id"]) is None


def test_two_case_groups_only_see_their_own_branch():
    policy = _policy()
    summary = LocalBundleSummary(
        _bundle_for_branch(BRANCH_A) + BRANCH_B,
        policy,
    )

    group_a_ids = summary.view("group-a").ids
    group_b_ids = summary.view("group-b").ids

    for obj in BRANCH_A:
        assert obj["id"] in group_a_ids
        assert obj["id"] not in group_b_ids
    for obj in BRANCH_B:
        assert obj["id"] in group_b_ids
        assert obj["id"] not in group_a_ids


def test_hidden_missing_and_malformed_refs_are_indistinguishable():
    hidden_target = BRANCH_A[1]
    visible = _identity("ref-source", "Ref Source")

    with_hidden = dict(visible)
    with_hidden["x_object_ref"] = hidden_target["id"]
    with_hidden["x_object_refs"] = [hidden_target["id"]]
    with_hidden["x_nested"] = {
        "marking_ref": hidden_target["id"],
        "value": "private",
    }

    with_missing = dict(visible)
    with_missing["x_object_ref"] = "indicator--deadbeef"
    with_missing["x_object_refs"] = ["not-an-id", "indicator--deadbeef"]
    with_missing["x_nested"] = {
        "marking_ref": "marking-definition--deadbeef",
        "value": "private",
    }

    rules = [
        ObjectAssignment("visible", PUBLIC_CASE, [visible["id"]]),
        ObjectAssignment("hidden", "case-a", [hidden_target["id"]]),
    ]
    policy = DistributionPolicy("refs", rules)

    summary_hidden = local_summary([with_hidden], policy)
    summary_missing = local_summary([with_missing], policy)

    assert (
        summary_hidden.view("outsider").objects
        == summary_missing.view("outsider").objects
    )
    assert (
        summary_hidden.references("outsider")
        == summary_missing.references("outsider")
    )


def test_edge_objects_with_unresolved_endpoints_are_dropped_recursively():
    public = _identity("edge-public", "Edge Public")
    hidden = _identity("edge-hidden", "Edge Hidden")
    edge_one = _relationship("edge-one", public["id"], hidden["id"])
    edge_two = _relationship("edge-two", public["id"], edge_one["id"])

    policy = DistributionPolicy(
        "edges",
        [
            ObjectAssignment(
                "public",
                PUBLIC_CASE,
                [public["id"], edge_one["id"], edge_two["id"]],
            ),
            ObjectAssignment("hidden", "case-a", [hidden["id"]]),
        ],
    )

    view = LocalBundleSummary(
        [public, hidden, edge_one, edge_two],
        policy,
    ).view("outsider")

    assert view.ids == frozenset({public["id"]})
    assert view.references() == []


def test_hidden_granular_markings_are_removed_without_hiding_visible_ones():
    visible_marking = _common(
        "marking-definition",
        "visible-marking",
        "Visible Marking",
    )
    hidden_marking = _common(
        "marking-definition",
        "hidden-marking",
        "Hidden Marking",
    )
    identity = _identity("granular", "Granular")
    identity["granular_markings"] = [
        {
            "marking_ref": hidden_marking["id"],
            "selectors": ["name"],
        },
        {
            "marking_ref": visible_marking["id"],
            "selectors": ["name"],
        },
    ]

    policy = DistributionPolicy(
        "markings",
        [
            ObjectAssignment(
                "public",
                PUBLIC_CASE,
                [identity["id"], visible_marking["id"]],
            ),
            ObjectAssignment(
                "hidden",
                "case-a",
                [hidden_marking["id"]],
            ),
        ],
    )

    view = LocalBundleSummary(
        [identity, visible_marking, hidden_marking],
        policy,
    ).view("outsider")

    assert view.object(identity["id"])["granular_markings"] == [
        {
            "marking_ref": visible_marking["id"],
            "selectors": ["name"],
        },
    ]


def test_policy_switch_separates_receiver_notice_from_internal_audit():
    old_policy = _policy("2026.11-a")
    new_policy = _policy(
        "2026.11-b",
        extra_rules=[
            SubjectGrant("group-a-case-b", ["group-a"], ["case-b"]),
        ],
    )
    summary = LocalBundleSummary(
        _bundle_for_branch(BRANCH_A) + BRANCH_B + BRANCH_C,
        old_policy,
    )
    switch = summary.switch(new_policy, "group-a")

    notice = switch.receiver_notice()
    assert notice.changed is True
    assert set(notice.added_ids) == {obj["id"] for obj in BRANCH_B}
    assert notice.removed_ids == ()

    notice_dict = notice.to_dict()
    serialized = json.dumps(notice_dict, sort_keys=True)
    for obj in BRANCH_C:
        assert obj["id"] not in serialized
    assert "group-a-case-b" not in serialized
    assert "2026.11-b" not in serialized
    assert notice_dict["summary_before"] != notice_dict["summary_after"]

    audit = switch.audit()
    assert audit.changed_rule_ids == ("group-a-case-b",)
    assert [rule.rule_id for rule in audit.added] == ["group-a-case-b"]
    assert audit.removed == []
    assert audit.modified == []
    assert "group-a" in audit.changed_subjects
    assert "case-b" in audit.changed_cases
    assert audit.is_empty is False

    unchanged = summary.switch(new_policy, "group-b").receiver_notice()
    assert unchanged.changed is False
    assert unchanged.to_dict()["added"] == []
    assert unchanged.to_dict()["removed"] == []


def test_policy_switch_reports_removal_and_updated_visible_objects():
    old_policy = _policy("2026.11-a")
    new_rules = [
        rule for rule in old_policy.rules
        if rule.rule_id != "group-a-case-a"
    ]
    new_policy = DistributionPolicy("2026.11-b", new_rules)
    summary = LocalBundleSummary(
        _bundle_for_branch(BRANCH_A) + BRANCH_B + BRANCH_C,
        old_policy,
    )

    notice = summary.switch(new_policy, "group-a").receiver_notice()
    assert set(notice.removed_ids) == {obj["id"] for obj in BRANCH_A}
    assert _id("report", "public-report") in notice.updated_ids
    assert notice.added_ids == ()

    serialized = json.dumps(notice.to_dict(), sort_keys=True)
    for obj in BRANCH_B + BRANCH_C:
        assert obj["id"] not in serialized

    audit = summary.switch(new_policy, "group-a").audit()
    assert [rule.rule_id for rule in audit.removed] == ["group-a-case-a"]


def test_policy_audit_reports_modified_rules():
    old_policy = _policy("2026.11-a")
    moved_id = BRANCH_A[1]["id"]
    new_rules = [
        rule for rule in old_policy.rules
        if rule.rule_id != "case-a-objects"
    ]
    new_rules.append(
        ObjectAssignment(
            "case-a-objects",
            "case-c",
            [
                obj["id"] for obj in BRANCH_A
                if obj["id"] != moved_id
            ],
        ),
    )
    new_rules.append(
        ObjectAssignment("case-c-moved", "case-c", [moved_id]),
    )
    new_policy = DistributionPolicy("2026.11-b", new_rules)

    audit = audit_policy_change(old_policy, new_policy)
    assert audit.changed_rule_ids == ("case-a-objects", "case-c-moved")
    assert audit.version_changed is True

    modified = audit.to_dict()["modified"]
    assert len(modified) == 1
    assert modified[0]["rule_id"] == "case-a-objects"
    assert moved_id in modified[0]["before"]["object_ids"]
    assert moved_id not in modified[0]["after"]["object_ids"]
    assert [rule.rule_id for rule in audit.added] == ["case-c-moved"]
    assert "case-c" in audit.changed_cases

    assert old_policy.diff(old_policy).is_empty is True
    assert old_policy.compare(new_policy).changed_rule_ids


def test_policy_round_trip_and_validation():
    policy = _policy()
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
    with pytest.raises(ValueError):
        LocalBundleSummary([], policy).view("x").page(0)
    with pytest.raises(ValueError):
        LocalBundleSummary([], policy).view("x").page(1, 0)


def test_stix_objects_and_bundle_export_normalize_datetimes():
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
    bundle = stix2.Bundle(objects=[identity, indicator, relationship])
    policy = DistributionPolicy(
        "stix-objects",
        [
            ObjectAssignment(
                "public",
                PUBLIC_CASE,
                [identity, indicator, relationship],
            ),
        ],
    )

    summary = LocalBundleSummary(bundle, policy)
    view = summary.view(identity)
    assert view.summary()["total"] == 3
    assert {
        ref["target_id"] for ref in view.references()
    } == {identity.id, indicator.id}

    exported = summary.export("outsider")
    assert exported["type"] == "bundle"
    assert len(exported["objects"]) == 3
    assert isinstance(exported["objects"][0]["created"], str)
    json.dumps(exported)


def test_ambiguous_same_timestamp_versions_fail_closed():
    first = _identity("duplicate", "First")
    second = dict(first)
    second["name"] = "Second"

    with pytest.raises(ValueError):
        LocalBundleSummary([first, second], DistributionPolicy("v"))
