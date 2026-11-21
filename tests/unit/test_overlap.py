from __future__ import unicode_literals

from cpe.overlap import (
    ANY,
    NA,
    MISSING,
    STATUS_DISJOINT,
    STATUS_OVERLAP,
    STATUS_REVIEW,
    Domain,
    Rule,
    RuleOverlapChecker,
    check_overlap,
    find_witness,
    rules_overlap,
)


DOMAIN = {
    "vendor": ["acme", "globex"],
    "product": ["gateway", "client"],
    "version": ["1.0", "1.0.0", "2.0"],
    "edition": ["standard", "enterprise"],
}


def test_version_spelling_variants_are_disjoint():
    left = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": "standard",
    }
    right = dict(left, version="1.0.0")

    result = check_overlap(left, right, DOMAIN)

    assert result.status == STATUS_DISJOINT
    assert result.overlaps is False
    assert result.requires_decision is False
    assert result.needs_review is False
    assert result.witness is None
    assert result.disjoint_attributes() == ["version"]
    assert "'1.0'" in result.explanation
    assert "'1.0.0'" in result.explanation
    assert "literal string" in result.explanation
    assert "No policy decision is required" in result.explanation


def test_substantive_overlap_has_witness_and_requires_decision():
    left = {
        "vendor": "acme",
        "product": "gateway",
        "version": ANY,
        "edition": ANY,
    }
    right = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": "standard",
    }

    result = check_overlap(left, right, DOMAIN)

    assert result.status == STATUS_OVERLAP
    assert result.overlaps is True
    assert result.requires_decision is True
    assert result.needs_review is False
    assert result.witness_display == {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": "standard",
    }
    assert "Common asset found" in result.explanation
    assert "human must decide" in result.explanation
    assert rules_overlap(left, right, DOMAIN) is True
    assert find_witness(left, right, DOMAIN) == result.witness


def test_any_na_and_missing_are_not_the_same_value():
    domain = {
        "vendor": ["acme"],
        "product": ["gateway"],
        "version": ["1.0"],
        "edition": ["standard", NA],
    }
    base = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
    }

    any_result = check_overlap(
        dict(base, edition=ANY), dict(base, edition="standard"), domain)
    na_result = check_overlap(
        dict(base, edition=NA), dict(base, edition=NA), domain)
    any_na_result = check_overlap(
        dict(base, edition=ANY), dict(base, edition=NA), domain)
    missing_result = check_overlap(
        dict(base, edition=MISSING), dict(base, edition=ANY), domain)

    assert any_result.status == STATUS_OVERLAP
    assert any_result.witness_display["edition"] == "standard"
    assert na_result.status == STATUS_OVERLAP
    assert na_result.witness_display["edition"] == "NA"
    assert any_na_result.status == STATUS_OVERLAP
    assert any_na_result.witness_display["edition"] == "NA"
    assert missing_result.status == STATUS_REVIEW
    assert missing_result.needs_review is True
    assert missing_result.requires_decision is False
    assert missing_result.witness is None
    assert missing_result.unresolved_attributes() == ["edition"]


def test_na_does_not_match_a_concrete_value():
    left = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": NA,
    }
    right = dict(left, edition="standard")

    result = check_overlap(left, right, DOMAIN)

    assert result.status == STATUS_DISJOINT
    assert result.requires_decision is False
    assert result.disjoint_attributes() == ["edition"]


def test_missing_rule_value_is_left_for_review():
    left = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
    }
    right = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": "standard",
    }

    result = check_overlap(left, right, DOMAIN)

    assert result.status == STATUS_REVIEW
    assert result.needs_review is True
    assert result.requires_decision is False
    assert result.witness is None
    assert "manual review" in result.explanation


def test_edge_wildcard_can_supply_a_witness():
    left = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.*",
        "edition": ANY,
    }
    right = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": "standard",
    }

    result = check_overlap(left, right, DOMAIN)

    assert result.status == STATUS_OVERLAP
    assert result.witness_display["version"] == "1.0"


def test_wildcard_in_the_middle_is_not_compared_silently():
    domain = {
        "vendor": ["acme"],
        "product": ["gateway"],
        "version": ["1.2.0"],
        "edition": ["standard"],
    }
    left = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.*.0",
        "edition": ANY,
    }
    right = {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.2.0",
        "edition": "standard",
    }

    result = check_overlap(left, right, domain)

    assert result.status == STATUS_REVIEW
    assert result.needs_review is True
    assert result.unresolved_attributes() == ["version"]
    assert "middle of the value" in result.explanation


def test_cpe_names_can_be_used_directly():
    uri = "cpe:/a:acme:gateway:1.0::standard"
    wfn = (
        'wfn:[part="a", vendor="acme", product="gateway", '
        'version="1\\.0", edition="standard"]'
    )

    result = check_overlap(uri, wfn, DOMAIN)

    assert result.status == STATUS_OVERLAP
    assert result.witness_display["version"] == "1.0"
    assert Rule(uri).as_dict()["version"] == "1.0"
    assert Rule(uri).as_dict()["edition"] == "standard"


def test_missing_cpe_attributes_are_missing_not_any():
    rule = Rule("cpe:/a:acme:gateway")

    assert rule.as_dict()["version"] == "MISSING"
    assert rule.as_dict()["edition"] == "MISSING"


def test_correlated_domain_does_not_invent_a_combination():
    domain = [
        {"vendor": "acme", "product": "gateway",
         "version": "1.0", "edition": "standard"},
        {"vendor": "globex", "product": "client",
         "version": "2.0", "edition": "enterprise"},
    ]
    left = {
        "vendor": "acme",
        "product": ANY,
        "version": "1.0",
        "edition": "standard",
    }
    right = {
        "vendor": "acme",
        "product": "client",
        "version": "1.0",
        "edition": "standard",
    }

    result = check_overlap(left, right, domain)

    assert result.status == STATUS_DISJOINT
    assert result.witness is None
    assert result.requires_decision is False


def test_empty_domain_is_reviewed_not_called_disjoint():
    result = check_overlap(
        {"vendor": "acme"},
        {"vendor": "acme"},
        {},
    )

    assert result.status == STATUS_REVIEW
    assert result.needs_review is True
    assert result.witness is None
    assert "empty" in result.explanation


def test_checker_wrapper_and_serialisation():
    checker = RuleOverlapChecker(Domain(DOMAIN))
    result = checker.check(
        {"vendor": "acme", "product": "gateway"},
        {"vendor": "acme", "product": "gateway"},
    )

    assert result.status == STATUS_REVIEW
    payload = result.as_dict()
    assert payload["status"] == STATUS_REVIEW
    assert payload["requires_decision"] is False
    assert payload["needs_review"] is True
