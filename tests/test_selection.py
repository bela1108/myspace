import random

import pytest

from sigma.exceptions import SigmaSelectionError
from sigma.rule import SigmaRule
from sigma.selection import (
    RuleCandidate,
    SigmaRuleSelector,
    brute_force_select,
    select_rules,
    select_rules_exhaustive,
    select_rules_greedy,
)


def make_rule(title, tags, fields, *, rule_id=None, status="stable", logsource=None):
    return SigmaRule.from_dict(
        {
            "title": title,
            "id": rule_id or str(random_uuid(title)),
            "logsource": logsource or {"product": "windows"},
            "detection": {"selection": {field: 1 for field in fields}, "condition": "selection"},
            "tags": tags,
            "status": status,
        }
    )


def random_uuid(seed):
    from uuid import NAMESPACE_DNS, uuid5

    return uuid5(NAMESPACE_DNS, f"sigma-selection-{seed}")


def test_shared_fields_are_charged_once_and_budget_is_respected():
    first = make_rule("first", ["attack.a", "attack.b"], ["A", "B"])
    second = make_rule("second", ["attack.b", "attack.c"], ["B", "C"])
    costs = {"A": 3, "B": 2, "C": 4}

    selection = select_rules([first, second], ["attack.a", "attack.b", "attack.c"], costs, 9)

    assert selection.selected_keys == (str(first.id), str(second.id))
    assert selection.covered_risks == frozenset({"attack.a", "attack.b", "attack.c"})
    assert selection.total_cost == 9
    assert selection.used_fields == frozenset({"A", "B", "C"})

    smaller = select_rules([first, second], ["attack.a", "attack.b", "attack.c"], costs, 8)
    assert smaller.selected_keys == (str(first.id),)
    assert smaller.total_cost == 5
    assert smaller.uncovered_risks["attack.c"].startswith("budget")


def test_score_sorted_selection_fails_on_shared_field_sample():
    # R1 has the highest standalone coverage, but R2 plus R3 covers the same risks for
    # the same budget because R1 and R3 share f1. R2 looks even better by risk/cost.
    candidates = [
        RuleCandidate(reference="r1", risks={"A", "B"}, fields={"f1"}),
        RuleCandidate(reference="r2", risks={"A"}, fields={"f2"}),
        RuleCandidate(reference="r3", risks={"C"}, fields={"f1"}),
    ]
    costs = {"f1": 4, "f2": 1}
    required = {"A", "B", "C"}

    greedy = select_rules_greedy(candidates, required, costs, 4)
    exact = select_rules(candidates, required, costs, 4)
    exhaustive = select_rules_exhaustive(candidates, required, costs, 4)
    brute = brute_force_select(candidates, required, costs, 4)

    assert greedy.selected_keys == ("r2",)
    assert greedy.covered_risks == frozenset({"A"})
    assert set(greedy.uncovered_risks) == {"B", "C"}
    assert exact.selected_keys == ("r1", "r3")
    assert exhaustive.selected_keys == exact.selected_keys == brute.selected_keys
    assert exhaustive.covered_risks == exact.covered_risks == required
    assert exhaustive.total_cost == exact.total_cost == 4


def test_related_rules_are_atomic():
    first = RuleCandidate(reference="r1", risks={"A"}, fields={"f1"})
    second = RuleCandidate(reference="r2", risks={"B"}, fields={"f2"})

    too_small = select_rules(
        [first, second], {"A", "B"}, {"f1": 1, "f2": 1}, 1, groups=[["r1", "r2"]]
    )
    assert too_small.selected_keys == ()
    assert set(too_small.uncovered_risks) == {"A", "B"}

    fits = select_rules([first, second], {"A", "B"}, {"f1": 1, "f2": 1}, 2, groups=[["r1", "r2"]])
    assert fits.selected_keys == ("r1", "r2")
    assert fits.covered_risks == frozenset({"A", "B"})
    assert fits.total_cost == 2


def test_invalid_rule_blocks_its_related_delivery_group():
    good = make_rule("good", ["attack.a"], ["A"])
    tag_only = SigmaRule.from_dict(
        {"title": "tag-only", "id": str(random_uuid("tag-only")), "tags": ["attack.b"]},
        collect_errors=True,
    )

    selection = select_rules(
        [good, tag_only],
        {"attack.a"},
        {"A": 1},
        10,
        groups=[[str(good.id), str(tag_only.id)]],
    )

    assert selection.selected_keys == ()
    assert selection.diagnostics[0].reason == "related_group"
    assert "no detection logic" in selection.uncovered_risks["attack.a"]


def test_tag_only_invalid_rule_never_counts_as_coverage():
    selection = select_rules(
        [{"title": "tag-only", "tags": ["attack.a", "attack.b"]}],
        {"attack.a", "attack.b"},
        {},
        100,
    )

    assert selection.selected == []
    assert selection.selected_rules == []
    assert set(selection.uncovered_risks) == {"attack.a", "attack.b"}
    assert all(diagnostic.reason == "invalid_candidate" for diagnostic in selection.diagnostics)
    assert "no detection" in selection.uncovered_risks["attack.a"]


def test_missing_collection_conditions_make_rule_undeliverable():
    rule = make_rule("dns", ["attack.a"], ["A"])
    candidate = RuleCandidate(rule=rule, collection_conditions=frozenset({"dns"}))

    missing = select_rules(
        [candidate],
        {"attack.a"},
        {"A": 1},
        10,
        available_collection_conditions={"proxy"},
    )
    assert missing.selected_keys == ()
    assert missing.diagnostics[0].reason == "collection_conditions"
    assert "dns" in missing.uncovered_risks["attack.a"]

    available = select_rules(
        [candidate],
        {"attack.a"},
        {"A": 1},
        10,
        available_collection_conditions={"dns"},
    )
    assert available.selected_keys == (str(rule.id),)


def test_missing_required_logsource_attribute_is_a_collection_gap():
    rule = make_rule(
        "category-only", ["attack.a"], ["A"], logsource={"category": "process_creation"}
    )
    selection = select_rules(
        [rule],
        {"attack.a"},
        {"A": 1},
        10,
        required_logsource_fields={"product"},
    )

    assert selection.selected_keys == ()
    assert selection.diagnostics[0].reason == "collection_conditions"
    assert "logsource.product" in selection.uncovered_risks["attack.a"]


def test_only_fields_referenced_by_the_condition_are_charged():
    rule = SigmaRule.from_dict(
        {
            "title": "unused block",
            "id": str(random_uuid("unused-block")),
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"A": 1},
                "unused": {"Z": 2},
                "condition": "selection",
            },
            "tags": ["attack.a"],
            "status": "stable",
        }
    )

    selection = select_rules([rule], {"attack.a"}, {"A": 2, "Z": 100}, 10)

    assert selection.selected_keys == (str(rule.id),)
    assert selection.total_cost == 2
    assert selection.used_fields == frozenset({"A"})


def test_unpriced_fields_are_rejected_by_default():
    rule = make_rule("unpriced", ["attack.a"], ["A"])

    strict = select_rules([rule], {"attack.a"}, {}, 10)
    assert strict.selected_keys == ()
    assert "no field cost declared" in strict.uncovered_risks["attack.a"]

    relaxed = select_rules([rule], {"attack.a"}, {}, 10, unknown_field_cost=0)
    assert relaxed.selected_keys == (str(rule.id),)
    assert relaxed.total_cost == 0


def test_deprecated_rules_are_not_delivered():
    rule = make_rule("old", ["attack.a"], ["A"], status="deprecated")

    selection = select_rules([rule], {"attack.a"}, {"A": 1}, 10)

    assert selection.selected_keys == ()
    assert selection.diagnostics[0].reason == "invalid_candidate"
    assert "not deliverable" in selection.uncovered_risks["attack.a"]


def test_group_reference_errors_are_configuration_errors():
    first = RuleCandidate(reference="r1", risks={"A"}, fields={"f1"})
    second = RuleCandidate(reference="r1", risks={"B"}, fields={"f2"})

    with pytest.raises(SigmaSelectionError, match="ambiguous"):
        select_rules([first, second], {"A"}, {"f1": 1, "f2": 1}, 10, groups=[["r1"]])

    with pytest.raises(SigmaSelectionError, match="unknown rule reference"):
        select_rules([first], {"A"}, {"f1": 1}, 10, groups=[["does-not-exist"]])


def test_reusable_selector():
    selector = SigmaRuleSelector(required_risks=("attack.a",), field_costs={"A": 1}, budget=1)
    rule = make_rule("reusable", ["attack.a"], ["A"])

    selection = selector.select([rule])

    assert selection.selected_keys == (str(rule.id),)
    assert selection.total_cost == 1


def test_exact_matches_exhaustive_on_random_small_catalogs():
    rng = random.Random(1234)
    risks = ("A", "B", "C", "D")
    fields = ("f1", "f2", "f3", "f4")

    for _ in range(40):
        candidates = []
        for index in range(rng.randint(1, 6)):
            candidates.append(
                RuleCandidate(
                    reference=f"r{index}",
                    risks={risk for risk in risks if rng.random() < 0.5},
                    fields={field for field in fields if rng.random() < 0.5},
                )
            )
        costs = {field: rng.randint(0, 3) for field in fields}
        required = {risk for risk in risks if rng.random() < 0.7}
        budget = rng.randint(0, 8)

        exact = select_rules(candidates, required, costs, budget)
        exhaustive = select_rules(candidates, required, costs, budget, algorithm="exhaustive")

        assert exact.selected_keys == exhaustive.selected_keys
        assert exact.covered_risks == exhaustive.covered_risks
        assert exact.total_cost == exhaustive.total_cost
