import pytest

from policy_coverage import analyze_policy_table, analyze_policy_tables

DICTIONARY = (
    "dictionary:\n"
    "  operations: [read, write]\n"
    "  subjects: [alice, bob, carol, mallory]\n"
    "  attributes:\n"
    "    level: [low, high]\n"
)


def table(*clauses):
    return DICTIONARY + "clauses:\n" + "".join(clauses)


def test_subset_clause_is_covered():
    report = analyze_policy_table(table(
        "  - id: broad\n"
        "    effect: allow\n"
        "    operation: read\n",
        "  - id: narrow\n"
        "    effect: allow\n"
        "    operation: read\n"
        "    subjects: alice\n"
        "    attributes: {level: low}\n",
    ))
    assert report["status"] == "ok"
    assert report["covered"] == ["narrow"]
    entry = report["clauses"][1]
    assert entry["covered_by"] == ["broad"]


def test_union_coverage_across_clauses():
    report = analyze_policy_table(table(
        "  - id: target\n"
        "    effect: allow\n"
        "    operation: read\n"
        "    subjects: [alice, bob]\n",
        "  - id: part-a\n"
        "    effect: allow\n"
        "    subjects: alice\n",
        "  - id: part-b\n"
        "    effect: allow\n"
        "    subjects: bob\n",
    ))
    assert report["covered"] == ["target"]
    entry = report["clauses"][0]
    assert entry["covered_by"] == ["part-a", "part-b"]


def test_deny_does_not_cover_allow():
    report = analyze_policy_table(table(
        "  - id: allow-read\n"
        "    effect: allow\n"
        "    operation: read\n"
        "    subjects: alice\n",
        "  - id: deny-all\n"
        "    effect: deny\n",
    ))
    entries = {e["id"]: e["verdict"] for e in report["clauses"]}
    assert entries == {"allow-read": "not_covered", "deny-all": "not_covered"}


def test_explicit_deny_covered_by_wider_deny():
    report = analyze_policy_table(table(
        "  - id: deny-all\n"
        "    effect: deny\n",
        "  - id: deny-mallory\n"
        "    effect: deny\n"
        "    subjects: mallory\n",
    ))
    assert report["covered"] == ["deny-mallory"]


def test_null_is_wildcard_not_empty():
    report = analyze_policy_table(table(
        "  - id: null-op\n"
        "    effect: allow\n"
        "    operation: null\n"
        "    subjects: alice\n",
        "  - id: read-alice\n"
        "    effect: allow\n"
        "    operation: read\n"
        "    subjects: alice\n",
        "  - id: write-alice\n"
        "    effect: allow\n"
        "    operation: write\n"
        "    subjects: alice\n",
    ))
    # the explicit-null clause spans both operations, so it is covered
    # by the union of the two specific clauses, and they by it.
    assert sorted(report["covered"]) == ["null-op", "read-alice", "write-alice"]


def test_empty_subject_list_is_trivially_covered():
    report = analyze_policy_table(table(
        "  - id: nobody\n"
        "    effect: allow\n"
        "    subjects: []\n",
    ))
    entry = report["clauses"][0]
    assert entry["verdict"] == "covered"
    assert entry["note"] == "clause denotes an empty set"


@pytest.mark.parametrize("clause", [
    "  - id: bad-op\n    effect: allow\n    operation: delete\n",
    "  - id: bad-attr\n    effect: allow\n    attributes: {owner: alice}\n",
    "  - id: bad-value\n    effect: allow\n    attributes: {level: top}\n",
    "  - id: bad-effect\n    effect: audit\n",
    "  - id: bad-key\n    effect: allow\n    priority: 1\n",
    "  - id: bad-shape\n    effect: allow\n    subjects: {only: [alice]}\n",
    "  - id: bad-type\n    effect: allow\n    operation: 2020-01-01\n",
])
def test_unsupported_expressions_degrade_to_undetermined(clause):
    report = analyze_policy_table(table(clause))
    assert report["status"] == "ok"
    entry = report["clauses"][0]
    assert entry["verdict"] == "undetermined"
    assert entry["reason"]


def test_undetermined_clause_neither_covers_nor_is_covered():
    report = analyze_policy_table(table(
        "  - id: broken\n"
        "    effect: allow\n"
        "    operation: delete\n",
        "  - id: specific\n"
        "    effect: allow\n"
        "    operation: read\n"
        "    subjects: alice\n",
    ))
    entries = {e["id"]: e["verdict"] for e in report["clauses"]}
    assert entries == {"broken": "undetermined", "specific": "not_covered"}


def test_source_lines_are_preserved():
    report = analyze_policy_table(table(
        "  - id: first\n"
        "    effect: allow\n"
        "    operation: read\n",
        "  - id: second\n"
        "    effect: deny\n",
    ))
    first, second = report["clauses"]
    assert first["lines"]["start"]["line"] == 7
    assert second["lines"]["start"]["line"] == 10
    assert second["lines"]["end"]["line"] > second["lines"]["start"]["line"]


def test_review_hint_for_single_exception_subject_difference():
    report = analyze_policy_table(table(
        "  - id: all-but-mallory\n"
        "    effect: deny\n"
        "    operation: read\n"
        "    subjects: {except: [mallory]}\n",
        "  - id: everyone\n"
        "    effect: deny\n"
        "    operation: read\n",
    ))
    hint = report["review_hint"]
    assert hint is not None
    assert hint["kind"] == "single-exception-subject-difference"
    assert hint["subject"] == "mallory"
    assert hint["only_in"] == "everyone"
    assert hint["affected_lines"] == [7, 11]
    # mallory x read x {low, high}
    assert hint["affected_points"] == 2
    assert [c["id"] for c in hint["clauses"]] == ["all-but-mallory", "everyone"]


def test_no_review_hint_when_pairs_differ_elsewhere():
    report = analyze_policy_table(table(
        "  - id: a\n"
        "    effect: allow\n"
        "    operation: read\n",
        "  - id: b\n"
        "    effect: allow\n"
        "    operation: write\n",
    ))
    assert report["review_hint"] is None


def test_two_table_interface():
    table_a = table(
        "  - id: broad\n    effect: allow\n",
        "  - id: narrow\n    effect: allow\n    subjects: alice\n",
    )
    table_b = table(
        "  - id: solo\n    effect: deny\n    subjects: bob\n",
    )
    report = analyze_policy_tables(table_a, table_b, names=("a", "b"))
    assert [t["name"] for t in report["tables"]] == ["a", "b"]
    assert report["tables"][0]["covered"] == ["narrow"]
    assert report["tables"][1]["covered"] == []


def test_unparseable_yaml_degrades_whole_table():
    report = analyze_policy_table("clauses: [unclosed\n")
    assert report["status"] == "undetermined"
    assert "reason" in report


def test_malformed_dictionary_degrades_whole_table():
    report = analyze_policy_table(
        "dictionary:\n  operations: read\nclauses: []\n"
    )
    assert report["status"] == "undetermined"
