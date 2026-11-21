"""Tests for minimal-field match explanations."""

from datetime import datetime, timezone

import pytest

from sigma.collection import SigmaCollection
from sigma.matching import Event, EventLogSource, SigmaMatcher, explain_match
from sigma.matching.compiler import MatchCompiler
from sigma.matching.explanation import ExplanationStatus, MatchExplainer
from sigma.matching.rule_matcher import SigmaRuleMatcher

LOGSOURCE = EventLogSource(category="test", product="test")
TIMESTAMP = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


def make_rule(detection: str, condition: str = "selection") -> object:
    yaml = f"""
title: Explanation Test
name: explanation_test
status: test
logsource:
    category: test
    product: test
detection:
{detection}
    condition: {condition}
"""
    return SigmaCollection.from_yaml(yaml).rules[0]


def make_event(data: dict[str, object], **kwargs: object) -> Event:
    return Event(timestamp=TIMESTAMP, logsource=LOGSOURCE, data=data, **kwargs)


def test_and_explanation_returns_only_required_fields_and_hides_values() -> None:
    rule = make_rule("""    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: 'EncodedCommand'
""")
    event = make_event(
        {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand ZQBjAGgAbwA=",
            "User": "alice",
            "Secret": "hunter2",
        }
    )

    result = explain_match(rule, event)

    assert result.status == ExplanationStatus.EXPLAINED
    assert result.is_conclusive
    assert result.fields == {"CommandLine", "Image"}
    report = result.report()
    assert "CommandLine" in report
    assert "Image" in report
    assert "alice" not in report
    assert "hunter2" not in report
    assert "ZQBjAGgAbwA=" not in report
    assert "alice" not in str(result.to_dict())

    with_values = result.report(include_values=True)
    assert "alice" not in with_values
    assert "ZQBjAGgAbwA=" in with_values


def test_removing_redundant_field_keeps_explanation_and_removing_required_field_loses_it() -> None:
    rule = make_rule("""    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: 'EncodedCommand'
""")
    data = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand ZQBjAGgAbwA=",
        "Noise": "irrelevant",
    }

    initial = explain_match(rule, make_event(data))
    data.pop("Noise")
    without_noise = explain_match(rule, make_event(data))

    assert initial.status == without_noise.status == ExplanationStatus.EXPLAINED
    assert initial.fields == without_noise.fields == {"Image", "CommandLine"}

    data.pop("CommandLine")
    assert explain_match(rule, make_event(data)).status == ExplanationStatus.NO_MATCH


def test_or_alternatives_are_tied_and_each_alternative_is_usable() -> None:
    rule = make_rule(
        """    selection_a:
        A: one
    selection_b:
        B: two
""",
        condition="selection_a or selection_b",
    )
    data = {"A": "one", "B": "two", "Noise": "irrelevant"}

    result = explain_match(rule, make_event(data))
    assert result.status == ExplanationStatus.TIED
    assert result.is_tied
    assert result.status == "ambiguous"
    assert result.minimal_field_sets == (frozenset({"A"}), frozenset({"B"}))

    data.pop("A")
    only_b = explain_match(rule, make_event(data))
    assert only_b.status == ExplanationStatus.EXPLAINED
    assert only_b.fields == {"B"}

    data.pop("B")
    assert explain_match(rule, make_event(data)).status == ExplanationStatus.NO_MATCH


def test_dominated_alternative_is_discarded() -> None:
    rule = make_rule(
        """    selection_a:
        A: one
    selection_b:
        B: two
""",
        condition="(selection_a and selection_b) or selection_a",
    )
    result = explain_match(rule, make_event({"A": "one", "B": "two"}))

    assert result.status == ExplanationStatus.EXPLAINED
    assert result.minimal_field_sets == (frozenset({"A"}),)


def test_negation_is_reported_as_undecidable() -> None:
    rule = make_rule(
        """    selection:
        A: one
    filter:
        B: bad
""",
        condition="selection and not filter",
    )
    result = explain_match(rule, make_event({"A": "one"}))

    assert result.status == ExplanationStatus.UNDECIDABLE
    assert result.status == "unknown"
    assert result.is_undecidable
    assert "negated" in (result.reason or "")


def test_keyword_is_reported_as_undecidable() -> None:
    yaml = """
title: Keyword
name: keyword
status: test
logsource:
    category: test
    product: test
detection:
    keywords:
        - suspicious
    condition: keywords
"""
    rule = SigmaCollection.from_yaml(yaml).rules[0]
    result = explain_match(rule, make_event({"Message": "a suspicious line"}))

    assert result.status == ExplanationStatus.UNDECIDABLE
    assert "keyword" in (result.reason or "")


def test_regular_expression_is_opt_in() -> None:
    rule = make_rule("""    selection:
        Field|re: '^ab+c$'
""")
    event = make_event({"Field": "abbbc"})

    assert explain_match(rule, event).status == ExplanationStatus.UNDECIDABLE
    advanced = explain_match(rule, event, include_advanced_values=True)
    assert advanced.status == ExplanationStatus.EXPLAINED
    assert advanced.fields == {"Field"}


def test_simple_value_types_and_exists() -> None:
    rule = make_rule("""    selection:
        Count: 42
        Enabled: true
        Missing: null
        Present|exists: true
""")
    event = make_event({"Count": 42, "Enabled": True, "Present": "yes"})
    result = explain_match(rule, event)

    assert result.status == ExplanationStatus.EXPLAINED
    assert result.fields == {"Count", "Enabled", "Present"}
    assert "Missing" not in result.report()


def test_non_matching_event_has_no_match_status() -> None:
    rule = make_rule("""    selection:
        A: one
""")
    result = explain_match(rule, make_event({"A": "two"}))

    assert result.status == ExplanationStatus.NO_MATCH
    assert result.status == "not_matched"
    assert not result
    assert result.fields == set()


def test_sigma_matcher_and_match_explain_entries() -> None:
    rule = make_rule("""    selection:
        A: one
""")
    collection = SigmaCollection([rule])
    event = make_event({"A": "one"})

    with SigmaMatcher(collection) as matcher:
        matches = matcher.match(event)
        assert len(matches) == 1
        assert matches[0].explain().fields == {"A"}
        assert matcher.explain(event).fields == {"A"}
        assert matcher.explain(event, "explanation_test").fields == {"A"}


def test_constructor_accepts_rule_and_event() -> None:
    rule = make_rule("""    selection:
        A: one
""")
    result = MatchExplainer(rule, make_event({"A": "one"})).explain()
    assert result.status == ExplanationStatus.EXPLAINED
    assert result.fields == {"A"}


@pytest.mark.parametrize(
    ("value", "field"),
    [
        ("one", "A"),
        (1, "B"),
        (True, "C"),
    ],
)
def test_supported_scalar_values(value: object, field: str) -> None:
    rule = make_rule(f"    selection:\n        {field}: {str(value).lower()}\n")
    assert explain_match(rule, make_event({field: value})).fields == {field}


def test_each_reported_alternative_is_sufficient_and_minimal() -> None:
    rule = make_rule(
        """    selection_a:
        A: one
    selection_b:
        B: two
        C: three
""",
        condition="selection_a or selection_b",
    )
    event = make_event({"A": "one", "B": "two", "C": "three", "Noise": "ignored"})
    result = explain_match(rule, event)
    assert result.status == ExplanationStatus.TIED

    matcher = SigmaRuleMatcher(rule, MatchCompiler())
    for alternative in result.alternatives:
        subset_data = {field: event.data[field] for field in alternative.fields}
        subset = make_event(subset_data)
        assert matcher.matches(subset) is not None
        for field in alternative.fields:
            smaller = {name: value for name, value in subset_data.items() if name != field}
            assert matcher.matches(make_event(smaller)) is None
