import json
import pytest
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.counting.checker import (
    ContractCheckResult,
    CountingBasis,
    CountingContractChecker,
    CountingVerdict,
)
from sigma.counting.contract import (
    CountingContractError,
    EquivalenceKind,
    FieldEquivalence,
    LogSourceCountingContract,
    LogSourceKey,
    TimePrecision,
    contracts_from_yaml,
)
from sigma.counting.registry import CountingContractRegistry
from sigma.counting.replay import (
    LogicalOperation,
    ReplayScenario,
    ReplayVerdict,
    ScenarioRunner,
)
from sigma.counting.report import CorrelationReportRecord, CountingReport


BASE_RULES = """
title: Privileged operation
name: priv_op
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4672
    condition: selection
---
title: Legacy operation
name: legacy_op
logsource:
    product: windows
    service: generic-legacy
detection:
    selection:
        EventID: 8002
    condition: selection
"""


def _correlation(yaml_text: str) -> tuple[SigmaCollection, SigmaCorrelationRule]:
    collection = SigmaCollection.from_yaml(BASE_RULES + "---\n" + yaml_text)
    correlation = next(rule for rule in collection.rules if isinstance(rule, SigmaCorrelationRule))
    correlation.resolve_rule_references(collection)
    return collection, correlation


def _registry() -> CountingContractRegistry:
    return CountingContractRegistry.from_yaml(
        """
contracts:
  - logsource: {product: windows, service: security}
    identity_fields: [EventRecordID]
    time_precision: 1s
    equivalences:
      - fields: [RecordId, EventRecordID]
  - logsource: {product: linux}
    identity_fields: [OperationId]
    time_precision: 10s
"""
    )


def _operations() -> list[LogicalOperation]:
    return [
        LogicalOperation(1, 0, {"User": "alice"}),
        LogicalOperation(2, 30, {"User": "bob"}),
        LogicalOperation(3, 75, {"User": "alice"}),
    ]


class TestTimePrecision:
    def test_parse_units(self):
        assert TimePrecision("500ms").seconds == pytest.approx(0.5)
        assert TimePrecision("1s").seconds == 1
        assert TimePrecision("2m").seconds == 120

    def test_invalid(self):
        with pytest.raises(CountingContractError):
            TimePrecision("banana")
        with pytest.raises(CountingContractError):
            TimePrecision("0s")


class TestFieldEquivalence:
    def test_rename_resolution(self):
        equivalence = FieldEquivalence(("RecordId", "EventRecordID"))
        assert equivalence.kind is EquivalenceKind.RENAME
        assert equivalence.other("RecordId") == "EventRecordID"

    def test_rejects_same_field(self):
        with pytest.raises(CountingContractError):
            FieldEquivalence(("x", "x"))

    def test_bijective_requires_transform(self):
        with pytest.raises(CountingContractError):
            FieldEquivalence(("a", "b"), kind=EquivalenceKind.BIJECTIVE_TRANSFORM)


class TestContract:
    def test_requires_identity(self):
        with pytest.raises(CountingContractError):
            LogSourceCountingContract(
                logsource=LogSourceKey(product="windows"),
                identity_fields=(),
                time_precision=TimePrecision("1s"),
            )

    def test_canonical_identity_via_equivalence(self):
        contract = contracts_from_yaml(
            """
- logsource: {product: windows, service: security}
  identity_fields: [EventRecordID]
  time_precision: 1s
  equivalences:
    - fields: [RecordId, EventRecordID]
"""
        )[0]
        assert contract.canonical_identity("RecordId") == "EventRecordID"
        assert contract.proves_identity("EventRecordID")
        assert not contract.proves_identity("Unrelated")

    def test_conflicting_equivalence_rejected(self):
        with pytest.raises(CountingContractError):
            LogSourceCountingContract(
                logsource=LogSourceKey(service="s"),
                identity_fields=("id",),
                time_precision=TimePrecision("1s"),
                equivalences=(
                    FieldEquivalence(("a", "id")),
                    FieldEquivalence(("a", "other")),
                ),
            )


class TestRegistry:
    def test_specificity_and_miss(self):
        registry = _registry()
        from sigma.rule.logsource import SigmaLogSource

        specific = registry.lookup(SigmaLogSource(product="windows", service="security"))
        assert specific is not None
        assert specific.identity_fields == ("EventRecordID",)

        fallback = registry.lookup(SigmaLogSource(product="linux", service="other"))
        assert fallback is not None
        assert fallback.identity_fields == ("OperationId",)

        assert registry.lookup(SigmaLogSource(product="windows", service="other")) is None


class TestChecker:
    def test_determined_count_based_branch(self):
        _, rule = _correlation("""
title: Count rule
name: count_rule
correlation:
    type: event_count
    rules: priv_op
    group-by: [User]
    timespan: 10m
    condition: {gte: 2}
""")
        result = CountingContractChecker(_registry()).check(rule)
        assert isinstance(result, ContractCheckResult)
        assert result.basis is CountingBasis.EVENT_COUNT
        assert result.verdict is CountingVerdict.DETERMINED
        assert result.branch_verdicts[0].identity_fields == ("EventRecordID",)

    def test_missing_contract_branch_makes_rule_undetermined_and_locatable(self):
        _, rule = _correlation("""
title: Temporal rule
name: temporal_rule
correlation:
    type: temporal
    rules: [priv_op, legacy_op]
    timespan: 15m
    condition: {gte: 2}
""")
        result = CountingContractChecker(_registry()).check(rule)
        assert result.verdict is CountingVerdict.UNDETERMINED
        undetermined = result.undetermined_branches
        assert [branch.branch for branch in undetermined] == ["legacy_op"]
        assert undetermined[0].logsource.service == "generic-legacy"
        assert "No counting contract" in undetermined[0].reason
        assert "legacy_op" in result.to_dict()["undetermined_branches"]

    def test_group_by_field_need_not_be_identity(self):
        # Counting distinct users must stay determined even though User is not
        # an identity field; de-duplication happens on the event identity.
        _, rule = _correlation("""
title: Value rule
name: value_rule
correlation:
    type: value_count
    rules: priv_op
    timespan: 10m
    condition:
        field: User
        gte: 2
""")
        result = CountingContractChecker(_registry()).check(rule)
        assert result.basis is CountingBasis.UNIQUE_VALUE
        assert result.verdict is CountingVerdict.DETERMINED

    def test_coarse_time_precision_undetermined(self):
        registry = CountingContractRegistry.from_yaml("""
contracts:
  - logsource: {product: windows, service: security}
    identity_fields: [EventRecordID]
    time_precision: 1h
""")
        _, rule = _correlation("""
title: Short window
name: short_window
correlation:
    type: event_count
    rules: priv_op
    timespan: 1m
    condition: {gte: 1}
""")
        result = checker = CountingContractChecker(registry).check(rule)
        assert result.verdict is CountingVerdict.UNDETERMINED
        assert "coarser" in result.branch_verdicts[0].reason


class TestReplay:
    @pytest.fixture
    def contract(self):
        return _registry().require(
            LogSourceKey(product="windows", service="security")
        )

    @pytest.fixture
    def count_rule(self):
        _, rule = _correlation("""
title: Burst
name: burst
correlation:
    type: event_count
    rules: priv_op
    timespan: 10m
    condition: {gte: 5}
""")
        return rule

    @pytest.fixture
    def value_rule(self):
        _, rule = _correlation("""
title: Distinct users
name: distinct_users
correlation:
    type: value_count
    rules: priv_op
    timespan: 10m
    condition:
        field: User
        gte: 3
""")
        return rule

    def test_single_dual_missing_scenarios_count(self, contract, count_rule):
        runner = ScenarioRunner(contract)
        outcomes = {o.scenario: o for o in runner.run_all(count_rule, _operations())}

        single = outcomes[ReplayScenario.SINGLE_WRITE]
        assert single.raw_events == 3
        assert single.dedup_count == 3
        assert single.verdict is ReplayVerdict.DETERMINED
        assert single.naive_alert is False

        dual = outcomes[ReplayScenario.DUAL_WRITE]
        assert dual.raw_events == 6
        assert dual.dedup_count == 3
        assert dual.naive_alert is True
        assert dual.contract_alert is False

        missing = outcomes[ReplayScenario.MISSING_IDENTITY]
        assert missing.raw_events == 3
        assert missing.dedup_count is None
        assert missing.contract_alert is None
        assert missing.verdict is ReplayVerdict.UNDETERMINED

    def test_dual_write_does_not_inflate_unique_values(self, contract, value_rule):
        runner = ScenarioRunner(contract)
        outcomes = {o.scenario: o for o in runner.run_all(value_rule, _operations())}
        dual = outcomes[ReplayScenario.DUAL_WRITE]
        assert dual.raw_events == 6
        assert dual.unique_values == 2
        assert dual.naive_alert == dual.contract_alert

    def test_missing_identity_unique_value_undetermined(self, contract, value_rule):
        runner = ScenarioRunner(contract)
        outcome = runner.run(value_rule, _operations(), ReplayScenario.MISSING_IDENTITY)
        assert outcome.verdict is ReplayVerdict.UNDETERMINED
        assert outcome.contract_alert is None


class TestReport:
    def test_report_separates_bases_and_attributes_threshold_change(self):
        registry = _registry()
        checker = CountingContractChecker(registry)
        _, count_rule = _correlation("""
title: Burst
name: burst
correlation:
    type: event_count
    rules: priv_op
    timespan: 10m
    condition: {gte: 5}
""")
        _, value_rule = _correlation("""
title: Distinct users
name: distinct_users
correlation:
    type: value_count
    rules: priv_op
    timespan: 10m
    condition: {field: User, gte: 3}
""")
        security_key = LogSourceKey(product="windows", service="security")
        runner = ScenarioRunner(registry.require(security_key))
        report = CountingReport([
            CorrelationReportRecord(
                checker.check(count_rule), runner.run_all(count_rule, _operations())
            ),
            CorrelationReportRecord(
                checker.check(value_rule), runner.run_all(value_rule, _operations())
            ),
        ])

        assert len(report.count_based) == 1
        assert len(report.unique_value_based) == 1
        payload = report.to_dict()
        assert payload["summary"]["count_based"] == 1
        assert payload["summary"]["unique_value_based"] == 1
        change = report.count_based[0].threshold_changes
        assert len(change) == 1
        assert change[0].scenario is ReplayScenario.DUAL_WRITE
        markdown = report.to_markdown()
        assert "Count-based correlations" in markdown
        assert "Unique-value correlations" in markdown
        assert "Threshold changes" in markdown


class TestCli:
    def test_demo_pipeline_writes_reports(self, tmp_path):
        from sigma.counting import cli

        demo = Path(cli.__file__).parent / "demo"
        json_out = tmp_path / "report.json"
        markdown_out = tmp_path / "report.md"
        exit_code = cli.main([
            "--base-rules", str(demo / "base_rules.yml"),
            "--correlation-rules", str(demo / "correlation_rules.yml"),
            "--contracts", str(demo / "contracts.yml"),
            "--operations", str(demo / "operations.yml"),
            "--json-out", str(json_out),
            "--markdown-out", str(markdown_out),
        ])
        assert exit_code == 0
        payload = json.loads(json_out.read_text(encoding="utf-8"))
        assert payload["summary"]["undetermined"] == 1
        assert payload["summary"]["count_based"] == 3
        assert payload["summary"]["unique_value_based"] == 1
        markdown = markdown_out.read_text(encoding="utf-8")
        assert "Count-based correlations" in markdown
        assert "Unique-value correlations" in markdown
