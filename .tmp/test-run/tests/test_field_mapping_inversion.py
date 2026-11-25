import copy

from sigma.processing.inversion import (
    FieldMappingInversionStatus,
    check_field_mapping_inversion,
)
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaRule


def make_rule(name: str, product: str, service: str, fields: list[str]) -> SigmaRule:
    return SigmaRule.from_dict(
        {
            "title": name,
            "name": name,
            "logsource": {"product": product, "service": service},
            "detection": {
                "selection": {field: f"{field}-value" for field in fields},
                "condition": "selection",
            },
        }
    )


def test_field_mapping_inversion_reports_reversible_merged_and_uncovered():
    rules = [
        make_rule("reversible-rule", "windows", "security", ["User"]),
        make_rule("merged-rule", "linux", "auth", ["SourceUser", "TargetUser", "SessionId"]),
        make_rule("unmapped-rule", "windows", "sysmon", ["Image"]),
    ]
    original_rules = copy.deepcopy(rules)
    pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                identifier="windows-fields",
                transformation=FieldMappingTransformation(
                    {
                        "User": "user.name",
                        "Image": "process.executable",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
            ProcessingItem(
                identifier="linux-fields",
                transformation=FieldMappingTransformation(
                    {
                        "SourceUser": "user.name",
                        "TargetUser": "user.name",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="linux")],
            ),
        ]
    )

    report = check_field_mapping_inversion(pipeline, rules)

    assert rules == original_rules
    assert [result.source_field for result in report.reversible] == [
        "Image",
        "User",
    ]
    assert all(
        result.status == FieldMappingInversionStatus.REVERSIBLE
        for result in report.reversible
    )
    assert [result.source_field for result in report.merged_irreversible] == [
        "SourceUser",
        "TargetUser",
    ]
    assert all(
        result.status == FieldMappingInversionStatus.MERGED_IRREVERSIBLE
        for result in report.merged_irreversible
    )
    assert [result.source_field for result in report.uncovered] == ["SessionId"]
    assert report.uncovered[0].event_source == "linux/auth"
    assert report.release_blocked is True
    assert [evidence.rule_identifier for evidence in report.blocking_evidence] == [
        "merged-rule",
        "merged-rule",
        "unmapped-rule",
    ]


def test_field_mapping_inversion_separate_event_sources_do_not_block_without_rule_evidence():
    rules = [
        make_rule("windows-user-rule", "windows", "security", ["User"]),
        make_rule("linux-user-rule", "linux", "auth", ["SourceUser"]),
        make_rule("covered-rule", "windows", "sysmon", ["Image"]),
    ]
    pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                identifier="windows-fields",
                transformation=FieldMappingTransformation(
                    {
                        "User": "user.name",
                        "Image": "process.executable",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
            ProcessingItem(
                identifier="linux-fields",
                transformation=FieldMappingTransformation(
                    {"SourceUser": "user.name"}
                ),
                rule_conditions=[LogsourceCondition(product="linux")],
            ),
        ]
    )

    report = pipeline.check_field_mapping_inversion(rules)

    assert report.merged_irreversible == ()
    assert report.uncovered == ()
    assert report.release_blocked is False
    assert report.blocking_evidence == ()
    assert {result.source_field for result in report.reversible} == {
        "Image",
        "SourceUser",
        "User",
    }
