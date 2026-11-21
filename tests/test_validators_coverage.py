import pytest

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssueSeverity
from sigma.validators.core.coverage import (
    LogsourceCoverageValidator,
    LogsourceNoCoverageIssue,
    LogsourcePartialCoverageIssue,
    LogsourceScopeMismatchIssue,
)
from .test_conversion_correlations import event_count_correlation_rule


@pytest.fixture
def file_event_rule():
    return SigmaRule.from_yaml(
        r"""
    title: Suspicious File Drop
    status: test
    logsource:
        category: file_event
        product: windows
    detection:
        selection:
            TargetFilename|endswith: '\Temp\payload.exe'
        proc:
            Image|endswith: '\powershell.exe'
        parent:
            ParentImage|endswith: '\winword.exe'
        condition: selection and (proc or parent)
    """
    )


@pytest.fixture
def partial_logsource_validator():
    """Synthetic log source that misses ParentImage required by an optional alternative."""
    return LogsourceCoverageValidator(
        fields={"TargetFilename": "string", "Image": "string"},
        scope={"category": ["file_event"], "product": ["windows"]},
        logsource_name="edr-file-events",
    )


@pytest.fixture
def blocked_logsource_validator():
    """Synthetic log source that misses TargetFilename required by all alternatives."""
    return LogsourceCoverageValidator(
        fields={"Image": "string", "ParentImage": "string"},
        scope={"category": ["file_event"], "product": ["windows"]},
        logsource_name="basic-file-audit",
    )


def test_logsourcecoveragevalidator_no_description(file_event_rule):
    assert LogsourceCoverageValidator().validate(file_event_rule) == []


def test_logsourcecoveragevalidator_correlation_rule(event_count_correlation_rule):
    correlation_rule = [
        rule
        for rule in event_count_correlation_rule.rules
        if isinstance(rule, SigmaCorrelationRule)
    ][0]
    assert (
        LogsourceCoverageValidator(fields={"field": "string"}).validate(correlation_rule)
        == []
    )


def test_logsourcecoveragevalidator_full_coverage(file_event_rule):
    validator = LogsourceCoverageValidator(
        fields={"TargetFilename": "string", "Image": "string", "ParentImage": "string"},
        scope={"category": ["file_event"], "product": ["windows"]},
    )
    assert validator.validate(file_event_rule) == []


def test_logsourcecoveragevalidator_partial_coverage(file_event_rule, partial_logsource_validator):
    issues = partial_logsource_validator.validate(file_event_rule)
    assert len(issues) == 1
    issue = issues[0]
    assert isinstance(issue, LogsourcePartialCoverageIssue)
    assert issue.severity == SigmaValidationIssueSeverity.MEDIUM
    assert issue.field == "ParentImage"
    assert issue.detection == "parent"
    assert issue.reason == "missing_field"
    assert issue.detection_item is file_event_rule.detection.detections["parent"].detection_items[0]
    assert "ParentImage" in issue.remediation
    assert "partial" in issue.remediation


def test_logsourcecoveragevalidator_no_coverage(file_event_rule, blocked_logsource_validator):
    issues = blocked_logsource_validator.validate(file_event_rule)
    assert len(issues) == 1
    issue = issues[0]
    assert isinstance(issue, LogsourceNoCoverageIssue)
    assert issue.severity == SigmaValidationIssueSeverity.HIGH
    assert issue.field == "TargetFilename"
    assert issue.detection == "selection"
    assert issue.reason == "missing_field"
    assert (
        issue.detection_item
        is file_event_rule.detection.detections["selection"].detection_items[0]
    )
    assert "TargetFilename" in issue.remediation
    assert "partial" not in issue.remediation


def test_logsourcecoveragevalidator_scope_mismatch(file_event_rule):
    validator = LogsourceCoverageValidator(
        fields={"TargetFilename": "string", "Image": "string", "ParentImage": "string"},
        scope={"category": ["process_creation"], "product": ["windows"]},
        logsource_name="process-only-source",
    )
    issues = validator.validate(file_event_rule)
    assert len(issues) == 1
    issue = issues[0]
    assert isinstance(issue, LogsourceScopeMismatchIssue)
    assert issue.severity == SigmaValidationIssueSeverity.HIGH
    assert issue.dimension == "category"
    assert issue.required == "file_event"
    assert issue.collected == ["process_creation"]
    assert "file_event" in issue.remediation


def test_logsourcecoveragevalidator_type_mismatch():
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: file_event
    detection:
        selection:
            TargetFilename: 'payload.exe'
        condition: selection
    """
    )
    validator = LogsourceCoverageValidator(fields={"TargetFilename": "number"})
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], LogsourceNoCoverageIssue)
    assert issues[0].reason == "type_mismatch"
    assert "number" in issues[0].remediation


def test_logsourcecoveragevalidator_optional_type_mismatch():
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: file_event
    detection:
        selection:
            TargetFilename: 'payload.exe'
        size:
            FileSize: 1024
        condition: selection or size
    """
    )
    validator = LogsourceCoverageValidator(
        fields={"TargetFilename": "string", "FileSize": "string"}
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], LogsourcePartialCoverageIssue)
    assert issues[0].reason == "type_mismatch"
    assert issues[0].field == "FileSize"


def test_logsourcecoveragevalidator_pipeline_field_requirements():
    rule = SigmaRule.from_yaml(
        r"""
    title: Test
    status: test
    logsource:
        category: process_creation
    detection:
        selection:
            Image|endswith: '\powershell.exe'
        condition: selection
    """
    )
    pipeline = ProcessingPipeline.from_dict(
        {
            "name": "test",
            "transformations": [
                {"type": "field_name_mapping", "mapping": {"Image": "ProcessName"}}
            ],
        }
    )
    # Without the pipeline the log source misses the required field Image.
    issues = LogsourceCoverageValidator(fields={"ProcessName": "string"}).validate(rule)
    assert len(issues) == 1
    assert issues[0].field == "Image"
    # With the pipeline the field required by the rule is ProcessName, which is collected.
    assert (
        LogsourceCoverageValidator(fields={"ProcessName": "string"}, pipeline=pipeline).validate(
            rule
        )
        == []
    )


def test_logsourcecoveragevalidator_sigma_validator_api(file_event_rule):
    validator = SigmaValidator(
        validators=[LogsourceCoverageValidator],
        config={
            "logsource_coverage": {
                "fields": {"TargetFilename": "string", "Image": "string"},
                "scope": {"category": ["file_event"]},
                "logsource_name": "edr-file-events",
            }
        },
    )
    issues = validator.validate_rule(file_event_rule)
    assert len(issues) == 1
    assert isinstance(issues[0], LogsourcePartialCoverageIssue)
    assert issues[0].field == "ParentImage"


def test_logsourcecoveragevalidator_two_synthetic_logsources_guidance(
    file_event_rule, partial_logsource_validator, blocked_logsource_validator, capsys
):
    """
    Send a file event rule to two synthetic log sources. The rendered output must guide the
    on-call staff which field to add to restore partial or full coverage.
    """
    for validator in (partial_logsource_validator, blocked_logsource_validator):
        for issue in validator.validate(file_event_rule):
            print(issue)
    output = capsys.readouterr().out
    # Partial coverage: adding ParentImage to edr-file-events restores the optional alternative.
    assert "severity=medium" in output
    assert "Add field 'ParentImage' to edr-file-events to restore partial rule coverage" in output
    # No coverage: adding TargetFilename to basic-file-audit restores the whole rule.
    assert "severity=high" in output
    assert "Add field 'TargetFilename' to basic-file-audit to restore rule coverage" in output
    # Issues point back to the source detection items.
    assert "detection=parent" in output
    assert "detection=selection" in output
