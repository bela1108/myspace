import json

import pytest
from packaging.version import Version

import pip_audit._format as report_format
import pip_audit._service as service

_ARCHIVE_ID = "ARCHIVE-2026-0001"
_RESOLVED_NAME = "reviewable-demo"
_RESOLVED_VERSION = "3.1.4"
_FIX_VERSION = "3.1.5"
_SKIPPED_NAME = "missing-version-demo"
_MISSING_REASON = "no reviewable version specified in offline fixture"

_RESOLVED_DEP = service.ResolvedDependency(
    name=_RESOLVED_NAME,
    version=Version(_RESOLVED_VERSION),
)
_SKIPPED_DEP = service.SkippedDependency(
    name=_SKIPPED_NAME,
    skip_reason=_MISSING_REASON,
)
_ARCHIVED_FINDING = service.VulnerabilityResult(
    id=_ARCHIVE_ID,
    description="Offline finding for report field correspondence.",
    fix_versions=[Version(_FIX_VERSION)],
    aliases=set(),
)
_FINDINGS = {
    _RESOLVED_DEP: [_ARCHIVED_FINDING],
    _SKIPPED_DEP: [],
}
_EXPECTED_MACHINE_FIELDS = {
    _RESOLVED_DEP.canonical_name: {
        "name": _RESOLVED_DEP.canonical_name,
        "version": _RESOLVED_VERSION,
        "vulns": [
            {
                "id": _ARCHIVE_ID,
                "fix_versions": [_FIX_VERSION],
            }
        ],
    },
    _SKIPPED_DEP.canonical_name: {
        "name": _SKIPPED_DEP.canonical_name,
        "skip_reason": _MISSING_REASON,
    },
}


@pytest.mark.parametrize(
    "dependency_order",
    [
        (_RESOLVED_DEP, _SKIPPED_DEP),
        (_SKIPPED_DEP, _RESOLVED_DEP),
    ],
)
def test_machine_and_text_reports_keep_fields_aligned_after_reorder(dependency_order):
    result = {dep: _FINDINGS[dep] for dep in dependency_order}

    machine_report = json.loads(
        report_format.JsonFormat(output_desc=False, output_aliases=False).format(result, [])
    )
    expected_dependencies = [
        _EXPECTED_MACHINE_FIELDS[dep.canonical_name] for dep in dependency_order
    ]
    assert machine_report["dependencies"] == expected_dependencies
    machine_by_name = {dep["name"]: dep for dep in machine_report["dependencies"]}
    resolved_machine = machine_by_name[_RESOLVED_DEP.canonical_name]
    skipped_machine = machine_by_name[_SKIPPED_DEP.canonical_name]

    text_report = report_format.ColumnsFormat(output_desc=False, output_aliases=False).format(
        result, []
    )
    report_lines = text_report.splitlines()

    resolved_line = next(
        line for line in report_lines if line.startswith(_RESOLVED_DEP.canonical_name)
    )
    assert resolved_line.split() == [
        _RESOLVED_DEP.canonical_name,
        resolved_machine["version"],
        resolved_machine["vulns"][0]["id"],
        resolved_machine["vulns"][0]["fix_versions"][0],
    ]

    missing_version_line = next(
        line for line in report_lines if line.startswith(_SKIPPED_DEP.canonical_name)
    )
    assert missing_version_line.split(maxsplit=1) == [
        _SKIPPED_DEP.canonical_name,
        skipped_machine["skip_reason"],
    ]
