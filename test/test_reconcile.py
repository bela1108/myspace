from __future__ import annotations

import json
from pathlib import Path

from pip_audit._reconcile import (
    AuditReport,
    FindingKind,
    ReconciliationReport,
    ReleaseTarget,
    load_cache_map,
    load_manifests,
    load_targets,
    reconcile,
)

_ASSETS = Path(__file__).parent / "assets" / "reconcile"


def _inputs() -> tuple[AuditReport, dict, dict, tuple[ReleaseTarget, ...]]:
    audit = AuditReport.load(_ASSETS / "audit-report.json")
    targets = load_targets(_ASSETS / "release-scope.json")
    cache = load_cache_map(_ASSETS / "cache-map.json")
    manifests = {
        path.stem: load_manifests(path)["default"]
        for path in sorted((_ASSETS / "manifests").glob("*.json"))
    }
    return audit, manifests, cache, targets


def _report() -> ReconciliationReport:
    return reconcile(*_inputs())


def _by_target(report: ReconciliationReport) -> dict[str, object]:
    return {record.target.name: record for record in report.targets}


def test_markers_and_extras_follow_the_declared_release_scope() -> None:
    report = _report()
    records = _by_target(report)

    windows = {basis.package for basis in records["windows-amd64"].expected}
    linux = {basis.package for basis in records["linux-x86_64"].expected}
    macos = {basis.package for basis in records["macos-arm64"].expected}

    assert "pywin32" in windows
    assert "pywin32" not in linux
    assert "uvloop" in linux
    assert "uvloop" not in windows
    assert "cuda-bindings" in linux
    assert "cuda-bindings" not in macos


def test_same_package_name_keeps_platform_artifacts_separate() -> None:
    audit, _, _, _ = _inputs()
    numpy_entries = [item for item in audit.dependencies if item.name == "numpy"]

    assert len(numpy_entries) == 5
    assert len({item.artifact.filename for item in numpy_entries if item.artifact}) == 5

    records = _by_target(_report())
    macos_numpy = next(item for item in records["macos-arm64"].expected if item.package == "numpy")
    windows_numpy = next(
        item for item in records["windows-amd64"].expected if item.package == "numpy"
    )
    linux_numpy = next(item for item in records["linux-x86_64"].expected if item.package == "numpy")

    assert macos_numpy.artifact.filename.endswith("macosx_11_0_arm64.whl")
    assert windows_numpy.artifact.filename.endswith("win_amd64.whl")
    assert linux_numpy.artifact.filename.endswith("manylinux_2_17_x86_64.whl")


def test_old_cache_desktop_architectures_are_listed() -> None:
    report = _report()

    assert [
        (finding.target, finding.package, finding.actual_version)
        for finding in report.desktop_old_cache_findings
    ] == [("macos-arm64", "numpy", "2.1.0")]
    assert [
        (finding.target, finding.package, finding.actual_version)
        for finding in report.other_old_cache_findings
    ] == [("offline-linux-arm64", "numpy", "2.2.2")]


def test_missing_manifest_targets_carry_dependency_basis() -> None:
    report = _report()
    missing = report.missing_manifest_findings

    assert [finding.target for finding in missing] == ["offline-linux-arm64"]
    record = next(item for item in report.targets if item.target.name == "offline-linux-arm64")
    names = {basis.package for basis in record.expected}
    assert names == {"attrs", "cattrs", "numpy", "uvloop"}
    numpy = next(basis for basis in record.expected if basis.package == "numpy")
    assert 'platform_machine == "aarch64"' in numpy.marker
    assert numpy.artifact is not None
    assert numpy.artifact.filename.endswith("manylinux_2_17_aarch64.whl")


def test_missing_cache_mappings_are_a_separate_bucket() -> None:
    report = _report()

    assert [
        (finding.target, finding.package) for finding in report.missing_cache_mapping_findings
    ] == [("macos-x86_64", "(build cache)"), ("windows-amd64", "attrs")]
    assert report.missing_manifest_findings[0].target != "macos-x86_64"


def test_same_version_different_artifact_is_not_treated_as_one() -> None:
    report = _report()
    artifact_findings = [
        finding for finding in report.findings if finding.kind is FindingKind.STALE_CACHE_ARTIFACT
    ]

    assert len(artifact_findings) == 1
    finding = artifact_findings[0]
    assert (finding.target, finding.package) == ("linux-x86_64", "cryptography")
    assert finding.expected_artifact is not None
    assert finding.actual_artifact is not None
    assert finding.expected_artifact.digest != finding.actual_artifact.digest


def test_artifact_identity_is_rendered_for_review() -> None:
    report = _report()
    text = report.render_text()

    assert "Desktop architectures on an old build cache:" in text
    assert "macos-arm64" in text
    assert "numpy audit=2.2.3 cache=2.1.0" in text
    assert "Desktop architectures with a non-audited cache artifact:" in text
    assert "cryptography audit=42.0.8 cache=42.0.8" in text
    assert "Targets without an install manifest:" in text
    assert "offline-linux-arm64" in text
    assert "Missing cache mappings (listed separately):" in text
    assert "numpy==2.2.3" in text


def test_json_report_exposes_required_sections() -> None:
    report = _report()
    payload = report.as_dict()
    json.dumps(payload)

    assert payload["summary"]["targets"] == 5
    assert payload["summary"]["desktop_stale_cache"] == 1
    assert payload["summary"]["missing_install_manifests"] == 1
    assert [item["target"] for item in payload["missing_install_manifests"]] == [
        "offline-linux-arm64"
    ]
    assert payload["missing_install_manifests"][0]["basis"]
    assert [item["target"] for item in payload["desktop_stale_cache"]] == ["macos-arm64"]


def test_plain_pip_audit_json_still_works() -> None:
    audit = AuditReport.load(
        {
            "dependencies": [
                {
                    "name": "Foo_Bar",
                    "version": "1.0.0",
                    "vulns": [{"id": "CVE-2024-0001", "fix_versions": ["1.0.1"]}],
                }
            ],
            "fixes": [],
        }
    )
    target = ReleaseTarget(name="plain", markers={"python_version": "3.12"})
    report = reconcile(
        audit,
        {"plain": [{"name": "foo-bar", "version": "1.0.0"}]},
        {"plain": [{"name": "foo-bar", "version": "1.0.0"}]},
        targets=[target],
    )

    record = report.targets[0]
    assert not record.findings
    assert record.expected[0].canonical_name == "foo-bar"
    assert record.expected[0].vulnerabilities == ("CVE-2024-0001",)


def test_missing_marker_variable_is_pending_not_assumed() -> None:
    audit = AuditReport.load(
        {
            "dependencies": [
                {
                    "name": "numpy",
                    "version": "2.2.3",
                    "marker": 'sys_platform == "linux"',
                }
            ]
        }
    )
    target = ReleaseTarget(name="incomplete", markers={"python_version": "3.12"})
    report = reconcile(audit, {"incomplete": []}, {"incomplete": []}, targets=[target])

    assert report.unresolved
    assert report.unresolved[0].kind is FindingKind.UNRESOLVED_MARKER
    assert report.targets[0].expected == ()
    assert "sys_platform" in report.unresolved[0].detail


def test_duplicate_manifest_entries_are_not_collapsed_silently() -> None:
    audit = AuditReport.load(
        {
            "dependencies": [
                {
                    "name": "demo",
                    "version": "1.0",
                    "artifact": {"filename": "demo-1.0-py3-none-any.whl", "sha256": "a" * 64},
                }
            ]
        }
    )
    manifest = [
        {"name": "demo", "version": "1.0", "sha256": "a" * 64},
        {"name": "demo", "version": "1.0", "sha256": "b" * 64},
    ]
    target = ReleaseTarget(name="dup", markers={"python_version": "3.12"})
    report = reconcile(audit, {"dup": manifest}, {"dup": manifest}, targets=[target])

    assert any(finding.kind is FindingKind.AMBIGUOUS_MATCH for finding in report.findings)


def test_scope_can_travel_with_the_cache_mapping() -> None:
    audit = AuditReport.load({"dependencies": [{"name": "demo", "version": "1.0"}]})
    cache = {
        "scope": [
            {
                "name": "demo-target",
                "markers": {"python_version": "3.12"},
                "extras": [],
            }
        ],
        "demo-target": [{"name": "demo", "version": "1.0"}],
    }
    report = reconcile(audit, {"demo-target": [{"name": "demo", "version": "1.0"}]}, cache)

    assert [record.target.name for record in report.targets] == ["demo-target"]
    assert not report.findings
