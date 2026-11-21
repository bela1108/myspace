from pathlib import Path

from packaging.version import Version

from pip_audit._audit import Auditor
from pip_audit._dependency_source import PyLockSource
from pip_audit._service.interface import (
    VulnerabilityID,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._target import (
    EvidenceStatus,
    TargetEnvironment,
    load_target_environment_matrix,
)

ASSETS = Path(__file__).parent / "assets"


class StubService(VulnerabilityService):
    def __init__(self, advisories):
        self.advisories = advisories
        self.calls = []

    def query(self, spec):
        self.calls.append((spec.canonical_name, str(spec.version)))
        return spec, list(self.advisories.get((spec.canonical_name, str(spec.version)), []))


def _vuln(vuln_id, aliases=()):
    return VulnerabilityResult(
        id=VulnerabilityID(vuln_id),
        description="stub advisory",
        fix_versions=[Version("99.0")],
        aliases=set(aliases),
    )


def _report():
    source = PyLockSource([ASSETS / "pylock.matrix.toml"])
    matrix = load_target_environment_matrix(ASSETS / "environments.matrix.toml")
    service = StubService(
        {
            ("cryptography", "41.0.7"): [_vuln("CVE-2024-0001")],
            ("colorama", "0.4.6"): [_vuln("CVE-2024-0002")],
            ("numpy", "2.2.3"): [_vuln("CVE-2024-0003")],
        }
    )
    return service, matrix, Auditor(service).audit_matrix(source, matrix)


def test_matrix_queries_are_reused_by_distribution_identity():
    service, _, report = _report()

    assert len(service.calls) == 7
    assert len(set(service.calls)) == 7
    assert report.query_count == 7
    assert report.cache_hits == 5

    # Without identity reuse each environment would query its own checked rows.
    per_environment_queries = sum(len(env.checked) for env in report.environments)
    assert per_environment_queries == 12
    assert per_environment_queries - report.query_count == report.cache_hits
    assert report.queries == (
        ("attrs", "25.1.0"),
        ("uvloop", "0.19.0"),
        ("cryptography", "41.0.7"),
        ("numpy", "2.2.3"),
        ("platform-probe", "1.0"),
        ("colorama", "0.4.6"),
        ("cryptography", "42.0.5"),
    )

    # Same distribution and version across environments: one query.
    assert service.calls.count(("attrs", "25.1.0")) == 1
    assert service.calls.count(("uvloop", "0.19.0")) == 1
    assert service.calls.count(("cryptography", "41.0.7")) == 1

    # Same name at different versions: distinct distribution identities.
    assert service.calls.count(("cryptography", "41.0.7")) == 1
    assert service.calls.count(("cryptography", "42.0.5")) == 1


def test_linux_environment_is_complete():
    _, matrix, report = _report()
    linux = report.environments[0]

    assert linux.environment is matrix[0]
    assert linux.complete
    assert linux.missing_evidence == {}
    assert len(linux.checked) == 5
    assert [d.canonical_name for d in linux.excluded] == ["colorama", "cryptography"]
    assert {v.id for d in linux.vulnerable for v in d.vulnerabilities} == {
        "CVE-2024-0001",
        "CVE-2024-0003",
    }


def test_missing_marker_variable_blocks_windows_conclusion():
    service, _, report = _report()
    windows = report.environments[1]

    assert not windows.complete
    assert windows.missing_evidence == {"platform-probe 1.0": ("platform_release",)}
    assert ("platform-probe", "1.0") in service.calls
    crypto = {d.version: d.status for d in windows.dependencies if d.name == "cryptography"}
    assert crypto == {
        "42.0.5": EvidenceStatus.CHECKED,
        "41.0.7": EvidenceStatus.EXCLUDED,
    }
    assert {v.id for d in windows.vulnerable for v in d.vulnerabilities} == {
        "CVE-2024-0002",
        "CVE-2024-0003",
    }


def test_architecture_gap_and_marker_gap_block_macos_conclusion():
    service, _, report = _report()
    macos = report.environments[2]

    assert not macos.complete
    assert macos.missing_evidence == {
        "numpy 2.2.3": ("compatible-distribution",),
        "platform-probe 1.0": ("platform_release",),
    }
    # The macOS arm64 environment has no locked numpy wheel, so it must not
    # inherit Linux/Windows advisory evidence for numpy.
    assert ("numpy", "2.2.3") in service.calls
    assert not any(d.name == "numpy" for d in macos.vulnerable)

    explicit = {d.name: d for d in macos.dependencies}
    assert explicit["numpy"].status is EvidenceStatus.MISSING_ARTIFACT
    assert explicit["platform-probe"].status is EvidenceStatus.MISSING_MARKER_VARIABLE


def test_matrix_report_serializes_per_environment_conclusions():
    _, _, report = _report()
    document = report.to_dict()

    assert document["queries"]["count"] == 7
    assert document["queries"]["cache_hits"] == 5
    assert [env["environment"] for env in document["environments"]] == [
        "linux-x86_64",
        "windows-amd64",
        "macos-arm64",
    ]
    assert [env["complete"] for env in document["environments"]] == [True, False, False]
    assert document["environments"][2]["missing_evidence"] == {
        "numpy 2.2.3": ["compatible-distribution"],
        "platform-probe 1.0": ["platform_release"],
    }


def test_marker_variables_are_not_inherited_from_host():
    environment = TargetEnvironment(
        name="partial",
        markers={"python_version": "3.12"},
        platform_tags=("win_amd64",),
    )
    source = PyLockSource([ASSETS / "pylock.matrix.toml"])
    service = StubService({})
    report = Auditor(service).audit_matrix(source, [environment])
    windows_only = {d.name: d for d in report.environments[0].dependencies}

    # sys_platform is absent from the target, so colorama and uvloop cannot be
    # classified using the host's platform, and cryptography has no version
    # evidence for this target.
    assert windows_only["colorama"].status is EvidenceStatus.MISSING_MARKER_VARIABLE
    assert windows_only["uvloop"].status is EvidenceStatus.MISSING_MARKER_VARIABLE
    assert windows_only["cryptography"].status is EvidenceStatus.MISSING_MARKER_VARIABLE
    assert ("colorama", "0.4.6") not in service.calls
    assert ("uvloop", "0.19.0") not in service.calls


def test_wheel_tags_select_between_same_name_versions(tmp_path):
    lock = tmp_path / "pylock.toml"
    lock.write_text(
        "\n".join(
            [
                'lock-version = "1.0"',
                'created-by = "test"',
                "",
                "[[packages]]",
                'name = "demo"',
                'version = "1.0"',
                'requires-python = ">=3.8"',
                'wheels = [{ name = "demo-1.0-cp312-cp312-win_amd64.whl" }]',
                "",
                "[[packages]]",
                'name = "demo"',
                'version = "2.0"',
                'requires-python = ">=3.8"',
                'wheels = [{ name = "demo-2.0-cp312-cp312-manylinux_2_17_x86_64.whl" }]',
                "",
            ]
        )
    )

    markers = {
        "implementation_name": "cpython",
        "python_version": "3.12",
        "python_full_version": "3.12.4",
    }
    linux = TargetEnvironment(
        name="linux",
        markers={**markers, "sys_platform": "linux"},
        platform_tags=("manylinux_2_17_x86_64",),
    )
    windows = TargetEnvironment(
        name="windows",
        markers={**markers, "sys_platform": "win32"},
        platform_tags=("win_amd64",),
    )
    service = StubService({})
    report = Auditor(service).audit_matrix(PyLockSource([lock]), [linux, windows])

    selected = []
    for environment in report.environments:
        rows = {row.version: row.status for row in environment.dependencies}
        selected.append((environment.name, rows))
        assert environment.complete

    assert selected == [
        (
            "linux",
            {"2.0": EvidenceStatus.CHECKED, "1.0": EvidenceStatus.EXCLUDED},
        ),
        (
            "windows",
            {"1.0": EvidenceStatus.CHECKED, "2.0": EvidenceStatus.EXCLUDED},
        ),
    ]
    assert service.calls == [("demo", "2.0"), ("demo", "1.0")]
