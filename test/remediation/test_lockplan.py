from pathlib import Path

import pytest
from packaging.utils import canonicalize_name

from pip_audit._remediation.lockplan import (
    LockPlanError,
    evaluate_marker,
    load_lock_plan,
)

ASSETS = Path(__file__).parent.parent / "assets" / "remediation"


class TestLoadLockPlan:
    def test_parses_packages_and_versions(self):
        plan = load_lock_plan(ASSETS / "pylock.before.toml")

        assert plan.lock_version == "1.0"
        assert plan.environments == (
            "sys_platform == 'linux'",
            "sys_platform == 'darwin'",
        )
        vulnchain = plan.package("vulnchain")
        assert vulnchain is not None
        assert vulnchain.version == "4.0.0"
        assert vulnchain.resolved is True

    def test_parses_optional_groups(self):
        plan = load_lock_plan(ASSETS / "pylock.before.toml")

        assert plan.group_members("plugins") == ("plugintool",)

    def test_lock_roots_exclude_group_members(self):
        plan = load_lock_plan(ASSETS / "pylock.before.toml")

        assert "appcore" in plan.root_names
        assert "platformextras" in plan.root_names
        assert "plugintool" not in plan.root_names

    def test_dependency_edges_keep_markers(self):
        plan = load_lock_plan(ASSETS / "pylock.before.toml")
        extras = plan.package("platformextras")

        edge = next(dep for dep in extras.dependencies if dep.canonical_name == "markerlib")
        assert edge.marker is not None
        assert edge.marker_active is None

    def test_unconditional_edge_is_active(self):
        plan = load_lock_plan(ASSETS / "pylock.before.toml")
        appcore = plan.package("appcore")

        edge = next(dep for dep in appcore.dependencies if dep.canonical_name == "sharedutils")
        assert edge.marker is None
        assert edge.marker_active is True

    def test_missing_file(self):
        with pytest.raises(LockPlanError, match="not found"):
            load_lock_plan(ASSETS / "does-not-exist.toml")

    def test_missing_lock_version(self, tmp_path):
        lock = tmp_path / "pylock.toml"
        lock.write_text("packages = []\n")
        with pytest.raises(LockPlanError, match="missing lock-version"):
            load_lock_plan(lock)

    def test_unsupported_lock_version(self, tmp_path):
        lock = tmp_path / "pylock.toml"
        lock.write_text('lock-version = "2.0"\npackages = []\n')
        with pytest.raises(LockPlanError, match="not supported"):
            load_lock_plan(lock)

    def test_missing_packages(self, tmp_path):
        lock = tmp_path / "pylock.toml"
        lock.write_text('lock-version = "1.0"\n')
        with pytest.raises(LockPlanError, match="missing packages"):
            load_lock_plan(lock)

    def test_package_without_name(self, tmp_path):
        lock = tmp_path / "pylock.toml"
        lock.write_text('lock-version = "1.0"\n[[packages]]\nversion = "1.0"\n')
        with pytest.raises(LockPlanError, match="no name"):
            load_lock_plan(lock)

    def test_invalid_toml(self, tmp_path):
        lock = tmp_path / "pylock.toml"
        lock.write_text("this is = = not toml\n")
        with pytest.raises(LockPlanError, match="invalid TOML"):
            load_lock_plan(lock)


class TestEvaluateMarker:
    def test_none_marker_is_unconditional(self):
        assert evaluate_marker(None) is True

    def test_variable_marker_is_undecidable(self):
        assert evaluate_marker("sys_platform == 'win32'") is None

    def test_invalid_marker_is_undecidable(self):
        assert evaluate_marker("sys_platform ==") is None


def test_canonicalization_helper():
    assert canonicalize_name("Some_Package.Name") == "some-package-name"
