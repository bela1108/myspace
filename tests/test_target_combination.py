# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the offline target combination preflight."""

from __future__ import annotations

import os
import tempfile
import unittest

from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import TargetFile, Targets
from tuf.ngclient import Updater
from tuf.ngclient.combination import (
    CombinationConflictError,
    TargetCandidate,
    preflight_combination,
)


def make_target(
    path: str,
    module: str | None = None,
    version: str | None = None,
    provides: dict[str, str] | None = None,
    requires: object = None,
    config: str | None = None,
    content: bytes | None = None,
) -> TargetFile:
    data = content if content is not None else f"{path}:{module}".encode()
    target = TargetFile.from_data(path, data, ["sha256"])
    custom: dict[str, object] = {}
    if module is not None:
        custom["module"] = module
    if version is not None:
        custom["version"] = version
    if provides is not None:
        custom["provides"] = provides
    if requires is not None:
        custom["requires"] = requires
    if config is not None:
        custom["config"] = config
    if custom:
        target.unrecognized_fields["custom"] = custom
    return target


def make_view(*targets: TargetFile) -> dict[str, Targets]:
    return {
        Targets.type: Targets(
            targets={target.path: target for target in targets}
        )
    }


class TestCombinationPreflight(unittest.TestCase):
    def test_transitive_closure_and_evidence(self) -> None:
        app = make_target(
            "modules/app",
            "app",
            "1.0",
            {"app-api": "1.0.0"},
            [{"module": "lib", "interface": "lib-api", "version": ">=2,<3"}],
        )
        lib = make_target(
            "modules/lib",
            "lib",
            "2.1.0",
            {"lib-api": "2.4.0"},
            ["util"],
        )
        util = make_target("modules/util", "util", "1.0.0")

        plan = preflight_combination(
            make_view(app, lib, util),
            ["modules/app"],
            {"app-api": "1.0.0", "lib-api": ">=2"},
        )

        self.assertTrue(plan)
        self.assertEqual(set(plan.targets), {"app", "lib", "util"})
        self.assertIs(plan["app"], app)
        self.assertIs(plan.get("modules/lib"), lib)
        self.assertEqual(plan.get("nope"), None)
        self.assertEqual(
            [(edge.module, edge.dependency) for edge in plan.dependencies],
            [("app", "lib"), ("lib", "util")],
        )
        app_lib = plan.dependencies[0]
        self.assertEqual(app_lib.provided_version, "2.4.0")
        self.assertTrue(app_lib.satisfied)
        self.assertEqual(plan.targets_by_path["modules/app"], app)
        self.assertEqual(dict(plan.caller_interfaces)["app-api"], "1.0.0")

    def test_candidate_wrapper_and_channel_mapping(self) -> None:
        app = make_target("app", "app", requires=["lib"])
        lib = make_target("lib", "lib")

        plan = preflight_combination(
            make_view(app, lib),
            {"stable": [TargetCandidate(app, channel="stable")]},
        )
        self.assertTrue(plan.ok)
        self.assertEqual(set(plan.targets), {"app", "lib"})
        self.assertEqual(plan.dependencies[0].channel, "stable")

    def test_cycle_conflict_and_allow_cycles(self) -> None:
        a = make_target("a", "a", requires=["b"])
        b = make_target("b", "b", requires=["a"])
        view = make_view(a, b)

        plan = preflight_combination(view, ["a"])
        self.assertFalse(plan.ok)
        assert plan.conflict is not None
        self.assertEqual(plan.conflict.kind, "cycle")
        self.assertEqual(plan.conflict.cycle, ("a", "b", "a"))
        self.assertTrue(plan.conflict.is_cycle)
        self.assertEqual(plan.targets, {})
        self.assertEqual(plan.first_unsatisfiable, ("a -> b", "b -> a"))

        allowed = preflight_combination(view, ["a"], allow_cycles=True)
        self.assertTrue(allowed.ok)
        self.assertEqual(set(allowed.targets), {"a", "b"})

    def test_conflicting_identity_across_channels(self) -> None:
        stable = make_target(
            "stable/plugin", "plugin", "1.0", content=b"stable content"
        )
        beta = make_target(
            "beta/plugin", "plugin", "1.0", content=b"beta content"
        )

        view = {
            "stable": Targets(targets={stable.path: stable}),
            "beta": Targets(targets={beta.path: beta}),
        }
        plan = preflight_combination(
            view,
            ["stable/plugin", "beta/plugin"],
        )

        self.assertFalse(plan.ok)
        assert plan.conflict is not None
        self.assertEqual(plan.conflict.kind, "identity")
        self.assertTrue(plan.conflict.is_identity_conflict)
        self.assertEqual(set(plan.conflict.channels), {"stable", "beta"})
        self.assertEqual(len(plan.conflict.identities), 2)
        self.assertIn("plugin", plan.conflict.modules)
        self.assertEqual(plan.targets, {})

    def test_config_mismatch_only_when_combined(self) -> None:
        a = make_target("a", "a", config="cfg/v1")
        b = make_target("b", "b", config="cfg/v2")
        view = make_view(a, b)

        first = preflight_combination(view, ["a"])
        second = preflight_combination(view, ["b"])
        self.assertTrue(first.ok)
        self.assertTrue(second.ok)

        combined = preflight_combination(view, ["a", "b"])
        self.assertFalse(combined.ok)
        assert combined.conflict is not None
        self.assertEqual(combined.conflict.reason, "config-mismatch")
        self.assertEqual(combined.conflict.kind, "unsatisfiable")
        self.assertEqual(len(combined.conflict.group), 2)

    def test_interface_constraint_group(self) -> None:
        lib = make_target("lib", "lib", provides={"lib-api": "2.4.0"})
        first = make_target(
            "first",
            "first",
            requires=[
                {"module": "lib", "interface": "lib-api", "version": ">=2,<3"}
            ],
        )
        second = make_target(
            "second",
            "second",
            requires=[
                {"module": "lib", "interface": "lib-api", "version": "<2"}
            ],
        )

        plan = preflight_combination(
            make_view(lib, first, second), ["first", "second"]
        )

        self.assertFalse(plan.ok)
        assert plan.conflict is not None
        self.assertEqual(plan.conflict.kind, "unsatisfiable")
        self.assertEqual(plan.conflict.reason, "interface-version")
        self.assertEqual(len(plan.conflict.group), 2)
        self.assertTrue(any("first" in item for item in plan.conflict.group))
        self.assertTrue(any("second" in item for item in plan.conflict.group))

    def test_caller_can_provide_an_interface(self) -> None:
        plugin = make_target(
            "plugin",
            "plugin",
            requires=[{"interface": "host-api", "version": ">=2"}],
        )
        plan = preflight_combination(
            make_view(plugin), ["plugin"], {"host-api": "2.1"}
        )
        self.assertTrue(plan.ok)
        self.assertEqual(plan.dependencies[0].dependency, "<caller>")
        self.assertTrue(plan.dependencies[0].satisfied)

        plan = preflight_combination(
            make_view(plugin), ["plugin"], {"host-api": "1.0"}
        )
        self.assertFalse(plan.ok)
        assert plan.conflict is not None
        self.assertEqual(plan.conflict.reason, "caller-interface-version")

    def test_textual_interface_versions(self) -> None:
        lib = make_target("lib", "lib", provides={"lib-api": "stable"})
        app = make_target(
            "app",
            "app",
            requires=[
                {"module": "lib", "interface": "lib-api", "version": "stable"}
            ],
        )
        plan = preflight_combination(
            make_view(lib, app), ["app"], {"lib-api": "stable"}
        )
        self.assertTrue(plan.ok)

        wrong = make_target(
            "wrong",
            "wrong",
            requires=[
                {"module": "lib", "interface": "lib-api", "version": "beta"}
            ],
        )
        plan = preflight_combination(make_view(lib, wrong), ["wrong"])
        self.assertFalse(plan.ok)

    def test_candidate_must_match_verified_identity(self) -> None:
        original = make_target("app", "app", content=b"original")
        tampered = TargetFile.from_data("app", b"tampered", ["sha256"])
        tampered.unrecognized_fields["custom"] = {"module": "app"}

        plan = preflight_combination(
            make_view(original), [TargetCandidate(tampered)]
        )
        self.assertFalse(plan.ok)
        assert plan.conflict is not None
        self.assertEqual(plan.conflict.kind, "identity")
        self.assertEqual(plan.conflict.reason, "candidate-view-mismatch")

    def test_missing_dependency(self) -> None:
        app = make_target("app", "app", requires=["not-present"])
        plan = preflight_combination(make_view(app), ["app"])

        self.assertFalse(plan.ok)
        assert plan.conflict is not None
        self.assertEqual(plan.conflict.kind, "missing")
        self.assertEqual(plan.conflict.reason, "missing-dependency")
        self.assertIn("not-present", plan.conflict.modules)

    def test_missing_candidate_is_reported(self) -> None:
        plan = preflight_combination(make_view(), ["not/in/view"])
        self.assertFalse(plan.ok)
        assert plan.conflict is not None
        self.assertEqual(plan.conflict.kind, "missing")
        self.assertEqual(plan.conflict.reason, "missing-candidate")

    def test_raise_on_conflict(self) -> None:
        app = make_target("app", "app", requires=["missing"])
        with self.assertRaises(CombinationConflictError) as raised:
            preflight_combination(
                make_view(app), ["app"], raise_on_conflict=True
            )
        self.assertEqual(raised.exception.conflict.kind, "missing")
        self.assertEqual(raised.exception.kind, "missing")


class TestCombinationOfflineMirrors(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dirs: list[tempfile.TemporaryDirectory[str]] = []

    def tearDown(self) -> None:
        for temp_dir in self.temp_dirs:
            temp_dir.cleanup()

    def _mirror_updater(self) -> tuple[Updater, RepositorySimulator]:
        temp_dir = tempfile.TemporaryDirectory()
        self.temp_dirs.append(temp_dir)
        metadata_dir = os.path.join(temp_dir.name, "metadata")
        targets_dir = os.path.join(temp_dir.name, "targets")
        os.mkdir(metadata_dir)
        os.mkdir(targets_dir)

        sim = RepositorySimulator()
        sim.add_target(
            "targets",
            b"app content",
            "modules/app",
        )
        sim.targets.targets["modules/app"].unrecognized_fields["custom"] = {
            "module": "app",
            "requires": [{"module": "lib", "interface": "lib-api"}],
        }
        sim.add_target("targets", b"lib content", "modules/lib")
        sim.targets.targets["modules/lib"].unrecognized_fields["custom"] = {
            "module": "lib",
            "provides": {"lib-api": "1.0.0"},
        }
        sim.targets.version += 1
        sim.update_snapshot()

        updater = Updater(
            metadata_dir,
            "https://example.com/metadata/",
            targets_dir,
            "https://example.com/targets/",
            sim,
            bootstrap=sim.signed_roots[0],
        )
        updater.refresh()
        return updater, sim

    def test_two_in_memory_mirrors_keep_download_state(self) -> None:
        first_updater, first_sim = self._mirror_updater()
        second_updater, second_sim = self._mirror_updater()

        first_before = first_updater.download_state()
        second_before = second_updater.download_state()
        fetches_before = (
            len(first_sim.fetch_tracker.metadata),
            len(first_sim.fetch_tracker.targets),
        )

        first_plan = first_updater.preflight_combination(
            ["modules/app"], {"lib-api": ">=1"}
        )
        second_plan = second_updater.preflight_combination(
            ["modules/app"], {"lib-api": ">=1"}
        )

        self.assertTrue(first_plan.ok)
        self.assertTrue(second_plan.ok)
        self.assertEqual(set(first_plan.targets), {"app", "lib"})
        self.assertEqual(set(second_plan.targets), {"app", "lib"})
        for name in first_plan.targets:
            self.assertEqual(
                first_plan.targets[name].hashes,
                second_plan.targets[name].hashes,
            )

        self.assertEqual(first_before, first_updater.download_state())
        self.assertEqual(second_before, second_updater.download_state())
        self.assertEqual(first_before, second_before)
        self.assertEqual(
            (
                len(first_sim.fetch_tracker.metadata),
                len(first_sim.fetch_tracker.targets),
            ),
            fetches_before,
        )
        self.assertEqual(first_sim.fetch_tracker.targets, [])
        self.assertEqual(second_sim.fetch_tracker.targets, [])


if __name__ == "__main__":
    unittest.main()
