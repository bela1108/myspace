import unittest

from tuf.api.metadata import TargetFile, Targets
from tuf.ngclient.combination import (
    CombinationConflictError,
    preflight_combination,
)


def make_target(path, module=None, version=None, provides=None,
                requires=None, config=None, content=None):
    data = content if content is not None else path.encode()
    target = TargetFile.from_data(path, data, ["sha256"])
    custom = {}
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


def make_view(*targets):
    return {"targets": Targets(targets={t.path: t for t in targets})}


class Check(unittest.TestCase):
    def test_closure(self):
        app = make_target("modules/app", "app", requires=[
            {"module": "lib", "interface": "lib-api", "version": ">=2,<3"}
        ])
        lib = make_target("modules/lib", "lib", "2.1.0",
                          provides={"lib-api": "2.4.0"}, requires=["util"])
        util = make_target("modules/util", "util")
        plan = preflight_combination(
            make_view(app, lib, util), ["modules/app"],
            {"lib-api": ">=2"},
        )
        self.assertTrue(plan, plan.conflict)
        self.assertEqual(set(plan.targets), {"app", "lib", "util"})
        self.assertIs(plan["app"], app)
        self.assertIs(plan.get("modules/lib"), lib)
        self.assertEqual(
            [(e.module, e.dependency) for e in plan.dependencies],
            [("app", "lib"), ("lib", "util")],
        )
        self.assertEqual(plan.dependencies[0].provided_version, "2.4.0")

    def test_cycle(self):
        a = make_target("a", "a", requires=["b"])
        b = make_target("b", "b", requires=["a"])
        plan = preflight_combination(make_view(a, b), ["a"])
        self.assertFalse(plan.ok)
        self.assertEqual(plan.conflict.kind, "cycle")
        self.assertEqual(plan.conflict.cycle, ("a", "b", "a"))
        self.assertEqual(plan.first_unsatisfiable, ("a -> b", "b -> a"))
        allowed = preflight_combination(
            make_view(a, b), ["a"], allow_cycles=True
        )
        self.assertTrue(allowed.ok, allowed.conflict)

    def test_identity(self):
        stable = make_target("stable/plugin", "plugin", content=b"s")
        beta = make_target("beta/plugin", "plugin", content=b"b")
        plan = preflight_combination(
            make_view(stable, beta), ["stable/plugin", "beta/plugin"]
        )
        self.assertFalse(plan.ok)
        self.assertEqual(plan.conflict.kind, "identity")
        self.assertEqual(len(plan.conflict.identities), 2)

    def test_config(self):
        a = make_target("a", "a", config="cfg/v1")
        b = make_target("b", "b", config="cfg/v2")
        self.assertTrue(preflight_combination(make_view(a), ["a"]).ok)
        combined = preflight_combination(make_view(a, b), ["a", "b"])
        self.assertFalse(combined.ok)
        self.assertEqual(combined.conflict.reason, "config-mismatch")
        self.assertEqual(len(combined.conflict.group), 2)

    def test_interface_group(self):
        lib = make_target("lib", "lib", provides={"lib-api": "2.4.0"})
        first = make_target("first", "first", requires=[
            {"module": "lib", "interface": "lib-api", "version": ">=2,<3"}
        ])
        second = make_target("second", "second", requires=[
            {"module": "lib", "interface": "lib-api", "version": "<2"}
        ])
        plan = preflight_combination(
            make_view(lib, first, second), ["first", "second"]
        )
        self.assertFalse(plan.ok)
        self.assertEqual(plan.conflict.reason, "interface-version")
        self.assertEqual(len(plan.conflict.group), 2)

    def test_missing_and_raise(self):
        app = make_target("app", requires=["missing"])
        plan = preflight_combination(make_view(app), ["app"])
        self.assertEqual(plan.conflict.kind, "missing")
        with self.assertRaises(CombinationConflictError):
            preflight_combination(
                make_view(app), ["app"], raise_on_conflict=True
            )


if __name__ == "__main__":
    unittest.main()
