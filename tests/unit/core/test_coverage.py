
# SPDX-License-Identifier: Apache-2.0
import json
import os
import tempfile

import testtools

from bandit.core import config as b_config
from bandit.core import coverage
from bandit.core import extension_loader
from bandit.core import manager as b_manager
from bandit.core import test_set as b_test_set


def _ledger(shard="shard", rules=("B101",), files=("f.py",)):
    ledger = coverage.CoverageLedger(shard_id=shard)
    ledger.set_rules(rules)
    for fname in files:
        ledger.begin_file(fname, f"sha256:{fname}")
    return ledger


class CoverageLedgerTests(testtools.TestCase):
    def test_states_recorded_per_rule_and_file(self):
        ledger = _ledger(rules=("B101", "B102", "B103", "B104"))
        ledger.note_completed("B101", "f.py")
        ledger.note_failed("B102", "f.py")
        ledger.end_file("f.py", {"Call"}, {"B103": {"Call"}, "B104": {"Str"}})

        cells = ledger.cells
        self.assertEqual(coverage.STATE_COMPLETED, cells[("B101", "f.py")])
        self.assertEqual(coverage.STATE_FAILED, cells[("B102", "f.py")])
        # B103 ran out of nodes? no: its checktype was seen but it never
        # recorded an outcome, so it stays a selected gap
        self.assertEqual(coverage.STATE_SELECTED, cells[("B103", "f.py")])
        self.assertEqual(
            coverage.STATE_NOT_APPLICABLE, cells[("B104", "f.py")]
        )

    def test_failure_is_sticky(self):
        ledger = _ledger()
        ledger.note_failed("B101", "f.py")
        ledger.note_completed("B101", "f.py")
        self.assertEqual(
            coverage.STATE_FAILED, ledger.cells[("B101", "f.py")]
        )

    def test_round_trip(self):
        ledger = _ledger(rules=("B101", "B102"))
        ledger.note_completed("B101", "f.py")
        ledger.note_failed("B102", "f.py")
        data = ledger.to_dict()
        self.assertEqual(ledger.source_digest, data["source_digest"])
        self.assertEqual(ledger.config_digest, data["config_digest"])

        loaded = coverage.CoverageLedger.from_dict(
            json.loads(json.dumps(data))
        )
        self.assertEqual(ledger.cells, loaded.cells)
        self.assertEqual(ledger.rules, loaded.rules)
        self.assertEqual(ledger.files, loaded.files)
        self.assertEqual(
            ledger.compatibility_key(), loaded.compatibility_key()
        )

    def test_save_and_load(self):
        ledger = _ledger()
        ledger.note_completed("B101", "f.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "ledger.json")
            ledger.save(path)
            loaded = coverage.CoverageLedger.load(path)
        self.assertEqual(ledger.cells, loaded.cells)

    def test_from_dict_rejects_bad_version(self):
        ledger = _ledger()
        data = ledger.to_dict()
        data["version"] = 999
        self.assertRaises(ValueError, coverage.CoverageLedger.from_dict, data)


class MergeTests(testtools.TestCase):
    def test_matching_digests_fill_gaps(self):
        model = _ledger(shard="model-layer", rules=("B101", "B102"))
        model.note_completed("B101", "f.py")
        # B102 left as selected gap in the model shard
        other = _ledger(shard="api-layer", rules=("B101", "B102"))
        other.note_completed("B101", "f.py")
        other.note_completed("B102", "f.py")

        merged = coverage.merge_ledgers([model, other])
        self.assertEqual(1, len(merged.groups))
        group = next(iter(merged.groups.values()))
        cells = coverage.MergedCoverage._group_cells(group)
        self.assertEqual(coverage.STATE_COMPLETED, cells[("B102", "f.py")])
        self.assertEqual([], merged.evaluate())

    def test_mismatched_digests_cannot_fill_gaps(self):
        model = _ledger(shard="model-layer", rules=("B101",))
        model.note_completed("B101", "f.py")
        other = _ledger(shard="api-layer", rules=("B102",))
        other.note_completed("B102", "f.py")

        merged = coverage.merge_ledgers([model, other])
        self.assertEqual(2, len(merged.groups))
        self.assertEqual(["api-layer"], merged.incompatible)

    def test_same_shard_rerun_replaces_own_cells(self):
        first = _ledger(shard="model-layer")
        first.note_failed("B101", "f.py")
        rerun = _ledger(shard="model-layer")
        rerun.note_completed("B101", "f.py")

        merged = coverage.merge_ledgers([first, rerun])
        group = next(iter(merged.groups.values()))
        cells = coverage.MergedCoverage._group_cells(group)
        self.assertEqual(coverage.STATE_COMPLETED, cells[("B101", "f.py")])
        self.assertEqual([], merged.conflicts)
        self.assertEqual([], merged.evaluate())

    def test_cross_shard_conflict_is_visible(self):
        one = _ledger(shard="model-layer")
        one.note_completed("B101", "f.py")
        two = _ledger(shard="api-layer")
        two.note_failed("B101", "f.py")

        merged = coverage.merge_ledgers([one, two])
        self.assertEqual(1, len(merged.conflicts))
        conflict = merged.conflicts[0]
        self.assertEqual("B101", conflict["rule"])
        self.assertEqual("f.py", conflict["file"])
        self.assertEqual(
            {"model-layer": "completed", "api-layer": "failed"},
            conflict["states"],
        )
        reasons = merged.evaluate()
        self.assertEqual(1, len(reasons))
        self.assertIn("B101", reasons[0])

    def test_failed_cell_fails_gate_with_reason(self):
        ledger = _ledger(shard="broken")
        ledger.note_failed("B101", "f.py")
        merged = coverage.merge_ledgers([ledger])
        reasons = merged.evaluate()
        self.assertEqual(1, len(reasons))
        self.assertIn("failed", reasons[0])
        self.assertIn("B101", reasons[0])

    def test_render_table_marks_states(self):
        ledger = _ledger(rules=("B101", "B102", "B103"))
        ledger.note_completed("B101", "f.py")
        ledger.note_failed("B102", "f.py")
        ledger.end_file("f.py", set(), {"B103": {"Str"}})
        table = coverage.render_table(coverage.merge_ledgers([ledger]))
        self.assertIn("ok", table)
        self.assertIn("FAIL", table)
        self.assertIn("source digest:", table)
        self.assertIn("config digest:", table)


class ExtractRulesTests(testtools.TestCase):
    def test_extract_rules_expands_blacklist_ids(self):
        testset = b_test_set.BanditTestSet(b_config.BanditConfig())
        rules = coverage.extract_rules(testset)
        self.assertIn("B404", rules)  # blacklist import check
        self.assertIn("Import", rules["B404"])
        self.assertIn("B602", rules)  # regular plugin
        self.assertNotIn("B001", rules)  # wrapper id is expanded


class ManagerCoverageTests(testtools.TestCase):
    def _run_manager(self, target, profile=None, shard="test-shard"):
        mgr = b_manager.BanditManager(
            b_config.BanditConfig(),
            "file",
            profile=profile or {"include": ["B608"]},
            coverage_shard=shard,
        )
        mgr.discover_files([target])
        mgr.run_tests()
        return mgr

    def test_manager_records_coverage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "target.py")
            with open(target, "w") as fp:
                fp.write('query = "SELECT * FROM users"\n')
            mgr = self._run_manager(target)

        ledger = mgr.coverage
        self.assertEqual("test-shard", ledger.shard_id)
        self.assertIn(target, ledger.files)
        self.assertEqual(
            coverage.STATE_COMPLETED, ledger.cells[("B608", target)]
        )

    def test_manager_records_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "target.py")
            with open(target, "w") as fp:
                fp.write("x = 1\n")
            mgr = self._run_manager(target)

        self.assertEqual(
            coverage.STATE_NOT_APPLICABLE,
            mgr.coverage.cells[("B608", target)],
        )

    def test_manager_records_failed_rule(self):
        def boom(context, config=None):
            raise RuntimeError("simulated plugin crash")

        boom._test_id = "B608"
        boom._checks = {"Str"}
        boom.__name__ = "hardcoded_sql_string"

        original = []
        for ext in extension_loader.MANAGER.plugins:
            if getattr(ext.plugin, "_test_id", None) == "B608":
                original.append((ext, ext.plugin))
                ext.plugin = boom
        self.addCleanup(self._restore, original)

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "target.py")
            with open(target, "w") as fp:
                fp.write('query = "SELECT 1"\n')
            mgr = self._run_manager(target)

        self.assertEqual([], mgr.results)  # zero findings
        self.assertEqual(
            coverage.STATE_FAILED, mgr.coverage.cells[("B608", target)]
        )
        reasons = coverage.merge_ledgers([mgr.coverage]).evaluate()
        self.assertEqual(1, len(reasons))

    @staticmethod
    def _restore(original):
        for ext, plugin in original:
            ext.plugin = plugin
