#
# SPDX-License-Identifier: Apache-2.0
import os

import fixtures
import testtools

from bandit.core import config
from bandit.core import constants
from bandit.core import coverage
from bandit.core import extension_loader
from bandit.core import issue
from bandit.core import manager


def plugin_alpha(context):
    """First small plugin: never flags anything."""
    return None


plugin_alpha._test_id = "B901"
plugin_alpha._checks = ["Str"]


def plugin_beta(context):
    """Second small plugin: blows up on the string boom."""
    if context.string_val == "boom":
        raise RuntimeError("boom")
    return None


plugin_beta._test_id = "B902"
plugin_beta._checks = ["Str"]


class _FakeExtension:
    def __init__(self, plugin):
        self.plugin = plugin
        self.name = plugin.__name__


class CoverageLedgerTests(testtools.TestCase):
    def _ledger(self, shard="shard-a", config_digest="cfg"):
        ledger = coverage.CoverageLedger(
            config_digest=config_digest, shard=shard
        )
        ledger.begin_file("a.py", "digest-a")
        return ledger

    def test_record_states(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.SELECTED)
        ledger.record("B902", "a.py", coverage.SKIPPED, detail="nosec")
        self.assertEqual(
            coverage.SELECTED, ledger.get("B901", "a.py").state
        )
        self.assertEqual(coverage.SKIPPED, ledger.get("B902", "a.py").state)
        self.assertEqual("nosec", ledger.get("B902", "a.py").detail)
        self.assertEqual({"shard-a"}, ledger.get("B901", "a.py").shards)

    def test_transition_file(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.SELECTED)
        ledger.record("B902", "a.py", coverage.FAILED)
        ledger.transition_file(
            "a.py", coverage.SELECTED, coverage.COMPLETED
        )
        self.assertEqual(
            coverage.COMPLETED, ledger.get("B901", "a.py").state
        )
        # failed cells are not touched by the transition
        self.assertEqual(coverage.FAILED, ledger.get("B902", "a.py").state)

    def test_same_shard_rerun_replaces_cell(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.FAILED, detail="old")
        ledger.record("B901", "a.py", coverage.COMPLETED)
        cell = ledger.get("B901", "a.py")
        self.assertEqual(coverage.COMPLETED, cell.state)
        self.assertEqual("", cell.detail)
        self.assertEqual({"shard-a"}, cell.shards)

    def test_cross_shard_same_state_merges_provenance(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.COMPLETED)
        ledger.record("B901", "a.py", coverage.COMPLETED, shard="shard-b")
        cell = ledger.get("B901", "a.py")
        self.assertEqual({"shard-a", "shard-b"}, cell.shards)

    def test_cross_shard_state_conflict_raises(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.COMPLETED)
        self.assertRaises(
            coverage.CoverageConflictError,
            ledger.record,
            "B901",
            "a.py",
            coverage.FAILED,
            shard="shard-b",
        )
        # the failed overwrite must not clobber the existing cell
        self.assertEqual(
            coverage.COMPLETED, ledger.get("B901", "a.py").state
        )

    def test_source_digest_mismatch_raises(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.COMPLETED)
        self.assertRaises(
            coverage.CoverageConflictError,
            ledger.record,
            "B901",
            "a.py",
            coverage.COMPLETED,
            source_digest="digest-b",
            shard="shard-b",
        )

    def test_config_digest_mismatch_raises(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.COMPLETED)
        other = self._ledger(shard="shard-b", config_digest="other-cfg")
        other.record("B901", "a.py", coverage.COMPLETED)
        self.assertRaises(
            coverage.CoverageConflictError, ledger.merge, other
        )

    def test_merge_ledgers(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.COMPLETED)
        other = self._ledger(shard="shard-b")
        other.record("B902", "a.py", coverage.FAILED, detail="boom")
        ledger.merge(other)
        summary = ledger.summary()
        self.assertEqual(1, summary[coverage.COMPLETED])
        self.assertEqual(1, summary[coverage.FAILED])
        self.assertEqual(
            {"shard-b"}, ledger.get("B902", "a.py").shards
        )

    def test_record_without_digest_raises(self):
        ledger = coverage.CoverageLedger(config_digest="cfg")
        self.assertRaises(
            KeyError,
            ledger.record,
            "B901",
            "unknown.py",
            coverage.SELECTED,
        )

    def test_report_points_at_failed_cell(self):
        ledger = self._ledger()
        ledger.record("B901", "a.py", coverage.COMPLETED)
        ledger.record("B902", "a.py", coverage.FAILED, detail="boom")
        report = ledger.report()
        failed = [l for l in report.splitlines() if l.startswith("FAILED")]
        self.assertEqual(1, len(failed))
        self.assertIn("B902", failed[0])
        self.assertIn("a.py", failed[0])
        self.assertIn("shard-a", failed[0])
        self.assertIn("failed=1", report.splitlines()[0])


class ManagerCoverageTests(testtools.TestCase):
    FILES = {
        "alpha.py": "x = 'hello'\n",
        "beta.py": "y = 'world'\n",
        "gamma.py": "z = 'boom'\n",
        "delta.py": "n = 1\n",
        "epsilon.py": "s = 'safe'\n",
    }

    def setUp(self):
        super().setUp()
        extman = extension_loader.MANAGER
        self.patch(
            extman,
            "plugins",
            [_FakeExtension(plugin_alpha), _FakeExtension(plugin_beta)],
        )
        self.patch(
            extman,
            "plugins_by_id",
            {"B901": extman.plugins[0], "B902": extman.plugins[1]},
        )
        self.patch(extman, "blacklist", {})
        self.config = config.BanditConfig()
        self.tmp = self.useFixture(fixtures.TempDir()).path

    def _write_files(self, files):
        for name, content in files.items():
            with open(os.path.join(self.tmp, name), "w") as fd:
                fd.write(content)

    def _make_manager(self, shard, profile=None):
        if profile is None:
            profile = {"include": ["B901", "B902"]}
        return manager.BanditManager(
            config=self.config,
            agg_type="file",
            profile=profile,
            shard=shard,
        )

    def _run(self, mgr):
        mgr.discover_files([self.tmp], recursive=True)
        mgr.run_tests()

    def test_zero_alerts_unique_failed_cell(self):
        self._write_files(self.FILES)
        mgr = self._make_manager("shard-a")
        self._run(mgr)

        # both plugins stay silent: the scan reports zero issues
        self.assertEqual([], mgr.results)

        # 2 plugins x 5 files = 10 cells, exactly one of them failed
        summary = mgr.coverage.summary()
        self.assertEqual(10, sum(summary.values()))
        self.assertEqual(9, summary[coverage.COMPLETED])
        self.assertEqual(1, summary[coverage.FAILED])
        self.assertEqual(0, summary[coverage.SKIPPED])

        failures = mgr.coverage.failures()
        self.assertEqual(1, len(failures))
        cell = failures[0]
        self.assertEqual("B902", cell.rule_id)
        self.assertTrue(cell.fname.endswith("gamma.py"))
        self.assertEqual({"shard-a"}, cell.shards)
        self.assertEqual("boom", cell.detail)

        # the report directly identifies the unique failing cell
        report = mgr.get_coverage_report()
        failed = [l for l in report.splitlines() if l.startswith("FAILED")]
        self.assertEqual(1, len(failed))
        self.assertIn("B902", failed[0])
        self.assertIn("gamma.py", failed[0])
        self.assertIn("shard-a", failed[0])

    def test_parse_exception_marks_file_cells_failed(self):
        self._write_files(
            {
                "ok.py": "x = 'fine'\n",
                "broken.py": "def broken(:\n",
            }
        )
        mgr = self._make_manager("shard-b")
        self._run(mgr)

        self.assertEqual([], mgr.results)
        self.assertEqual(1, len(mgr.get_skipped()))

        summary = mgr.coverage.summary()
        self.assertEqual(2, summary[coverage.COMPLETED])
        self.assertEqual(2, summary[coverage.FAILED])
        for cell in mgr.coverage.failures():
            self.assertTrue(cell.fname.endswith("broken.py"))
            self.assertIn("syntax error", cell.detail)

    def test_unselected_rule_marked_skipped(self):
        self._write_files(self.FILES)
        mgr = self._make_manager("shard-a", profile={"include": ["B901"]})
        self._run(mgr)

        summary = mgr.coverage.summary()
        self.assertEqual(5, summary[coverage.SKIPPED])
        for cell in mgr.coverage.cells_by_state(coverage.SKIPPED):
            self.assertEqual("B902", cell.rule_id)
            self.assertEqual("rule not selected", cell.detail)

    def test_offline_shards_merge_to_unique_failed_cell(self):
        # shard-a scans three files, shard-b scans the other two; both
        # report zero issues, the merged ledger shows the one bad cell
        names = sorted(self.FILES)
        for name in names[:3]:
            self._write_files({name: self.FILES[name]})
        mgr_a = self._make_manager("shard-a")
        self._run(mgr_a)
        for name in names[3:]:
            self._write_files({name: self.FILES[name]})
        mgr_b = self._make_manager("shard-b")
        self._run(mgr_b)

        self.assertEqual([], mgr_a.results)
        self.assertEqual([], mgr_b.results)

        mgr_a.coverage.merge(mgr_b.coverage)
        summary = mgr_a.coverage.summary()
        self.assertEqual(10, sum(summary.values()))
        self.assertEqual(1, summary[coverage.FAILED])

        report = mgr_a.get_coverage_report()
        failed = [l for l in report.splitlines() if l.startswith("FAILED")]
        self.assertEqual(1, len(failed))
        self.assertIn("B902", failed[0])
        self.assertIn("gamma.py", failed[0])
        self.assertIn("shard-b", failed[0])

    def test_same_shard_rerun_replaces_cells(self):
        self._write_files(self.FILES)
        mgr = self._make_manager("shard-a")
        self._run(mgr)
        # re-running the same shard replaces its old cells in place
        self._run(mgr)
        summary = mgr.coverage.summary()
        self.assertEqual(10, sum(summary.values()))
        self.assertEqual(1, summary[coverage.FAILED])

    def test_conflicting_shard_not_silently_merged(self):
        self._write_files(self.FILES)
        mgr_a = self._make_manager("shard-a")
        self._run(mgr_a)
        # same files scanned by another shard with a different config
        mgr_b = self._make_manager("shard-b", profile={"include": ["B901"]})
        self._run(mgr_b)
        self.assertRaises(
            coverage.CoverageConflictError,
            mgr_a.coverage.merge,
            mgr_b.coverage,
        )
        # the failed merge leaves the original cells untouched
        summary = mgr_a.coverage.summary()
        self.assertEqual(10, sum(summary.values()))
        self.assertEqual(1, summary[coverage.FAILED])

    def test_nosec_marks_cell_skipped(self):
        def plugin_flag(context):
            return issue.Issue(
                constants.MEDIUM,
                issue.Cwe.MULTIPLE_BINDS,
                constants.MEDIUM,
                "flagged",
            )

        plugin_flag._test_id = "B901"
        plugin_flag._checks = ["Str"]
        extman = extension_loader.MANAGER
        self.patch(extman, "plugins", [_FakeExtension(plugin_flag)])
        self.patch(extman, "plugins_by_id", {"B901": extman.plugins[0]})
        self._write_files({"nosec.py": "token = 'abc'  # nosec\n"})
        mgr = self._make_manager("shard-a", profile={"include": ["B901"]})
        self._run(mgr)

        self.assertEqual([], mgr.results)
        cell = mgr.coverage.get(
            "B901", os.path.join(self.tmp, "nosec.py")
        )
        self.assertEqual(coverage.SKIPPED, cell.state)
        self.assertEqual("nosec", cell.detail)
