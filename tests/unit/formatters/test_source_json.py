#
# SPDX-License-Identifier: Apache-2.0
import json
import tempfile

import testtools

import bandit
from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.core import metrics
from bandit.core import source_map
from bandit.formatters import source_json


def _make_issue(lineno, linerange, text, test_id="B602"):
    result = issue.Issue(
        bandit.LOW,
        issue.Cwe.OS_COMMAND_INJECTION,
        bandit.HIGH,
        text,
        lineno=lineno,
        test_id=test_id,
    )
    result.fname = "build/generated.py"
    result.linerange = linerange
    result.test = "subprocess_popen_with_shell_equals_true"
    return result


class SourceJsonFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(
            conf, "file", source_map=self._build_map()
        )
        _, self.tmp_fname = tempfile.mkstemp()

        first = _make_issue(4, [4], "first finding")
        second = _make_issue(4, [4, 5, 6, 7, 8, 9, 10],
                        "finding crossing a breakpoint")
        third = _make_issue(11, [11], "third finding", test_id="B506")
        self.manager.results.extend([first, second, third])
        self.manager.apply_source_map()
        self.manager.metrics = metrics.Metrics()
        for key in ["_totals", "build/generated.py"]:
            self.manager.metrics.data[key] = {"loc": 12, "nosec": 0}
            for criteria, default in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics.data[key][
                        "%s.%s" % (criteria, rank)
                    ] = 0

    def _build_map(self):
        return source_map.SourceMap(
            files={
                "build/generated.py": [
                    source_map.SourceSegment(
                        1, 4, "template_a.tmpl", 10, 13
                    ),
                    source_map.SourceSegment(
                        7, 9, "template_b.tmpl", 20, 22
                    ),
                    source_map.SourceSegment(
                        7, 9, "hand_written.py", 3, 3
                    ),
                    source_map.SourceSegment(
                        10, 12, "template_a.tmpl", 30, 32
                    ),
                ]
            },
            verify_files=False,
        )

    def _render(self):
        with open(self.tmp_fname, "w") as handle:
            source_json.report(
                self.manager,
                handle,
                constants.LOW,
                constants.LOW,
            )
        with open(self.tmp_fname) as handle:
            return json.loads(handle.read())

    def test_keeps_real_scan_evidence(self):
        data = self._render()
        by_text = {r["issue_text"]: r for r in data["results"]}
        crossing = by_text["finding crossing a breakpoint"]
        self.assertEqual("build/generated.py", crossing["filename"])
        self.assertEqual(4, crossing["line_number"])
        self.assertEqual([4, 5, 6, 7, 8, 9, 10], crossing["line_range"])
        self.assertIn("source_refs", crossing)

    def test_groups_are_keyed_by_source_location(self):
        data = self._render()
        groups = data["source_groups"]
        mapped = [g for g in groups if g["status"] == "mapped"]

        # the one-to-many region places the crossing finding in both source
        # files
        hand_written = next(
            g for g in mapped if g["source_file"] == "hand_written.py"
        )
        self.assertEqual(3, hand_written["source_line"])
        self.assertEqual(
            ["finding crossing a breakpoint"],
            [f["issue_text"] for f in hand_written["findings"]],
        )

        template_b = next(
            g for g in mapped if g["source_file"] == "template_b.tmpl"
        )
        # range-only group must not fabricate a unique line
        self.assertIsNone(template_b["source_line"])
        self.assertEqual(20, template_b["source_start"])
        self.assertEqual(22, template_b["source_end"])

    def test_crossing_finding_has_breakpoint_candidates(self):
        data = self._render()
        crossing = next(
            r
            for r in data["results"]
            if r["issue_text"] == "finding crossing a breakpoint"
        )
        refs = crossing["source_refs"]
        reasons = [ref.get("reason") for ref in refs if ref["status"] ==
                   "invalid"]
        self.assertIn(source_map.REASON_UNMAPPED_GAP, reasons)
        # every source line in the report comes from map data
        for ref in refs:
            if ref["status"] == "mapped" and ref["source_line"] is None:
                self.assertIsNotNone(ref["source_start"])

    def test_baseline_input_is_rejected(self):
        import collections

        baseline = collections.OrderedDict()
        issue_obj = self.manager.results[0]
        baseline[issue_obj] = [issue_obj]
        self.patch(
            self.manager, "get_issue_list", lambda *a, **k: baseline
        )
        with open(self.tmp_fname, "w") as handle:
            self.assertRaises(
                RuntimeError,
                source_json.report,
                self.manager,
                handle,
                constants.LOW,
                constants.LOW,
            )
