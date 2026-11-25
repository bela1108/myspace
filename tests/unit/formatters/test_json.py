# Copyright (c) 2015 VMware, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import collections
import json
import tempfile
from unittest import mock

import testtools

import bandit
from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.core import metrics
from bandit.formatters import json as b_json


class JsonFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            bandit.MEDIUM,
            "Possible binding to all interfaces.",
        )

        self.candidates = [
            issue.Issue(
                issue.Cwe.MULTIPLE_BINDS,
                bandit.LOW,
                bandit.LOW,
                "Candidate A",
                lineno=1,
            ),
            issue.Issue(
                bandit.HIGH,
                issue.Cwe.MULTIPLE_BINDS,
                bandit.HIGH,
                "Candiate B",
                lineno=2,
            ),
        ]

        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)
        self.manager.metrics = metrics.Metrics()

        # mock up the metrics
        for key in ["_totals", "binding.py"]:
            self.manager.metrics.data[key] = {"loc": 4, "nosec": 2}
            for criteria, default in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics.data[key][f"{criteria}.{rank}"] = 0

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report(self, get_issue_list):
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]

        get_issue_list.return_value = collections.OrderedDict(
            [(self.issue, self.candidates)]
        )

        with open(self.tmp_fname, "w") as tmp_file:
            b_json.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertIsNotNone(data["generated_at"])
            self.assertEqual(self.tmp_fname, data["results"][0]["filename"])
            self.assertEqual(
                self.issue.severity, data["results"][0]["issue_severity"]
            )
            self.assertEqual(
                self.issue.confidence, data["results"][0]["issue_confidence"]
            )
            self.assertEqual(self.issue.text, data["results"][0]["issue_text"])
            self.assertEqual(
                self.context["lineno"], data["results"][0]["line_number"]
            )
            self.assertEqual(
                self.context["linerange"], data["results"][0]["line_range"]
            )
            self.assertEqual(self.check_name, data["results"][0]["test_name"])
            self.assertIn("candidates", data["results"][0])
            self.assertIn("more_info", data["results"][0])
            self.assertIsNotNone(data["results"][0]["more_info"])

    def test_baseline_filter_and_json_report(self):
        old_path = "audit_handoff/legacy_placeholder.py"
        new_path = "audit_handoff/followup_placeholder.py"

        baseline_report = {
            "results": [
                {
                    "code": "placeholder_value = 1\n",
                    "filename": old_path,
                    "issue_severity": constants.LOW,
                    "issue_cwe": {},
                    "issue_confidence": constants.MEDIUM,
                    "issue_text": "registered placeholder finding",
                    "test_name": "placeholder_check",
                    "test_id": "B998",
                    "line_number": 3,
                    "line_range": [3],
                }
            ]
        }
        self.manager.populate_baseline(json.dumps(baseline_report))

        def mock_issue(
            path, test_id, line_number, severity, confidence, text
        ):
            mocked = mock.Mock(spec=issue.Issue)
            mocked.filter.return_value = True
            mocked.fname = path
            mocked.test = "placeholder_check"
            mocked.test_id = test_id
            mocked.lineno = line_number
            mocked.severity = severity
            mocked.cwe = issue.Cwe(issue.Cwe.NOTSET)
            mocked.confidence = confidence
            mocked.text = text
            mocked.as_dict.return_value = {
                "filename": path,
                "test_name": "placeholder_check",
                "test_id": test_id,
                "issue_severity": severity,
                "issue_cwe": {},
                "issue_confidence": confidence,
                "issue_text": text,
                "line_number": line_number,
                "line_range": [line_number],
                "code": "",
            }
            return mocked

        old_issue = mock_issue(
            old_path,
            "B998",
            3,
            constants.LOW,
            constants.MEDIUM,
            "registered placeholder finding",
        )
        new_issue = mock_issue(
            new_path,
            "B999",
            8,
            constants.MEDIUM,
            constants.HIGH,
            "independent placeholder finding",
        )
        self.manager.results = [old_issue, new_issue]

        filtered = self.manager.filter_results(
            constants.LOW, constants.LOW
        )

        self.assertIsInstance(filtered, collections.OrderedDict)
        self.assertEqual([new_issue], list(filtered))
        self.assertEqual([new_issue], filtered[new_issue])

        self.manager.metrics = metrics.Metrics()
        self.manager.metrics.data["_totals"]["SEVERITY.LOW"] = 1
        self.manager.metrics.data["_totals"]["SEVERITY.MEDIUM"] = 1

        with open(self.tmp_fname, "w") as report_file:
            b_json.report(
                self.manager,
                report_file,
                constants.LOW,
                constants.LOW,
            )

        with open(self.tmp_fname) as report_file:
            report = json.load(report_file)

        self.assertEqual(
            [new_path],
            [item["filename"] for item in report["results"]],
        )
        retained = report["results"][0]
        self.assertEqual("B999", retained["test_id"])
        self.assertEqual(
            "independent placeholder finding", retained["issue_text"]
        )
        self.assertNotIn("candidates", retained)
        self.assertEqual(
            1, report["metrics"]["_totals"]["SEVERITY.LOW"]
        )
