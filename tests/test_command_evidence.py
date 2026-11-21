# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_command_evidence.py

<Author>
  The in-toto contributors

<Started>
  Nov 21, 2026

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test command evidence library interface in in_toto/command_evidence.py.

"""

import hashlib
import json
import unittest
from pathlib import Path

from in_toto.command_evidence import (
    CommandEvidenceExpectation,
    EvidenceStatus,
    collect_command_evidence,
    verify_command_evidence,
)
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock

DEMO_LINK = Path(__file__).parent / "demo_files" / "write-code.776a00e2.link"


class FakeExecutor:
    """Local fake executor: runs nothing, but leaves link records behind.

    Mimics a build tool that either records full command evidence
    (working directory, executable digest, environment markers) or only
    the command arguments.
    """

    def __init__(self, workdir=None, executable_hashes=None, variables=None):
        self.workdir = workdir
        self.executable_hashes = executable_hashes
        self.variables = variables

    def execute(self, name, cmd_args, env_markers=(), record_evidence=True):
        environment = {}
        if record_evidence:
            environment = collect_command_evidence(
                workdir=self.workdir,
                executable_hashes=self.executable_hashes,
                variables=self.variables,
                env_markers=env_markers,
            )
        return Link(
            name=name,
            command=list(cmd_args),
            materials={},
            products={},
            byproducts={"stdout": "", "stderr": "", "return-value": 0},
            environment=environment,
        )


class TestCommandEvidence(unittest.TestCase):
    """Verify command evidence of two links that declare the same command."""

    @classmethod
    def setUpClass(cls):
        # Approved tool directory with a fake executable
        cls.tool_dir = "/approved/tools"
        cls.executable_hashes = {
            "sha256": hashlib.sha256(b"fake build tool").hexdigest()
        }
        cls.command = ["fake-tool", "--build", "foo.tar.gz"]
        cls.env_markers = ("PATH", "BUILD_ID")
        cls.variables = [
            "PATH=/approved/tools/bin",
            "BUILD_ID=42",
            "SECRET_TOKEN=hunter2",
        ]

        executor = FakeExecutor(
            workdir=cls.tool_dir,
            executable_hashes=cls.executable_hashes,
            variables=cls.variables,
        )
        # Link launched from the approved tool directory, with evidence
        cls.evidence_link = executor.execute(
            "build", cls.command, env_markers=cls.env_markers
        )
        # Link that only records the command arguments
        cls.declared_link = executor.execute(
            "build", cls.command, record_evidence=False
        )

        cls.expectation = CommandEvidenceExpectation(
            workdir=cls.tool_dir,
            executable_hashes=cls.executable_hashes,
            env_markers=cls.env_markers,
        )

    def test_collect_command_evidence_records_only_markers(self):
        """Evidence collection keeps approved data, drops sensitive values."""
        environment = collect_command_evidence(
            workdir=self.tool_dir,
            executable_hashes=self.executable_hashes,
            variables=self.variables,
            env_markers=self.env_markers,
        )
        self.assertEqual(environment["workdir"], self.tool_dir)
        self.assertEqual(environment["executable"], self.executable_hashes)
        # Only marker names are recorded, no values, no unlisted variables
        self.assertEqual(environment["variables"], ["BUILD_ID", "PATH"])
        self.assertNotIn(
            "hunter2", json.dumps(environment), "sensitive value leaked"
        )
        self.assertNotIn("SECRET_TOKEN", json.dumps(environment))

    def test_verify_evidence_link(self):
        """Link with recorded evidence is fully verified."""
        report = verify_command_evidence(self.evidence_link, self.expectation)
        self.assertEqual(report.status, EvidenceStatus.VERIFIED)
        for name in ("workdir", "executable", "env:PATH", "env:BUILD_ID"):
            self.assertEqual(
                report.check(name).status, EvidenceStatus.VERIFIED
            )

    def test_verify_declared_link(self):
        """Link with only command arguments is reported as declared-only."""
        report = verify_command_evidence(self.declared_link, self.expectation)
        self.assertEqual(report.status, EvidenceStatus.DECLARED)
        for name in ("workdir", "executable", "env:PATH", "env:BUILD_ID"):
            self.assertEqual(
                report.check(name).status, EvidenceStatus.DECLARED
            )

    def test_diff_identifies_missing_program_identity(self):
        """Auditor sees from the diff which link lacks program identity."""
        evidence_report = verify_command_evidence(
            self.evidence_link, self.expectation
        )
        declared_report = verify_command_evidence(
            self.declared_link, self.expectation
        )
        difference = evidence_report.diff(declared_report)
        self.assertEqual(
            difference["executable"],
            {
                "self": EvidenceStatus.VERIFIED,
                "other": EvidenceStatus.DECLARED,
            },
        )
        self.assertEqual(
            difference["workdir"],
            {
                "self": EvidenceStatus.VERIFIED,
                "other": EvidenceStatus.DECLARED,
            },
        )
        # Identical reports produce an empty diff
        self.assertEqual(evidence_report.diff(evidence_report), {})

    def test_conflicting_evidence(self):
        """Recorded evidence contradicting the expectation is a conflict."""
        wrong_expectation = CommandEvidenceExpectation(
            workdir="/some/other/directory",
            executable_hashes={"sha256": "0" * 64},
            env_markers=("PATH",),
        )
        report = verify_command_evidence(self.evidence_link, wrong_expectation)
        self.assertEqual(report.status, EvidenceStatus.CONFLICT)
        self.assertEqual(
            report.check("workdir").status, EvidenceStatus.CONFLICT
        )
        self.assertEqual(
            report.check("executable").status, EvidenceStatus.CONFLICT
        )
        self.assertEqual(
            report.check("env:PATH").status, EvidenceStatus.VERIFIED
        )

    def test_report_contains_no_sensitive_values(self):
        """Reports never include environment variable values."""
        report = verify_command_evidence(self.evidence_link, self.expectation)
        serialized = json.dumps(report.to_dict())
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("SECRET_TOKEN", serialized)
        self.assertNotIn("/approved/tools/bin", serialized)

    def test_old_link_still_parses(self):
        """Old links without evidence parse and verify as declared-only."""
        metablock = Metablock.load(str(DEMO_LINK))
        link = metablock.signed
        self.assertIsInstance(link, Link)
        report = verify_command_evidence(link, self.expectation)
        self.assertEqual(report.status, EvidenceStatus.DECLARED)

    def test_old_style_variables_with_values(self):
        """Old-style KEY=VALUE environment entries verify by name only."""
        link = Link(
            name="build",
            command=self.command,
            materials={},
            products={},
            byproducts={},
            environment={
                "workdir": self.tool_dir,
                "variables": ["PATH=/approved/tools/bin", "BUILD_ID=42"],
            },
        )
        expectation = CommandEvidenceExpectation(
            workdir=self.tool_dir, env_markers=self.env_markers
        )
        report = verify_command_evidence(link, expectation)
        self.assertEqual(report.status, EvidenceStatus.VERIFIED)
        # Values from the old-style entries must not leak into the report
        self.assertNotIn("/approved/tools/bin", json.dumps(report.to_dict()))


if __name__ == "__main__":
    unittest.main()
