# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  command_evidence.py

<Author>
  The in-toto contributors

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides a library interface to record and verify command execution
  evidence in link metadata.

  Two links may declare the same command while differing in the evidence
  that backs it: one may have been launched from an approved tool
  directory, recording the working directory, a digest of the actual
  executable and selected environment markers, while another only
  records the command arguments. This module lets callers explicitly
  choose what is publishable (working directory, executable digest and a
  limited set of environment variable markers) and classifies each piece
  of evidence as "verified", "declared" (only claimed, not backed by
  recorded evidence) or "conflict" (recorded evidence contradicts the
  expectation).

  Sensitive environment values are never included in evidence reports:
  only the caller-approved variable names (markers) appear, never their
  values.
"""

import attr

# Keys used inside the opaque ``environment`` dict of a link.
WORKDIR_KEY = "workdir"
EXECUTABLE_KEY = "executable"
VARIABLES_KEY = "variables"


class EvidenceStatus:
    """Classification of a single piece of command evidence."""

    VERIFIED = "verified"
    DECLARED = "declared"
    CONFLICT = "conflict"


def _variable_key(entry):
    """Returns the variable name of an environment entry.

    Accepts both new-style entries that record only the variable name
    ("KEY") and old-style entries that record name and value
    ("KEY=VALUE"), so that older links remain verifiable.
    """
    return entry.split("=", 1)[0]


@attr.s(repr=False, init=False)
class CommandEvidenceExpectation:
    """Caller-selected, publishable expectations for command evidence.

    Attributes:
      workdir: Optional working directory the caller allows to be
          published and expects the command to have run in.

      executable_hashes: Optional hash dictionary
          ("<hash algorithm>": "<hex digest>") of the actual executable,
          used to locate the program identity.

      env_markers: Optional tuple of environment variable names that the
          caller allows to be published and expects to be recorded. Only
          the names are ever used; values are never published or
          reported.
    """

    workdir = attr.ib()
    executable_hashes = attr.ib()
    env_markers = attr.ib()

    def __init__(self, workdir=None, executable_hashes=None, env_markers=()):
        self.workdir = workdir
        self.executable_hashes = (
            dict(executable_hashes) if executable_hashes else None
        )
        self.env_markers = tuple(env_markers or ())


@attr.s(repr=False, init=False)
class EvidenceCheck:
    """Outcome of verifying one piece of command evidence.

    Attributes:
      name: The name of the check, e.g. "workdir", "executable" or
          "env:<VARIABLE NAME>".

      status: One of EvidenceStatus.VERIFIED, EvidenceStatus.DECLARED or
          EvidenceStatus.CONFLICT.

      detail: A human-readable, non-sensitive explanation. It never
          contains environment variable values.
    """

    name = attr.ib()
    status = attr.ib()
    detail = attr.ib()

    def __init__(self, name, status, detail=""):
        self.name = name
        self.status = status
        self.detail = detail

    def to_dict(self):
        """Returns a JSON-serializable dict representation."""
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
        }


@attr.s(repr=False, init=False)
class CommandEvidenceReport:
    """Result of verifying a link's command evidence against an
    expectation.

    Attributes:
      name: The name of the inspected link.

      command: The command declared by the link.

      checks: A list of EvidenceCheck, one per requested piece of
          evidence.
    """

    name = attr.ib()
    command = attr.ib()
    checks = attr.ib()

    def __init__(self, name, command, checks):
        self.name = name
        self.command = list(command or [])
        self.checks = list(checks)

    @property
    def status(self):
        """Aggregated status: CONFLICT if any check conflicts, else
        DECLARED if any check is only declared, else VERIFIED."""
        statuses = {check.status for check in self.checks}
        if EvidenceStatus.CONFLICT in statuses:
            return EvidenceStatus.CONFLICT
        if EvidenceStatus.DECLARED in statuses:
            return EvidenceStatus.DECLARED
        return EvidenceStatus.VERIFIED

    def check(self, name):
        """Returns the EvidenceCheck with the passed name, or None."""
        for check_ in self.checks:
            if check_.name == name:
                return check_
        return None

    def to_dict(self):
        """Returns a JSON-serializable dict representation. Contains no
        environment variable values."""
        return {
            "name": self.name,
            "command": list(self.command),
            "status": self.status,
            "checks": [check.to_dict() for check in self.checks],
        }

    def diff(self, other):
        """Compares this report with another report check by check.

        Arguments:
          other: Another CommandEvidenceReport.

        Returns:
          A dict mapping each check name whose status differs to a dict
          of the form {"self": <status or None>, "other": <status or
          None>}. An empty dict means the reports agree.
        """
        difference = {}
        names = {check.name for check in self.checks} | {
            check.name for check in other.checks
        }
        for name in sorted(names):
            self_check = self.check(name)
            other_check = other.check(name)
            self_status = self_check.status if self_check else None
            other_status = other_check.status if other_check else None
            if self_status != other_status:
                difference[name] = {
                    "self": self_status,
                    "other": other_status,
                }
        return difference


def collect_command_evidence(
    workdir=None, executable_hashes=None, variables=None, env_markers=()
):
    """Builds a link ``environment`` dict with caller-approved evidence.

    Only data the caller explicitly selects is included. Environment
    variables are reduced to their names (markers); values are never
    recorded.

    Arguments:
      workdir (optional): The publishable working directory the command
          was executed in.

      executable_hashes (optional): A hash dictionary
          ("<hash algorithm>": "<hex digest>") of the actual executable,
          identifying the program that was run.

      variables (optional): An iterable of environment entries, either
          "KEY=VALUE" pairs or bare "KEY" names. Only entries whose name
          is listed in ``env_markers`` are recorded, and only their
          names.

      env_markers (optional): An iterable of environment variable names
          that may be published.

    Returns:
      A dict suitable for the ``environment`` field of a link.
    """
    environment = {}

    if workdir is not None:
        environment[WORKDIR_KEY] = workdir

    if executable_hashes:
        environment[EXECUTABLE_KEY] = dict(executable_hashes)

    markers = set(env_markers or ())
    if variables:
        recorded = sorted(
            {
                _variable_key(entry)
                for entry in variables
                if _variable_key(entry) in markers
            }
        )
        if recorded:
            environment[VARIABLES_KEY] = recorded

    return environment


def _verify_workdir(environment, expected_workdir):
    recorded = environment.get(WORKDIR_KEY)
    if recorded is None:
        return EvidenceCheck(
            "workdir",
            EvidenceStatus.DECLARED,
            "link does not record a working directory",
        )
    if recorded != expected_workdir:
        return EvidenceCheck(
            "workdir",
            EvidenceStatus.CONFLICT,
            f"recorded working directory '{recorded}' does not match "
            f"expected '{expected_workdir}'",
        )
    return EvidenceCheck(
        "workdir",
        EvidenceStatus.VERIFIED,
        f"working directory '{recorded}' matches expectation",
    )


def _verify_executable(environment, expected_hashes):
    recorded = environment.get(EXECUTABLE_KEY)
    if not recorded:
        return EvidenceCheck(
            "executable",
            EvidenceStatus.DECLARED,
            "link does not record an executable digest; the program "
            "identity cannot be located",
        )
    mismatched = [
        algorithm
        for algorithm, digest in expected_hashes.items()
        if recorded.get(algorithm) != digest
    ]
    if mismatched:
        return EvidenceCheck(
            "executable",
            EvidenceStatus.CONFLICT,
            "recorded executable digest does not match expectation for "
            f"algorithm(s): {', '.join(sorted(mismatched))}",
        )
    return EvidenceCheck(
        "executable",
        EvidenceStatus.VERIFIED,
        "executable digest matches expectation for algorithm(s): "
        f"{', '.join(sorted(expected_hashes))}",
    )


def _verify_env_marker(environment, marker):
    variables = environment.get(VARIABLES_KEY) or []
    recorded_keys = {_variable_key(entry) for entry in variables}
    if marker in recorded_keys:
        return EvidenceCheck(
            f"env:{marker}",
            EvidenceStatus.VERIFIED,
            f"environment marker '{marker}' is recorded",
        )
    return EvidenceCheck(
        f"env:{marker}",
        EvidenceStatus.DECLARED,
        f"environment marker '{marker}' is not recorded",
    )


def verify_command_evidence(link, expectation):
    """Verifies a link's command evidence against caller expectations.

    Each piece of evidence requested in the expectation is classified as
    "verified" (recorded and matching), "declared" (not recorded, only
    the command itself is claimed) or "conflict" (recorded but
    contradicting the expectation). Links without any recorded evidence,
    including links created by older versions, are accepted and reported
    as "declared".

    Arguments:
      link: A Link object (see in_toto.models.link.Link).

      expectation: A CommandEvidenceExpectation with the caller-selected
          publishable working directory, executable digest and
          environment markers.

    Returns:
      A CommandEvidenceReport. The report contains no environment
      variable values.
    """
    environment = link.environment or {}

    checks = []
    if expectation.workdir is not None:
        checks.append(_verify_workdir(environment, expectation.workdir))
    if expectation.executable_hashes:
        checks.append(
            _verify_executable(environment, expectation.executable_hashes)
        )
    for marker in expectation.env_markers:
        checks.append(_verify_env_marker(environment, marker))

    return CommandEvidenceReport(
        name=link.name, command=link.command, checks=checks
    )
