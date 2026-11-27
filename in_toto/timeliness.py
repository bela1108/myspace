# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  timeliness.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Nov 28, 2026

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides interval-based timeliness evaluation for link metadata.

  A link may record when a step was performed on a machine whose clock is
  not trusted by the verifier. To still reason about deadlines, a trusted
  independent clock may attest a *range* of time
  (``trusted_time_range``, with ``earliest`` and ``latest`` bounds) inside
  the signed link metadata. Because the attestation is part of the signed
  payload, the range cannot be altered without breaking the signature.

  Timeliness is decided by comparing the whole trusted range against a
  deadline, never by comparing point estimates such as midpoints:

  - ``on-time``: the entire range is at or before the deadline, so the
    step certainly finished within the window.
  - ``late``: the entire range is after the deadline, so the step
    certainly finished too late.
  - ``undecidable``: the range crosses the deadline, i.e. clock
    uncertainty makes it impossible to decide whether the step was on
    time.

"""

import datetime
import logging

import attr
import iso8601
import securesystemslib.exceptions

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

# Well-known key in a link's ``environment`` dictionary that carries a
# trusted time range attested by an independent clock.
TRUSTED_TIME_RANGE_ENV_KEY = "trusted_time_range"

# Well-known key in the summary link's ``environment`` dictionary under
# which the timeliness report of a verification run is stored.
TIMELINESS_REPORT_ENV_KEY = "timeliness_report"

# Timeliness verdicts
ON_TIME = "on-time"
LATE = "late"
UNDECIDABLE = "undecidable"

VERDICTS = (ON_TIME, LATE, UNDECIDABLE)


def _parse_datetime(value, field_name):
    """Parse an ISO 8601 string into a datetime, pass datetimes through."""
    if isinstance(value, str):
        try:
            value = iso8601.parse_date(value)
        except iso8601.ParseError as e:
            raise securesystemslib.exceptions.FormatError(
                f"Invalid {field_name}: '{value}' is not a valid"
                f" ISO 8601 datetime: {e}"
            ) from e

    if not isinstance(value, datetime.datetime):
        raise securesystemslib.exceptions.FormatError(
            f"Invalid {field_name}: expected ISO 8601 string or datetime,"
            f" got: {type(value)}"
        )

    if value.tzinfo is None:
        raise securesystemslib.exceptions.FormatError(
            f"Invalid {field_name}: datetime must be timezone-aware,"
            f" got naive datetime: {value}"
        )

    return value


@attr.s(repr=False, init=False)
class TrustedTimeRange:
    """A trusted range of time attested by an independent clock.

    The actual time an event occurred is only known to lie within
    ``[earliest, latest]``. Both bounds must be timezone-aware datetimes
    or ISO 8601 strings.

    Attributes:
      earliest: The earliest time the attested event may have occurred.

      latest: The latest time the attested event may have occurred.

    """

    earliest = attr.ib()
    latest = attr.ib()

    def __init__(self, earliest, latest):
        super().__init__()
        self.earliest = _parse_datetime(earliest, "earliest")
        self.latest = _parse_datetime(latest, "latest")
        self.validate()

    def validate(self):
        """Check that the range is well-formed, i.e. earliest <= latest."""
        if self.earliest > self.latest:
            raise securesystemslib.exceptions.FormatError(
                "Invalid trusted time range: 'earliest'"
                f" ({self.earliest.isoformat()}) is after 'latest'"
                f" ({self.latest.isoformat()})"
            )

    def to_dict(self):
        """Return the JSON-serializable dict representation of the range."""
        return {
            "earliest": self.earliest.isoformat(),
            "latest": self.latest.isoformat(),
        }

    @staticmethod
    def from_dict(data):
        """Create a TrustedTimeRange from its dict representation."""
        if not isinstance(data, dict):
            raise securesystemslib.exceptions.FormatError(
                f"Invalid trusted time range: expected dict, got: {type(data)}"
            )

        try:
            return TrustedTimeRange(data["earliest"], data["latest"])
        except KeyError as e:
            raise securesystemslib.exceptions.FormatError(
                f"Invalid trusted time range: missing field {e}"
            ) from e


@attr.s(repr=False, init=False)
class TimelinessReport:
    """The result of evaluating a trusted time range against a deadline.

    Attributes:
      verdict: One of ``on-time``, ``late`` or ``undecidable``.

      deadline: The deadline the trusted time range was evaluated against.

      time_range: The evaluated TrustedTimeRange, or None if the link did
          not carry a trusted time range.

      reason: A human-readable explanation of the verdict.

    """

    verdict = attr.ib()
    deadline = attr.ib()
    time_range = attr.ib()
    reason = attr.ib()

    def __init__(self, verdict, deadline, time_range, reason):
        super().__init__()
        if verdict not in VERDICTS:
            raise ValueError(f"Invalid timeliness verdict: '{verdict}'")
        self.verdict = verdict
        self.deadline = _parse_datetime(deadline, "deadline")
        self.time_range = time_range
        self.reason = reason

    def to_dict(self):
        """Return the JSON-serializable dict representation of the report."""
        return {
            "verdict": self.verdict,
            "deadline": self.deadline.isoformat(),
            "trusted_time_range": (
                self.time_range.to_dict() if self.time_range else None
            ),
            "reason": self.reason,
        }


def evaluate_timeliness(time_range, deadline):
    """Evaluate a trusted time range against a deadline.

    The comparison uses the bounds of the range, never a point estimate
    such as its midpoint:

    - If the latest possible time is at or before the deadline, the event
      is certainly ``on-time``.
    - If the earliest possible time is after the deadline, the event is
      certainly ``late``.
    - Otherwise the range crosses the deadline and clock uncertainty
      makes the relationship ``undecidable``.

    Arguments:
      time_range: A TrustedTimeRange object.

      deadline: A timezone-aware datetime or ISO 8601 string.

    Returns:
      A TimelinessReport.

    """
    deadline = _parse_datetime(deadline, "deadline")

    if time_range.latest <= deadline:
        return TimelinessReport(
            ON_TIME,
            deadline,
            time_range,
            "the latest possible time"
            f" ({time_range.latest.isoformat()}) is at or before the"
            f" deadline ({deadline.isoformat()})",
        )

    if time_range.earliest > deadline:
        return TimelinessReport(
            LATE,
            deadline,
            time_range,
            "the earliest possible time"
            f" ({time_range.earliest.isoformat()}) is after the"
            f" deadline ({deadline.isoformat()})",
        )

    return TimelinessReport(
        UNDECIDABLE,
        deadline,
        time_range,
        "the trusted time range"
        f" [{time_range.earliest.isoformat()},"
        f" {time_range.latest.isoformat()}] crosses the deadline"
        f" ({deadline.isoformat()}), clock uncertainty makes it"
        " impossible to decide whether the deadline was met",
    )


def extract_trusted_time_range(link):
    """Extract the trusted time range from a signed link, if present.

    The range is read from the link's ``environment`` dictionary, which
    is covered by the link's signatures and thus cannot be altered
    without invalidating them.

    Arguments:
      link: A Link object.

    Raises:
      securesystemslib.exceptions.FormatError: A trusted time range is
          present but malformed.

    Returns:
      A TrustedTimeRange, or None if the link does not carry one.

    """
    range_data = (link.environment or {}).get(TRUSTED_TIME_RANGE_ENV_KEY)
    if range_data is None:
        return None

    return TrustedTimeRange.from_dict(range_data)


def envelope(time_ranges):
    """Merge trusted time ranges into one enclosing range.

    If any of several links may record the true time of a step, the
    trusted range for the step is the smallest range that contains all
    individual ranges.

    Arguments:
      time_ranges: A non-empty list of TrustedTimeRange objects.

    Returns:
      A TrustedTimeRange spanning all passed ranges.

    """
    if not time_ranges:
        raise ValueError("Cannot compute envelope of no time ranges")

    return TrustedTimeRange(
        min(r.earliest for r in time_ranges),
        max(r.latest for r in time_ranges),
    )
