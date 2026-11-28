"""Clock correction based on segmented evidence."""

import datetime
import decimal

from dfdatetime import interface

STATUS_CORRECTED = "corrected"
STATUS_MANUAL_REVIEW = "manual-review"

REASON_EVIDENCE_MISSING = "missing-evidence"
REASON_EVIDENCE_OVERLAP = "overlapping-evidence"
REASON_SEGMENT_BOUNDARY = "segment-boundary"


def _CopyAliasedArgument(keyword_arguments, names, default=None):
    """Copies the first available aliased argument.

    Args:
      keyword_arguments (dict[str, object]): keyword arguments.
      names (list[str]): accepted argument names, in order of preference.
      default (Optional[object]): value if none of the names is present.

    Returns:
      object: argument value or the default.
    """
    for name in names:
        if name in keyword_arguments:
            return keyword_arguments.pop(name)
    return default


def _ToDecimal(value):
    """Converts a timestamp or duration to a decimal value.

    Args:
      value (decimal.Decimal|datetime.datetime|datetime.timedelta|float|int|str):
          value to convert.

    Returns:
      decimal.Decimal: converted value.

    Raises:
      TypeError: if the value type is not supported.
      ValueError: if the value is not finite.
    """
    if isinstance(value, decimal.Decimal):
        converted_value = value
    elif isinstance(value, bool):
        raise TypeError("Boolean values are not supported as timestamps.")
    elif isinstance(value, datetime.timedelta):
        converted_value = decimal.Decimal(str(value.total_seconds()))
    elif isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        converted_value = decimal.Decimal(str(value.timestamp()))
    elif isinstance(value, float):
        converted_value = decimal.Decimal(str(value))
    elif isinstance(value, int):
        converted_value = decimal.Decimal(value)
    elif isinstance(value, str):
        try:
            converted_value = decimal.Decimal(value)
        except decimal.InvalidOperation:
            try:
                converted_value = _ToDecimal(datetime.datetime.fromisoformat(value))
            except ValueError as exception:
                raise ValueError(f"Invalid timestamp value: {value:s}.") from exception
    elif isinstance(value, interface.DateTimeValues):
        normalized_timestamp = (
            value._GetNormalizedTimestamp()
        )  # pylint: disable=protected-access
        if normalized_timestamp is None:
            raise ValueError("Date time values do not contain a timestamp.")
        converted_value = _ToDecimal(normalized_timestamp)
    else:
        raise TypeError(f"Unsupported timestamp type: {type(value).__name__:s}.")

    if not converted_value.is_finite():
        raise ValueError("Timestamp value must be finite.")

    return converted_value


def _ToNumber(value):
    """Converts a decimal value to a JSON-compatible number.

    Args:
      value (decimal.Decimal): value to convert.

    Returns:
      int|float: JSON-compatible number.
    """
    if value == value.to_integral_value():
        return int(value)
    return float(value)


class ClockCorrectionEvidence:
    """Segmented evidence for a clock offset.

    The applicable timestamp range is left-closed and right-open. The clock
    offset is the number of seconds the recorded clock was ahead of the reference
    clock. A positive offset is therefore subtracted from a recorded timestamp.

    Attributes:
      clock_offset_seconds (decimal.Decimal): clock offset in seconds.
      end_timestamp (decimal.Decimal): end of the applicable range, exclusive.
      evidence_id (str): identifier of the evidence.
      priority (int): precedence used to resolve overlapping evidence.
      start_timestamp (decimal.Decimal): start of the applicable range, inclusive.
    """

    def __init__(
        self,
        evidence_id=None,
        start_timestamp=None,
        end_timestamp=None,
        clock_offset_seconds=None,
        priority=0,
        **keyword_arguments,
    ):
        """Initializes clock correction evidence.

        Args:
          evidence_id (Optional[str]): identifier of the evidence.
          start_timestamp (Optional[decimal.Decimal|datetime.datetime|float|int|str]):
              start of the applicable range, inclusive.
          end_timestamp (Optional[decimal.Decimal|datetime.datetime|float|int|str]):
              end of the applicable range, exclusive, or None for an open-ended
              range.
          clock_offset_seconds (Optional[decimal.Decimal|float|int]): number of
              seconds the recorded clock was ahead of the reference clock.
          priority (Optional[int]): precedence used to resolve overlapping
              evidence. Higher values take precedence.

        Raises:
          TypeError: if an argument type is not supported.
          ValueError: if an argument value is invalid.
        """
        if evidence_id is None:
            evidence_id = _CopyAliasedArgument(keyword_arguments, ["identifier", "id"])
        if start_timestamp is None:
            start_timestamp = _CopyAliasedArgument(
                keyword_arguments, ["start", "applicable_start", "valid_from"]
            )
        if end_timestamp is None:
            end_timestamp = _CopyAliasedArgument(
                keyword_arguments, ["end", "applicable_end", "valid_until"]
            )
        if clock_offset_seconds is None:
            clock_offset_seconds = _CopyAliasedArgument(
                keyword_arguments, ["offset_seconds", "clock_offset", "offset"]
            )

        if keyword_arguments:
            unexpected_arguments = ", ".join(sorted(keyword_arguments))
            raise TypeError(f"Unexpected arguments: {unexpected_arguments:s}.")

        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError("Evidence identifier must be a non-empty string.")
        if start_timestamp is None:
            raise ValueError("Evidence start timestamp is required.")
        if clock_offset_seconds is None:
            raise ValueError("Evidence clock offset is required.")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise ValueError("Evidence priority must be an integer.")

        self.evidence_id = evidence_id
        self.priority = priority
        self.start_timestamp = _ToDecimal(start_timestamp)
        self.end_timestamp = (
            None if end_timestamp is None else _ToDecimal(end_timestamp)
        )
        self.clock_offset_seconds = _ToDecimal(clock_offset_seconds)

        if (
            self.end_timestamp is not None
            and self.end_timestamp <= self.start_timestamp
        ):
            raise ValueError(
                "Evidence end timestamp must be greater than its start timestamp."
            )

    @classmethod
    def FromDict(cls, evidence_dict):
        """Creates clock correction evidence from a dictionary.

        Args:
          evidence_dict (dict[str, object]): evidence values. Accepted keys are
              evidence_id (or identifier/id), start_timestamp (or start), end_timestamp
              (or end), clock_offset_seconds (or offset_seconds/clock_offset/offset)
              and priority.

        Returns:
          ClockCorrectionEvidence: clock correction evidence.
        """
        if not isinstance(evidence_dict, dict):
            raise TypeError("Evidence must be a dictionary.")

        keyword_arguments = dict(evidence_dict)
        evidence_id = keyword_arguments.pop(
            "evidence_id",
            _CopyAliasedArgument(keyword_arguments, ["identifier", "id"]),
        )
        start_timestamp = keyword_arguments.pop(
            "start_timestamp",
            _CopyAliasedArgument(
                keyword_arguments, ["start", "applicable_start", "valid_from"]
            ),
        )
        end_timestamp = keyword_arguments.pop(
            "end_timestamp",
            _CopyAliasedArgument(
                keyword_arguments, ["end", "applicable_end", "valid_until"]
            ),
        )
        clock_offset_seconds = keyword_arguments.pop(
            "clock_offset_seconds",
            _CopyAliasedArgument(
                keyword_arguments, ["offset_seconds", "clock_offset", "offset"]
            ),
        )
        priority = keyword_arguments.pop("priority", 0)

        if keyword_arguments:
            unexpected_arguments = ", ".join(sorted(keyword_arguments))
            raise TypeError(f"Unexpected arguments: {unexpected_arguments:s}.")

        return cls(
            evidence_id=evidence_id,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            clock_offset_seconds=clock_offset_seconds,
            priority=priority,
        )

    def AppliesAt(self, timestamp):
        """Determines if the evidence applies at a recorded timestamp.

        Args:
          timestamp (decimal.Decimal|datetime.datetime|float|int|str): recorded
              timestamp.

        Returns:
          bool: True if the timestamp is within the applicable range.
        """
        timestamp = _ToDecimal(timestamp)
        if timestamp < self.start_timestamp:
            return False
        return self.end_timestamp is None or timestamp < self.end_timestamp

    def CopyToSerializableDict(self):
        """Copies the evidence to a serializable dictionary.

        Returns:
          dict[str, object]: serializable dictionary.
        """
        serializable_dict = {
            "__class_name__": type(self).__name__,
            "__type__": "ClockCorrectionEvidence",
            "clock_offset_seconds": _ToNumber(self.clock_offset_seconds),
            "evidence_id": self.evidence_id,
            "priority": self.priority,
            "start_timestamp": _ToNumber(self.start_timestamp),
        }
        if self.end_timestamp is not None:
            serializable_dict["end_timestamp"] = _ToNumber(self.end_timestamp)
        return serializable_dict


class ClockCorrectionResult:
    """Result of correcting a recorded timestamp.

    Attributes:
      candidate_evidence_ids (list[str]): identifiers of evidence that apply but
          could not safely be selected.
      clock_offset_seconds (decimal.Decimal): applied clock offset or None.
      corrected_timestamp (decimal.Decimal): corrected timestamp or None.
      evidence_id (str): identifier of the adopted evidence or None.
      original_timestamp (decimal.Decimal): recorded timestamp before correction.
      reason (str): reason manual review is required or None.
      status (str): correction status, either "corrected" or "manual-review".
    """

    def __init__(
        self,
        original_timestamp,
        corrected_timestamp=None,
        clock_offset_seconds=None,
        evidence_id=None,
        status=STATUS_MANUAL_REVIEW,
        reason=None,
        candidate_evidence_ids=None,
    ):
        """Initializes a clock correction result.

        Args:
          original_timestamp (decimal.Decimal): recorded timestamp.
          corrected_timestamp (Optional[decimal.Decimal]): corrected timestamp.
          clock_offset_seconds (Optional[decimal.Decimal]): applied clock offset.
          evidence_id (Optional[str]): identifier of the adopted evidence.
          status (Optional[str]): correction status.
          reason (Optional[str]): reason manual review is required.
          candidate_evidence_ids (Optional[list[str]]): identifiers of evidence
              that could not safely be selected.
        """
        if status not in (STATUS_CORRECTED, STATUS_MANUAL_REVIEW):
            raise ValueError(f"Unsupported correction status: {status!s}.")

        self.original_timestamp = _ToDecimal(original_timestamp)
        self.corrected_timestamp = (
            None if corrected_timestamp is None else _ToDecimal(corrected_timestamp)
        )
        self.clock_offset_seconds = (
            None if clock_offset_seconds is None else _ToDecimal(clock_offset_seconds)
        )
        self.evidence_id = evidence_id
        self.status = status
        self.reason = reason
        self.candidate_evidence_ids = list(candidate_evidence_ids or [])

    @property
    def is_corrected(self):
        """bool: True if a correction was applied."""
        return self.status == STATUS_CORRECTED

    @property
    def requires_manual_review(self):
        """bool: True if the timestamp could not be safely corrected."""
        return self.status == STATUS_MANUAL_REVIEW

    def CopyToSerializableDict(self):
        """Copies the correction result to a serializable dictionary.

        Returns:
          dict[str, object]: serializable dictionary. It preserves the original
              timestamp and, when corrected, the adopted evidence identifier and
              clock offset.
        """
        serializable_dict = {
            "__class_name__": type(self).__name__,
            "__type__": "ClockCorrectionResult",
            "original_timestamp": _ToNumber(self.original_timestamp),
            "requires_manual_review": self.requires_manual_review,
            "status": self.status,
        }
        if self.corrected_timestamp is not None:
            serializable_dict["clock_offset_seconds"] = _ToNumber(
                self.clock_offset_seconds
            )
            serializable_dict["corrected_timestamp"] = _ToNumber(
                self.corrected_timestamp
            )
            serializable_dict["evidence_id"] = self.evidence_id
        else:
            serializable_dict["reason"] = self.reason
            if self.candidate_evidence_ids:
                serializable_dict["candidate_evidence_ids"] = list(
                    self.candidate_evidence_ids
                )

        return serializable_dict


class ClockCorrection:
    """Corrects recorded timestamps using segmented clock offset evidence."""

    def __init__(
        self,
        evidence=None,
        ambiguity_window_seconds=60,
        **keyword_arguments,
    ):
        """Initializes a clock correction.

        Args:
          evidence (Optional[list[ClockCorrectionEvidence|dict[str, object]]]):
              segmented correction evidence.
          ambiguity_window_seconds (Optional[decimal.Decimal|float|int]): width of
              the manual-review window between adjacent correction segments. The
              default of 60 seconds keeps ambiguous records off the timeline.

        Raises:
          TypeError: if an argument type is not supported.
          ValueError: if an argument value is invalid.
        """
        if evidence is None:
            evidence = _CopyAliasedArgument(
                keyword_arguments,
                ["correction_evidence", "evidence_segments", "segments"],
            )

        if keyword_arguments:
            unexpected_arguments = ", ".join(sorted(keyword_arguments))
            raise TypeError(f"Unexpected arguments: {unexpected_arguments:s}.")

        self.ambiguity_window_seconds = _ToDecimal(ambiguity_window_seconds or 0)
        if self.ambiguity_window_seconds < 0:
            raise ValueError("Ambiguity window must not be negative.")

        self._evidence = []
        evidence_ids = set()
        if isinstance(evidence, (ClockCorrectionEvidence, dict)):
            evidence = [evidence]

        for evidence_value in evidence or []:
            if isinstance(evidence_value, dict):
                evidence_segment = ClockCorrectionEvidence.FromDict(evidence_value)
            elif isinstance(evidence_value, ClockCorrectionEvidence):
                evidence_segment = evidence_value
            else:
                raise TypeError(
                    "Evidence must be ClockCorrectionEvidence or a dictionary."
                )

            if evidence_segment.evidence_id in evidence_ids:
                raise ValueError(
                    "Duplicate evidence identifier: "
                    f"{evidence_segment.evidence_id:s}."
                )

            self._evidence.append(evidence_segment)
            evidence_ids.add(evidence_segment.evidence_id)

        self._transition_windows = self._GetTransitionWindows()

    @property
    def evidence(self):
        """list[ClockCorrectionEvidence]: segmented correction evidence."""
        return list(self._evidence)

    def _GetTransitionWindows(self):
        """Determines manual-review windows between adjacent segments.

        Returns:
          list[tuple[decimal.Decimal, decimal.Decimal, list[str]]]: start, end and
              evidence identifiers of each transition window.
        """
        if self.ambiguity_window_seconds == 0 or len(self._evidence) < 2:
            return []

        ordered_evidence = sorted(
            enumerate(self._evidence),
            key=lambda value: (
                value[1].start_timestamp,
                value[1].end_timestamp is None,
                value[1].end_timestamp or 0,
                value[0],
            ),
        )

        transition_windows = []
        half_window = self.ambiguity_window_seconds / 2

        def add_window(boundary, evidence_ids):
            """Adds a manual-review window centered on a boundary."""
            transition_windows.append(
                (boundary - half_window, boundary + half_window, evidence_ids)
            )

        for index in range(len(ordered_evidence) - 1):
            _, previous_evidence = ordered_evidence[index]
            _, next_evidence = ordered_evidence[index + 1]

            if previous_evidence.clock_offset_seconds == (
                next_evidence.clock_offset_seconds
            ):
                continue
            if previous_evidence.end_timestamp is None:
                if next_evidence.priority > previous_evidence.priority:
                    add_window(
                        next_evidence.start_timestamp,
                        [
                            previous_evidence.evidence_id,
                            next_evidence.evidence_id,
                        ],
                    )
                    if next_evidence.end_timestamp is not None:
                        add_window(
                            next_evidence.end_timestamp,
                            [
                                next_evidence.evidence_id,
                                previous_evidence.evidence_id,
                            ],
                        )
                continue
            if next_evidence.start_timestamp < previous_evidence.end_timestamp:
                if next_evidence.priority > previous_evidence.priority:
                    add_window(
                        next_evidence.start_timestamp,
                        [
                            previous_evidence.evidence_id,
                            next_evidence.evidence_id,
                        ],
                    )
                    if (
                        next_evidence.end_timestamp is not None
                        and next_evidence.end_timestamp
                        < previous_evidence.end_timestamp
                    ):
                        add_window(
                            next_evidence.end_timestamp,
                            [
                                next_evidence.evidence_id,
                                previous_evidence.evidence_id,
                            ],
                        )
                elif previous_evidence.priority > next_evidence.priority:
                    if (
                        next_evidence.end_timestamp is not None
                        and next_evidence.end_timestamp
                        > previous_evidence.end_timestamp
                    ):
                        add_window(
                            previous_evidence.end_timestamp,
                            [
                                previous_evidence.evidence_id,
                                next_evidence.evidence_id,
                            ],
                        )
                continue

            gap = next_evidence.start_timestamp - previous_evidence.end_timestamp
            if gap >= self.ambiguity_window_seconds:
                continue

            midpoint = previous_evidence.end_timestamp + (gap / 2)
            add_window(
                midpoint,
                [previous_evidence.evidence_id, next_evidence.evidence_id],
            )

        return transition_windows

    def CorrectTimestamp(self, timestamp):
        """Corrects a recorded timestamp.

        Args:
          timestamp (decimal.Decimal|datetime.datetime|float|int|str): recorded
              timestamp, typically a POSIX timestamp converted to UTC.

        Returns:
          ClockCorrectionResult: correction result. The result requires manual
              review when evidence is missing, overlapping evidence conflicts, or
              the timestamp falls in a transition window between segments.
        """
        original_timestamp = _ToDecimal(timestamp)

        candidates = [
            evidence
            for evidence in self._evidence
            if evidence.AppliesAt(original_timestamp)
        ]

        if len(candidates) > 1:
            highest_priority = max(evidence.priority for evidence in candidates)
            highest_priority_candidates = [
                evidence
                for evidence in candidates
                if evidence.priority == highest_priority
            ]
            offsets = {
                evidence.clock_offset_seconds
                for evidence in highest_priority_candidates
            }
            if len(offsets) > 1:
                return ClockCorrectionResult(
                    original_timestamp,
                    reason=REASON_EVIDENCE_OVERLAP,
                    candidate_evidence_ids=[
                        evidence.evidence_id for evidence in candidates
                    ],
                )

            candidates = highest_priority_candidates

        for window_start, window_end, evidence_ids in self._transition_windows:
            if window_start <= original_timestamp < window_end:
                return ClockCorrectionResult(
                    original_timestamp,
                    reason=REASON_SEGMENT_BOUNDARY,
                    candidate_evidence_ids=evidence_ids,
                )

        if not candidates:
            return ClockCorrectionResult(
                original_timestamp, reason=REASON_EVIDENCE_MISSING
            )

        selected_evidence = candidates[0]
        corrected_timestamp = (
            original_timestamp - selected_evidence.clock_offset_seconds
        )
        return ClockCorrectionResult(
            original_timestamp,
            corrected_timestamp=corrected_timestamp,
            clock_offset_seconds=selected_evidence.clock_offset_seconds,
            evidence_id=selected_evidence.evidence_id,
            status=STATUS_CORRECTED,
        )

    def correct(self, timestamp):
        """Corrects a recorded timestamp.

        Args:
          timestamp (decimal.Decimal|datetime.datetime|float|int|str): recorded
              timestamp.

        Returns:
          ClockCorrectionResult: correction result.
        """
        return self.CorrectTimestamp(timestamp)


# Common aliases used by callers that model the evidence as correction segments.
CorrectionEvidence = ClockCorrectionEvidence
CorrectionResult = ClockCorrectionResult
ClockCorrectionSegment = ClockCorrectionEvidence
ClockCorrector = ClockCorrection
