"""Independent time testimony and synthesis implementation."""

import decimal

from dfdatetime import definitions
from dfdatetime import interface


class TimeTestimony:
    """Independent time testimony.

    A time testimony represents the interval of time supported by an
    independent date and time value. Intervals are represented using
    normalized POSIX timestamps in seconds and are half-open: the start time
    is included while the end time is excluded.

    Attributes:
      date_time_values (interface.DateTimeValues): source date and time values,
          or None if the testimony was created from an explicit interval.
      end_time (decimal.Decimal): end of the supported time interval.
      identifier (str): unique source identifier.
      precision (str): precision of the date and time value.
      start_time (decimal.Decimal): start of the supported time interval.
    """

    _PRECISION_DURATIONS = {
        definitions.PRECISION_1_DAY: decimal.Decimal(86400),
        definitions.PRECISION_1_HOUR: decimal.Decimal(3600),
        definitions.PRECISION_1_NANOSECOND: decimal.Decimal("0.000000001"),
        definitions.PRECISION_10_NANOSECONDS: decimal.Decimal("0.00000001"),
        definitions.PRECISION_100_NANOSECONDS: decimal.Decimal("0.0000001"),
        definitions.PRECISION_1_MICROSECOND: decimal.Decimal("0.000001"),
        definitions.PRECISION_10_MICROSECONDS: decimal.Decimal("0.00001"),
        definitions.PRECISION_100_MICROSECONDS: decimal.Decimal("0.0001"),
        definitions.PRECISION_1_MILLISECOND: decimal.Decimal("0.001"),
        definitions.PRECISION_10_MILLISECONDS: decimal.Decimal("0.01"),
        definitions.PRECISION_100_MILLISECONDS: decimal.Decimal("0.1"),
        definitions.PRECISION_1_MINUTE: decimal.Decimal(60),
        definitions.PRECISION_1_SECOND: decimal.Decimal(1),
        definitions.PRECISION_2_SECONDS: decimal.Decimal(2),
    }

    def __init__(
        self,
        identifier,
        start_time,
        end_time,
        precision,
        date_time_values=None,
        source=None,
        confidence=None,
    ):
        """Initializes a time testimony.

        Args:
          identifier (str): unique source identifier.
          start_time (decimal.Decimal): start of the supported time interval,
              in normalized POSIX seconds.
          end_time (decimal.Decimal): end of the supported time interval, in
              normalized POSIX seconds.
          precision (str): precision of the date and time value.
          date_time_values (Optional[interface.DateTimeValues]): source date and
              time values, or None if the testimony was created from an explicit
              interval.
          source (Optional[object]): source information.
          confidence (Optional[object]): source confidence information.

        Raises:
          ValueError: if the identifier is not a string, the interval is invalid,
              or the precision is unsupported.
        """
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("Identifier must be a non-empty string.")

        start_time = self._NormalizeTimestamp(start_time)
        end_time = self._NormalizeTimestamp(end_time)

        if end_time <= start_time:
            raise ValueError("End time must be greater than start time.")

        if precision not in definitions.PRECISION_VALUES:
            raise ValueError(f"Unsupported precision: {precision!s}")

        if date_time_values is not None and not isinstance(
            date_time_values, interface.DateTimeValues
        ):
            raise ValueError(
                "Date time values must be an instance of DateTimeValues."
            )

        super().__init__()
        self.date_time_values = date_time_values
        self.end_time = end_time
        self.identifier = identifier
        self._metadata = {
            "confidence": confidence,
            "source": source,
        }
        self.precision = precision
        self.start_time = start_time

    @property
    def confidence(self):
        """object: source confidence information, or None if not set."""
        return self._metadata["confidence"]

    @property
    def source(self):
        """object: source information, or None if not set."""
        return self._metadata["source"]

    @classmethod
    def _GetPrecisionDuration(cls, precision):
        """Retrieves the duration covered by a precision value.

        Args:
          precision (str): precision of the date and time value.

        Returns:
          decimal.Decimal: duration in normalized POSIX seconds.

        Raises:
          ValueError: if the precision is unsupported.
        """
        try:
            return cls._PRECISION_DURATIONS[precision]
        except KeyError as exception:
            raise ValueError(f"Unsupported precision: {precision!s}") from exception

    @staticmethod
    def _NormalizeTimestamp(timestamp):
        """Normalizes a timestamp value to a decimal number of seconds.

        Args:
          timestamp (decimal.Decimal|int|float): timestamp in normalized POSIX
              seconds.

        Returns:
          decimal.Decimal: normalized timestamp.

        Raises:
          ValueError: if the timestamp cannot be represented as a decimal number.
        """
        if isinstance(timestamp, decimal.Decimal):
            return timestamp

        if isinstance(timestamp, int):
            return decimal.Decimal(timestamp)

        if isinstance(timestamp, float):
            return decimal.Decimal(str(timestamp))

        raise ValueError("Timestamp must be a decimal, integer or float value.")

    def Overlaps(self, other):
        """Determines if this testimony overlaps another testimony.

        Args:
          other (TimeTestimony): testimony to compare against.

        Returns:
          bool: True if the supported time intervals overlap.

        Raises:
          ValueError: if other is not a time testimony.
        """
        if not isinstance(other, TimeTestimony):
            raise ValueError("Other not an instance of TimeTestimony")

        return self.start_time < other.end_time and other.start_time < self.end_time


class TimeTestimonyConflict:
    """Minimal conflicting combination of time testimonies.

    Attributes:
      confidence (tuple[object, object]): source confidence information for each
          conflicting testimony.
      end_time (decimal.Decimal): end of the gap between the conflicting
          intervals.
      identifiers (tuple[str, str]): identifiers of the conflicting testimonies.
      start_time (decimal.Decimal): start of the gap between the conflicting
          intervals.
    """

    def __init__(self, first_testimony, second_testimony):
        """Initializes a time testimony conflict.

        Args:
          first_testimony (TimeTestimony): first conflicting testimony.
          second_testimony (TimeTestimony): second conflicting testimony.
        """
        super().__init__()
        self.confidence = (
            first_testimony.confidence,
            second_testimony.confidence,
        )
        self.identifiers = (
            first_testimony.identifier,
            second_testimony.identifier,
        )

        if first_testimony.end_time <= second_testimony.start_time:
            self.start_time = first_testimony.end_time
            self.end_time = second_testimony.start_time
        else:
            self.start_time = second_testimony.end_time
            self.end_time = first_testimony.start_time


class TimeTestimonySynthesis:
    """Synthesis result for a set of independent time testimonies.

    Attributes:
      conflicts (tuple[TimeTestimonyConflict, ...]): minimal supported conflicting
          combinations.
      end_time (decimal.Decimal|None): end of the common supported interval, or
          None if no common interval exists.
      start_time (decimal.Decimal|None): start of the common supported interval,
          or None if no common interval exists.
      testimonies (tuple[TimeTestimony, ...]): synthesized testimonies.
    """

    def __init__(self, testimonies):
        """Initializes a time testimony synthesis result.

        Args:
          testimonies (tuple[TimeTestimony, ...]): synthesized testimonies.
        """
        super().__init__()
        self.conflicts = tuple(self._GetConflicts(testimonies))
        self.testimonies = testimonies

        if self.conflicts:
            self.start_time = None
            self.end_time = None
        else:
            self.start_time = max(testimony.start_time for testimony in testimonies)
            self.end_time = min(testimony.end_time for testimony in testimonies)

    @property
    def has_conflicts(self):
        """bool: True if the testimonies contain a conflicting combination."""
        return bool(self.conflicts)

    @staticmethod
    def _GetConflicts(testimonies):
        """Retrieves the minimal conflicting combinations of testimonies.

        Args:
          testimonies (tuple[TimeTestimony, ...]): testimonies to synthesize.

        Returns:
          list[TimeTestimonyConflict]: minimal supported conflicting combinations.
        """
        conflicts = []
        for index, first_testimony in enumerate(testimonies):
            for second_testimony in testimonies[index + 1 :]:
                if not first_testimony.Overlaps(second_testimony):
                    conflicts.append(
                        TimeTestimonyConflict(first_testimony, second_testimony)
                    )

        return conflicts


def CreateTimeTestimony(
    identifier,
    date_time_values=None,
    precision=None,
    start_time=None,
    end_time=None,
    source=None,
    confidence=None,
):
    """Creates an independent time testimony.

    If start and end times are provided they define the supported interval and
    take precedence over the precision-derived interval. If only one interval
    boundary is provided, precision determines the other boundary. If neither is
    provided the normalized date and time value is used as the interval start.

    Args:
      identifier (str): unique source identifier.
      date_time_values (Optional[interface.DateTimeValues]): source date and time
          values.
      precision (Optional[str]): precision of the date and time value, which
          should be one of the PRECISION_VALUES in definitions.
      start_time (Optional[decimal.Decimal|int|float]): start of the supported
          time interval in normalized POSIX seconds.
      end_time (Optional[decimal.Decimal|int|float]): end of the supported time
          interval in normalized POSIX seconds.
      source (Optional[object]): source information.
      confidence (Optional[object]): source confidence information.

    Returns:
      TimeTestimony: time testimony.

    Raises:
      ValueError: if the testimony cannot be created from the provided values.
    """
    if start_time is None and end_time is None and date_time_values is None:
        raise ValueError(
            "Date time values or an explicit start or end time is required."
        )

    if precision is None:
        if date_time_values is not None and date_time_values.precision is not None:
            precision = date_time_values.precision
        else:
            raise ValueError("Precision is required.")

    if precision not in definitions.PRECISION_VALUES:
        raise ValueError(f"Unsupported precision: {precision!s}")

    normalized_timestamp = None
    if date_time_values is not None:
        if not isinstance(date_time_values, interface.DateTimeValues):
            raise ValueError(
                "Date time values must be an instance of DateTimeValues."
            )

        # pylint: disable=protected-access
        normalized_timestamp = date_time_values._GetNormalizedTimestamp()
        # pylint: enable=protected-access
        if normalized_timestamp is None:
            raise ValueError("Unable to determine normalized timestamp.")

    if start_time is None:
        if end_time is None:
            start_time = normalized_timestamp
        else:
            start_time = TimeTestimony._NormalizeTimestamp(end_time) - (
                TimeTestimony._GetPrecisionDuration(precision)
            )
    else:
        start_time = TimeTestimony._NormalizeTimestamp(start_time)

    if end_time is not None:
        end_time = TimeTestimony._NormalizeTimestamp(end_time)
    else:
        end_time = start_time + TimeTestimony._GetPrecisionDuration(precision)

    return TimeTestimony(
        identifier=identifier,
        start_time=start_time,
        end_time=end_time,
        precision=precision,
        date_time_values=date_time_values,
        source=source,
        confidence=confidence,
    )


def SynthesizeTimeTestimonies(testimonies):
    """Synthesizes independent time testimonies.

    Confidence information is retained for interpretation but does not change
    interval arithmetic. A broad, low-confidence interval can therefore never
    narrow a narrower interval supported by another source.

    Args:
      testimonies (iterable[TimeTestimony]): independent time testimonies.

    Returns:
      TimeTestimonySynthesis: common supported interval or minimal conflicting
          combinations.

    Raises:
      ValueError: if no testimonies are provided, an item is not a time
          testimony, or identifiers are not unique.
    """
    testimony_tuple = tuple(testimonies)
    if not testimony_tuple:
        raise ValueError("At least one time testimony is required.")

    identifiers = set()
    for testimony in testimony_tuple:
        if not isinstance(testimony, TimeTestimony):
            raise ValueError("Item not an instance of TimeTestimony")

        if testimony.identifier in identifiers:
            raise ValueError(
                f"Duplicate time testimony identifier: {testimony.identifier!s}"
            )
        identifiers.add(testimony.identifier)

    return TimeTestimonySynthesis(testimony_tuple)
