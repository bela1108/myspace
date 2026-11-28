"""Ambiguous local time implementation."""

from dfdatetime import definitions
from dfdatetime import factory
from dfdatetime import interface


class AmbiguousTime(interface.DateTimeValues):
    """Date and time value that has more than one possible UTC interpretation.

    This type is used for local times in the repeated hour of a clock rollback,
    where the same wall-clock time maps to two different UTC instants. Each
    candidate preserves the UTC offset that was in effect for that interpretation.

    Attributes:
      is_local_time (bool): True if the date and time value is in local time.
      time_zone_candidates (list[DateTimeValues]): candidate date and time values.
      time_zone_hint (str): time zone hint, such as "Europe/Amsterdam".
    """

    def __init__(
        self,
        candidates=None,
        exclusion_conditions=None,
        is_local_time=True,
        precision=None,
        time_zone_candidates=None,
        time_zone_hint=None,
        time_zone_offset=None,
    ):
        """Initializes ambiguous date and time values.

        Args:
          candidates (Optional[list[DateTimeValues]]): candidate date and time
              values. Each candidate should carry the UTC offset used for its
              interpretation.
          exclusion_conditions (Optional[list[object]]): optional evidence based
              exclusion conditions.
          is_local_time (Optional[bool]): True if the date and time value is in
              local time.
          precision (Optional[str]): precision of the date and time value.
          time_zone_candidates (Optional[list[DateTimeValues]]): alias for
              candidates.
          time_zone_hint (Optional[str]): time zone hint.
          time_zone_offset (Optional[int]): primary time zone offset in minutes
              from UTC or None if not set.
        """
        super().__init__(
            precision=precision or definitions.PRECISION_1_SECOND,
            time_zone_offset=time_zone_offset,
        )
        if candidates is None:
            candidates = time_zone_candidates

        self.is_local_time = bool(is_local_time)
        self.time_zone_hint = time_zone_hint
        self.SetTimeZoneCandidates(candidates, exclusion_conditions)

    def _GetNormalizedTimestamp(self):
        """Retrieves the normalized timestamp.

        Returns:
          decimal.Decimal: normalized timestamp of the first candidate that was
              not excluded, or None if no candidate is available.
        """
        candidates = self.GetRemainingTimeZoneCandidates()
        if not candidates:
            candidates = self.time_zone_candidates or []

        for candidate in candidates:
            if isinstance(candidate, interface.DateTimeValues):
                normalized_timestamp = (
                    candidate._GetNormalizedTimestamp()
                )  # pylint: disable=protected-access
                if normalized_timestamp is not None:
                    return normalized_timestamp

        return None

    def CopyToDateTimeString(self):
        """Copies the date and time value to a date and time string.

        Returns:
          str: date and time value formatted as: "YYYY-MM-DD hh:mm:ss" or None
              if the timestamp is missing.
        """
        candidate = self.GetSelectedTimeZoneCandidate()
        if candidate is None:
            return None

        return candidate.CopyToDateTimeString()

    def CopyToDateTimeStringISO8601(self):
        """Copies the date and time value to an ISO 8601 date and time string.

        Returns:
          str: date and time value formatted as:
              "YYYY-MM-DDThh:mm:ss.######[+-]##:##" or None if the timestamp
              is missing.
        """
        candidate = self.GetSelectedTimeZoneCandidate()
        if candidate is None:
            return None

        return candidate.CopyToDateTimeStringISO8601()

    def CopyToSerializableDict(self):
        """Copies the date time value to a serializable dictionary.

        Returns:
          dict[str, object]: serializable dictionary.
        """
        return self._CreateSerializableDict()

    def GetSelectedTimeZoneCandidate(self):
        """Retrieves the candidate selected after evidence based exclusion.

        Returns:
          DateTimeValues: first candidate that was not excluded or None if no
              candidate is available.
        """
        candidates = self.GetRemainingTimeZoneCandidates()
        if not candidates:
            candidates = self.time_zone_candidates or []

        for candidate in candidates:
            if isinstance(candidate, interface.DateTimeValues):
                return candidate

        return None


class AmbiguousLocalTime(AmbiguousTime):
    """Ambiguous local time."""

    def __init__(
        self,
        candidates=None,
        exclusion_conditions=None,
        is_local_time=True,
        precision=None,
        time_zone_candidates=None,
        time_zone_hint=None,
        time_zone_offset=None,
    ):
        """Initializes an ambiguous local time."""
        super().__init__(
            candidates=candidates,
            exclusion_conditions=exclusion_conditions,
            is_local_time=is_local_time,
            precision=precision,
            time_zone_candidates=time_zone_candidates,
            time_zone_hint=time_zone_hint,
            time_zone_offset=time_zone_offset,
        )


class AmbiguousDateTime(AmbiguousTime):
    """Ambiguous date and time value."""

    def __init__(
        self,
        candidates=None,
        exclusion_conditions=None,
        is_local_time=True,
        precision=None,
        time_zone_candidates=None,
        time_zone_hint=None,
        time_zone_offset=None,
    ):
        """Initializes an ambiguous date and time value."""
        super().__init__(
            candidates=candidates,
            exclusion_conditions=exclusion_conditions,
            is_local_time=is_local_time,
            precision=precision,
            time_zone_candidates=time_zone_candidates,
            time_zone_hint=time_zone_hint,
            time_zone_offset=time_zone_offset,
        )


factory.Factory.RegisterDateTimeValues(AmbiguousTime)
factory.Factory.RegisterDateTimeValues(AmbiguousLocalTime)
factory.Factory.RegisterDateTimeValues(AmbiguousDateTime)
