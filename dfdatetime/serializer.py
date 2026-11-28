"""The date and time values serializer."""

import copy
import datetime

from dfdatetime import factory
from dfdatetime import interface

_AMBIGUITY_FLAG_KEYS = (
    "had_ambiguity",
    "was_ambiguous",
    "is_ambiguous",
    "previously_ambiguous",
    "ambiguity",
    "ambiguity_history",
)
_CANDIDATE_KEYS = (
    "candidates",
    "time_zone_candidates",
    "ambiguous_time_candidates",
    "ambiguous_times",
    "time_zone_offset_candidates",
    "utc_candidates",
    "utc_time_candidates",
    "candidate_times",
    "possible_times",
)
_EXCLUSION_KEYS = (
    "exclusion_conditions",
    "evidence_exclusion_conditions",
    "evidence_exclusions",
    "exclusions",
)
_OFFSET_CANDIDATE_KEYS = (
    "time_zone_offsets",
    "ambiguous_offsets",
    "candidate_offsets",
)


class _LocalTimeZoneRulesAdapter:
    """Adapter that turns caller supplied local time zone rules into offsets."""

    _OFFSET_KEYS = (
        "candidates",
        "time_zone_offsets",
        "time_zone_offset_candidates",
        "ambiguous_offsets",
        "candidate_offsets",
        "offsets",
    )

    @classmethod
    def _GetLocalDateTimeTuple(cls, date_time_values):
        """Retrieves the local date and time tuple from date time values."""
        values = []
        for attribute_name in (
            "year",
            "month",
            "day_of_month",
            "hours",
            "minutes",
            "seconds",
        ):
            value = getattr(date_time_values, attribute_name, None)
            if value is None:
                return None
            values.append(value)

        return tuple(values)

    @classmethod
    def _GetOffsetsFromTimeZone(cls, time_zone, date_time_values):
        """Retrieves candidate UTC offsets from a time zone object."""
        local_time_tuple = cls._GetLocalDateTimeTuple(date_time_values)
        if not local_time_tuple:
            return None

        local_date_time = datetime.datetime(*local_time_tuple)
        date_time_offsets = []

        localize_method = getattr(time_zone, "localize", None)
        if callable(localize_method):
            for is_dst in (True, False):
                localized_date_time = localize_method(local_date_time, is_dst=is_dst)
                utc_offset = localized_date_time.utcoffset()
                if utc_offset is None:
                    return None
                date_time_offsets.append(int(utc_offset.total_seconds()) // 60)
        else:
            for fold in (0, 1):
                localized_date_time = local_date_time.replace(
                    tzinfo=time_zone, fold=fold
                )
                utc_offset = localized_date_time.utcoffset()
                if utc_offset is None:
                    return None
                date_time_offsets.append(int(utc_offset.total_seconds()) // 60)

        return date_time_offsets

    @classmethod
    def _LookupInDictionary(cls, rules, date_time_values):
        """Retrieves local rules from a caller supplied dictionary."""
        time_zone_hint = getattr(date_time_values, "time_zone_hint", None)
        local_time_tuple = cls._GetLocalDateTimeTuple(date_time_values)

        lookup_keys = []
        if time_zone_hint:
            lookup_keys.append(time_zone_hint)
        if local_time_tuple:
            lookup_keys.append(local_time_tuple)
            lookup_keys.append("%04d-%02d-%02d %02d:%02d:%02d" % local_time_tuple)
            lookup_keys.append("%04d-%02d-%02dT%02d:%02d:%02d" % local_time_tuple)
        lookup_keys.extend(["default", "ambiguous_local_times", "local_times"])

        for lookup_key in lookup_keys:
            if lookup_key in rules:
                lookup_value = rules[lookup_key]
                if lookup_key in ("ambiguous_local_times", "local_times"):
                    if isinstance(lookup_value, dict):
                        nested_value = cls._LookupInDictionary(
                            lookup_value, date_time_values
                        )
                        if nested_value is not None:
                            return nested_value
                    continue
                return lookup_value

        time_zone = rules.get("time_zone") or rules.get("timezone")
        if time_zone is not None:
            return cls._GetOffsetsFromTimeZone(time_zone, date_time_values)

        for offset_key in cls._OFFSET_KEYS:
            if offset_key in rules:
                return rules[offset_key]

        return None

    @classmethod
    def GetCandidateOffsets(cls, rules, date_time_values):
        """Retrieves candidate UTC offsets from caller supplied local rules.

        Args:
          rules (object): caller supplied local time zone rules. Supported forms
              are an object with a GetTimeZoneOffsets method, a callable, a
              datetime.tzinfo or pytz-like time zone, a dictionary that maps a
              time zone hint or local time to offsets, or a sequence of offsets.
          date_time_values (DateTimeValues): local date and time values.

        Returns:
          list[object]: candidate offsets or candidate specifications, or None
              if no rules apply.
        """
        if rules is None:
            return None

        result = None
        rule_method = None
        for method_name in (
            "GetTimeZoneOffsets",
            "GetOffsets",
            "get_time_zone_offsets",
            "get_offsets",
        ):
            rule_method = getattr(rules, method_name, None)
            if callable(rule_method):
                break

        if rule_method is not None:
            try:
                result = rule_method(date_time_values)
            except TypeError:
                result = rule_method(
                    date_time_values, getattr(date_time_values, "time_zone_hint", None)
                )
        elif hasattr(rules, "localize") or isinstance(rules, datetime.tzinfo):
            result = cls._GetOffsetsFromTimeZone(rules, date_time_values)
        elif isinstance(rules, dict):
            result = cls._LookupInDictionary(rules, date_time_values)
        elif callable(rules):
            result = rules(date_time_values)
        else:
            result = None
            for attribute_name in cls._OFFSET_KEYS:
                if hasattr(rules, attribute_name):
                    result = getattr(rules, attribute_name)
                    break
            if result is None:
                result = rules

        if result is None:
            return None
        if isinstance(result, (int, str)):
            return [result]
        if isinstance(result, dict):
            for offset_key in cls._OFFSET_KEYS:
                if offset_key in result:
                    return cls.GetCandidateOffsets(result[offset_key], date_time_values)
            if "time_zone" in result or "timezone" in result:
                return cls._GetOffsetsFromTimeZone(
                    result.get("time_zone") or result.get("timezone"),
                    date_time_values,
                )
            return [result]

        try:
            return list(result)
        except TypeError:
            return None


class Serializer:
    """Date and time values serializer."""

    @classmethod
    def _CreateCandidateFromOffset(
        cls, date_time_values, offset_value, candidate_specification=None
    ):
        """Creates a candidate by applying a UTC offset to date time values.

        Args:
          date_time_values (DateTimeValues): local date and time values.
          offset_value (int): UTC offset in minutes.
          candidate_specification (Optional[dict]): optional candidate metadata,
              such as exclusion conditions.

        Returns:
          DateTimeValues: candidate date and time values.
        """
        candidate = copy.deepcopy(date_time_values)
        candidate.time_zone_offset = int(offset_value)
        candidate.is_local_time = True
        candidate.time_zone_candidates = None
        candidate.had_ambiguity = False
        if candidate_specification:
            candidate.exclusion_conditions = candidate_specification.get(
                "exclusion_conditions"
            )
            candidate.is_excluded = bool(candidate_specification.get("is_excluded"))
        return candidate

    @classmethod
    def _ApplyLocalTimeZoneRules(cls, date_time_values, time_zone_rules):
        """Applies local time zone rules to create candidate values.

        Args:
          date_time_values (DateTimeValues): local date and time values.
          time_zone_rules (object): caller supplied local time zone rules.

        Returns:
          DateTimeValues: date and time values with candidates, if any.
        """
        if time_zone_rules is None or date_time_values.time_zone_candidates:
            return date_time_values

        candidate_offsets = _LocalTimeZoneRulesAdapter.GetCandidateOffsets(
            time_zone_rules, date_time_values
        )
        if not candidate_offsets:
            return date_time_values

        candidates = []
        for candidate_offset in candidate_offsets:
            if isinstance(candidate_offset, interface.DateTimeValues):
                candidates.append(candidate_offset)
                continue

            if isinstance(candidate_offset, dict):
                offset_value = candidate_offset.get(
                    "time_zone_offset", candidate_offset.get("utc_offset")
                )
                if offset_value is None:
                    candidates.append(candidate_offset)
                    continue

                candidate = cls._CreateCandidateFromOffset(
                    date_time_values, offset_value, candidate_offset
                )
                candidates.append(candidate)
                continue

            if isinstance(candidate_offset, (tuple, list)):
                if len(candidate_offset) != 2:
                    candidates.append(candidate_offset)
                    continue

                candidate = cls._CreateCandidateFromOffset(
                    date_time_values, candidate_offset[1]
                )
                candidates.append(candidate)
                continue

            try:
                offset_value = int(candidate_offset)
            except (TypeError, ValueError):
                candidates.append(candidate_offset)
                continue

            candidate = cls._CreateCandidateFromOffset(date_time_values, offset_value)
            candidates.append(candidate)

        normalized_timestamps = set()
        for candidate in candidates:
            if isinstance(candidate, interface.DateTimeValues):
                normalized_timestamp = (
                    candidate._GetNormalizedTimestamp()
                )  # pylint: disable=protected-access
                if normalized_timestamp is not None:
                    normalized_timestamps.add(normalized_timestamp)

        if len(normalized_timestamps) < 2:
            return date_time_values

        if date_time_values.time_zone_offset is None:
            first_candidate = candidates[0]
            if isinstance(first_candidate, interface.DateTimeValues):
                date_time_values.time_zone_offset = first_candidate.time_zone_offset

        date_time_values.time_zone_candidates = candidates
        date_time_values.had_ambiguity = True
        return date_time_values

    @classmethod
    def _GetTimeZoneRules(cls, time_zone_rules, local_time_rules, kwargs):
        """Resolves aliases for caller supplied local time zone rules."""
        if time_zone_rules is None:
            time_zone_rules = local_time_rules
        if time_zone_rules is None:
            for argument_name in (
                "ambiguous_time_rules",
                "local_rules",
                "local_time_zone_rules",
                "rule",
                "rules",
                "time_zone_rule",
                "timezone_rules",
                "tz_rules",
            ):
                if argument_name in kwargs:
                    time_zone_rules = kwargs[argument_name]
                    break

        return time_zone_rules

    @classmethod
    def ConvertDictToDateTimeValues(
        cls, json_dict, time_zone_rules=None, local_time_rules=None, **kwargs
    ):
        """Converts a JSON dict into a date time values object.

        This method is deprecated use ConvertJSONToDateTimeValues instead.

        The dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case this should
        be 'DateTimeValues'. The rest of the elements of the dictionary make up the
        date time values object properties.

        Args:
          json_dict (dict[str, object]): JSON serialized objects.
          time_zone_rules (Optional[object]): caller supplied local time zone
              rules used to resolve ambiguous local times.
          local_time_rules (Optional[object]): alias for time_zone_rules.
          **kwargs (dict): optional aliases for time_zone_rules.

        Returns:
          dfdatetime.DateTimeValues: date and time values.
        """
        rules = cls._GetTimeZoneRules(time_zone_rules, local_time_rules, kwargs)
        return cls.ConvertJSONToDateTimeValues(json_dict, time_zone_rules=rules)

    @classmethod
    def ConvertDateTimeValuesToDict(
        cls, date_time_values, time_zone_rules=None, local_time_rules=None, **kwargs
    ):
        """Converts a date and time values object into a JSON dictionary.

        This method is deprecated use ConvertDateTimeValuesToJSON instead.

        The resulting dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case
        'DateTimeValues'. The rest of the elements of the dictionary make up the
        date and time value object properties.

        Args:
          date_time_values (dfdatetime.DateTimeValues): date and time values.
          time_zone_rules (Optional[object]): caller supplied local time zone
              rules used to resolve ambiguous local times.
          local_time_rules (Optional[object]): alias for time_zone_rules.
          **kwargs (dict): optional aliases for time_zone_rules.

        Returns:
          dict[str, object]: JSON serialized objects.

        Raises:
          TypeError: if object is not an instance of DateTimeValues.
        """
        if not isinstance(date_time_values, interface.DateTimeValues):
            raise TypeError

        rules = cls._GetTimeZoneRules(time_zone_rules, local_time_rules, kwargs)
        return cls.ConvertDateTimeValuesToJSON(date_time_values, time_zone_rules=rules)

    @classmethod
    def ConvertDateTimeValuesToJSON(
        cls, date_time_values, time_zone_rules=None, local_time_rules=None, **kwargs
    ):
        """Converts a date and time values object into a JSON dictionary.

        The resulting dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case
        'DateTimeValues'. The rest of the elements of the dictionary make up the
        date and time value object properties.

        Args:
          date_time_values (dfdatetime.DateTimeValues): date and time values.
          time_zone_rules (Optional[object]): caller supplied local time zone
              rules used to resolve ambiguous local times.
          local_time_rules (Optional[object]): alias for time_zone_rules.
          **kwargs (dict): optional aliases for time_zone_rules.

        Returns:
          dict[str, object]: JSON serialized objects.
        """
        rules = cls._GetTimeZoneRules(time_zone_rules, local_time_rules, kwargs)

        if rules is not None:
            date_time_values = copy.deepcopy(date_time_values)
            date_time_values = cls._ApplyLocalTimeZoneRules(date_time_values, rules)

        return date_time_values.CopyToSerializableDict()

    @classmethod
    def ConvertJSONToDateTimeValues(
        cls, json_dict, time_zone_rules=None, local_time_rules=None, **kwargs
    ):
        """Converts a JSON dict into a date time values object.

        The dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case this should
        be 'DateTimeValues'. The rest of the elements of the dictionary make up the
        date time values object properties.

        Args:
          json_dict (dict[str, object]): JSON serialized objects.
          time_zone_rules (Optional[object]): caller supplied local time zone
              rules used to resolve ambiguous local times.
          local_time_rules (Optional[object]): alias for time_zone_rules.
          **kwargs (dict): optional aliases for time_zone_rules.

        Returns:
          dfdatetime.DateTimeValues: date and time values.

        Raises:
          KeyError: If date and time values type is not supported by factory.
        """
        rules = cls._GetTimeZoneRules(time_zone_rules, local_time_rules, kwargs)

        json_dict = dict(json_dict)

        candidates = None
        for candidate_key in _CANDIDATE_KEYS:
            if candidate_key in json_dict:
                candidates = json_dict.pop(candidate_key)
                break

        offset_candidates = None
        for offset_key in _OFFSET_CANDIDATE_KEYS:
            if offset_key in json_dict:
                offset_candidates = json_dict.pop(offset_key)
                break

        exclusion_conditions = None
        for exclusion_key in _EXCLUSION_KEYS:
            if exclusion_key in json_dict:
                exclusion_conditions = json_dict.pop(exclusion_key)
                break

        had_ambiguity = False
        for ambiguity_key in _AMBIGUITY_FLAG_KEYS:
            if ambiguity_key in json_dict:
                had_ambiguity = bool(json_dict.pop(ambiguity_key))

        is_excluded = bool(json_dict.pop("is_excluded", False))

        class_name = json_dict.get("__class_name__")
        if class_name:
            del json_dict["__class_name__"]

        # Remove the class type from the JSON dict since we cannot pass it.
        del json_dict["__type__"]

        if class_name not in (
            "TimeElements",
            "TimeElementsInMilliseconds",
            "TimeElementsInMicroseconds",
            "TimeElementsInNanoseconds",
        ):
            is_delta = json_dict.get("is_delta")
            if is_delta is not None:
                del json_dict["is_delta"]

        is_local_time = json_dict.get("is_local_time")
        if is_local_time is not None:
            del json_dict["is_local_time"]

        time_zone_hint = json_dict.get("time_zone_hint")
        if time_zone_hint is not None:
            del json_dict["time_zone_hint"]

        if class_name in ("InvalidTime", "Never", "NotSet"):
            string = json_dict.get("string")
            if string is not None:
                del json_dict["string"]

        if class_name in ("GolangTime", "RFC2579DateTime"):
            time_zone_offset = json_dict.get("time_zone_offset")
            if time_zone_offset is not None:
                del json_dict["time_zone_offset"]

        date_time = factory.Factory.NewDateTimeValues(class_name, **json_dict)

        if isinstance(candidates, dict):
            candidates = [candidates]

        if candidates:
            deserialized_candidates = []
            candidate_offsets = []
            for candidate in candidates:
                if isinstance(candidate, dict) and candidate.get("__type__"):
                    deserialized_candidate = cls.ConvertJSONToDateTimeValues(candidate)
                    deserialized_candidates.append(deserialized_candidate)
                elif isinstance(candidate, int):
                    candidate_offsets.append(candidate)
                elif isinstance(candidate, dict) and (
                    "time_zone_offset" in candidate
                    and "timestamp" not in candidate
                    and "__class_name__" not in candidate
                ):
                    candidate_offsets.append(candidate)
                else:
                    deserialized_candidate = copy.deepcopy(candidate)
                    deserialized_candidates.append(deserialized_candidate)

            for candidate_offset in candidate_offsets:
                if isinstance(candidate_offset, dict):
                    offset_value = candidate_offset.get("time_zone_offset")
                    candidate_specification = candidate_offset
                else:
                    offset_value = candidate_offset
                    candidate_specification = None

                deserialized_candidates.append(
                    cls._CreateCandidateFromOffset(
                        date_time, offset_value, candidate_specification
                    )
                )

            if deserialized_candidates:
                date_time.time_zone_candidates = deserialized_candidates
                had_ambiguity = True

        if isinstance(offset_candidates, (int, str)):
            offset_candidates = [offset_candidates]

        if offset_candidates and not date_time.time_zone_candidates:
            deserialized_candidates = []
            for candidate_offset in offset_candidates:
                if isinstance(candidate_offset, dict):
                    offset_value = candidate_offset.get("time_zone_offset")
                    candidate_specification = candidate_offset
                else:
                    offset_value = candidate_offset
                    candidate_specification = None
                deserialized_candidates.append(
                    cls._CreateCandidateFromOffset(
                        date_time, offset_value, candidate_specification
                    )
                )

            date_time.time_zone_candidates = deserialized_candidates
            had_ambiguity = True

        if exclusion_conditions is not None:
            date_time.exclusion_conditions = copy.deepcopy(exclusion_conditions)
        if had_ambiguity:
            date_time.had_ambiguity = True
        if is_excluded:
            date_time.is_excluded = True

        if is_local_time:
            date_time.is_local_time = is_local_time
        if time_zone_hint:
            date_time.time_zone_hint = time_zone_hint

        if not date_time.time_zone_candidates:
            date_time = cls._ApplyLocalTimeZoneRules(date_time, rules)

        return date_time
