# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Timestamp parsing with explicit precision.

The audit deliberately keeps the precision that was present in the source.
A date-only timestamp denotes the whole UTC day, so it can be placed anywhere
inside that day.  A timestamp with a seconds component denotes an instant.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from .model import TimeSpan

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_DAY_US = 24 * 60 * 60 * 1_000_000

_ISO_RE = re.compile(
    r'(?<!\d)'
    r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})'
    r'(?:[T ](?P<hour>\d{2})'
    r'(?::(?P<minute>\d{2})'
    r'(?::(?P<second>\d{2})(?:\.(?P<fraction>\d{1,9}))?'
    r')?'
    r')?'
    r')?'
    r'(?P<tz>Z|[+-]\d{2}:?\d{2})?'
    r'(?!\d)'
)

_EPOCH_RE = re.compile(r'^\d{10,16}$')


def _to_utc_us(value: datetime) -> int:
    delta = value.astimezone(timezone.utc) - _EPOCH
    return delta.days * 86400 * 1_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _timezone_from_match(value: Optional[str]) -> timezone:
    if not value or value == 'Z':
        return timezone.utc
    sign = 1 if value[0] == '+' else -1
    digits = value[1:].replace(':', '')
    hours = int(digits[:2])
    minutes = int(digits[2:4])
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def parse_time_span(value: object) -> Optional[TimeSpan]:  # noqa: C901
    """Parse an ISO-8601-like timestamp or a Unix epoch value.

    Returns ``None`` when no timestamp can be recognized.  The parser is
    intentionally permissive: it also finds a timestamp embedded in log text,
    a file name, or other free-form evidence context.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        if 1_000_000_000 <= number < 10_000_000_000:
            return TimeSpan(number * 1_000_000, number * 1_000_000, 'second', str(value))
        if 10_000_000_000 <= number < 10_000_000_000_000:
            return TimeSpan(number * 1_000, number * 1_000, 'millisecond', str(value))
        if 10_000_000_000_000 <= number < 10_000_000_000_000_000:
            return TimeSpan(number, number, 'microsecond', str(value))
        return None

    text = str(value).strip()
    if not text:
        return None
    if _EPOCH_RE.fullmatch(text):
        return parse_time_span(int(text))

    match = _ISO_RE.search(text)
    if match is None:
        return None

    year = int(match.group('year'))
    month = int(match.group('month'))
    day = int(match.group('day'))
    hour_s = match.group('hour')
    minute_s = match.group('minute')
    second_s = match.group('second')
    fraction_s = match.group('fraction')
    try:
        tz = _timezone_from_match(match.group('tz'))
    except ValueError:
        return None

    try:
        if hour_s is None:
            start_dt = datetime(year, month, day, tzinfo=tz)
            start = _to_utc_us(start_dt)
            return TimeSpan(start, start + _ONE_DAY_US - 1, 'date', text)

        hour = int(hour_s)
        if minute_s is None:
            start_dt = datetime(year, month, day, hour, tzinfo=tz)
            start = _to_utc_us(start_dt)
            return TimeSpan(start, start + 60 * 60 * 1_000_000 - 1, 'hour', text)

        minute = int(minute_s)
        if second_s is None:
            start_dt = datetime(year, month, day, hour, minute, tzinfo=tz)
            start = _to_utc_us(start_dt)
            return TimeSpan(start, start + 60 * 1_000_000 - 1, 'minute', text)

        second = int(second_s)
        fraction = (fraction_s or '').ljust(6, '0')[:6]
        microsecond = int(fraction) if fraction else 0
        instant = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tz)
        point = _to_utc_us(instant)
        precision = 'microsecond' if fraction_s else 'second'
        return TimeSpan(point, point, precision, text)
    except ValueError:
        return None


def format_microseconds(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    instant = _EPOCH + timedelta(microseconds=value)
    return instant.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def truncate_to_span(value: int, span: TimeSpan) -> int:
    """Clamp a witness time to a concrete span, if it is bounded."""
    if span.start is not None and value < span.start:
        return span.start
    if span.end is not None and value > span.end:
        return span.end
    return value
