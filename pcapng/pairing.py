"""
Read-only forensic pairing of packet observations taken at two ends of a link.

The two capture points may use different interfaces and capture lengths.  This
module therefore never pairs packets just because metadata (or a packet header)
looks similar: a pair is reported only when the captured bytes provide a common
prefix, the original packet lengths agree, the caller's direction condition
holds, the caller's *finite* time window holds, and the candidate is unique on
both sides.

The API is intentionally read-only.  It consumes pcap-ng streams (or iterables
of packet blocks) with :class:`~pcapng.scanner.FileScanner` and never writes to
them.

Example:

    .. code-block:: python

        from pcapng.pairing import pair_pcapng

        report = pair_pcapng(
            "left.pcapng",
            "right.pcapng",
            left_direction="outbound",
            right_direction="inbound",
            max_time_delta=0.010,
        )
        print(report.to_json(indent=2))

For a mirrored link the two direction labels usually differ (for example,
``outbound`` on one end is ``inbound`` on the other).  Passing non-``None``
string labels for both sides tells the matcher that those labels form the
caller-approved direction pair.  A callable may instead be supplied as a
direction extractor; in that case it should return canonical labels that are
equal for observations of the same directed traffic.
"""

import hashlib
import json
import math
import os
from collections import defaultdict

from pcapng.blocks import BasePacketBlock
from pcapng.exceptions import PairingInputError
from pcapng.scanner import FileScanner

__all__ = [
    "ForensicPairer",
    "IgnoredObservation",
    "NearMiss",
    "PacketObservation",
    "PacketPair",
    "PairingReport",
    "TimeWindow",
    "Truncation",
    "UnresolvedObservation",
    "common_prefix_length",
    "compare_captures",
    "iter_packet_observations",
    "observations_from_pcapng",
    "pair_captures",
    "pair_observations",
    "pair_packets",
    "pair_pcapng",
    "read_observations",
]


def _is_finite_number(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return False
    return not (math.isnan(value) or math.isinf(value))


def _require_int(name, value, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int):
        raise PairingInputError("{0} must be an integer".format(name))
    if value < minimum:
        raise PairingInputError(
            "{0} must be greater than or equal to {1}".format(name, minimum)
        )
    return value


def common_prefix_length(left, right):
    """
    Return the number of leading bytes shared by two byte strings.

    The implementation uses binary search so that a long, mostly equal payload
    does not require a Python loop over every byte.
    """

    left = memoryview(left)
    right = memoryview(right)
    limit = min(len(left), len(right))
    if limit == 0:
        return 0
    if left[:limit] == right[:limit]:
        return limit

    low = 0
    high = limit
    while low < high:
        middle = (low + high + 1) // 2
        if left[:middle] == right[:middle]:
            low = middle
        else:
            high = middle - 1
    return low


class TimeWindow(object):
    """
    Finite compatibility window for two observation timestamps.

    ``min_delta`` and ``max_delta`` are bounds on the absolute timestamp
    difference, in seconds.  Both bounds must be finite; an unbounded window is
    deliberately rejected because it would turn an investigative correlation
    into a mere guess.
    """

    __slots__ = ("min_delta", "max_delta")

    def __init__(self, max_delta, min_delta=0.0):
        if not _is_finite_number(max_delta):
            raise PairingInputError("max_delta must be a finite number")
        if not _is_finite_number(min_delta):
            raise PairingInputError("min_delta must be a finite number")
        max_delta = float(max_delta)
        min_delta = float(min_delta)
        if max_delta < 0:
            raise PairingInputError("max_delta must not be negative")
        if min_delta < 0:
            raise PairingInputError("min_delta must not be negative")
        if min_delta > max_delta:
            raise PairingInputError("min_delta must not exceed max_delta")
        object.__setattr__(self, "max_delta", max_delta)
        object.__setattr__(self, "min_delta", min_delta)

    def __setattr__(self, name, value):
        raise AttributeError("TimeWindow is read-only")

    @property
    def tolerance(self):
        """Alias for the maximum absolute timestamp difference."""

        return self.max_delta

    def delta(self, left_timestamp, right_timestamp):
        """Return the signed ``right - left`` timestamp difference."""

        if left_timestamp is None or right_timestamp is None:
            return None
        if not _is_finite_number(left_timestamp):
            raise PairingInputError("observation timestamp must be finite")
        if not _is_finite_number(right_timestamp):
            raise PairingInputError("observation timestamp must be finite")
        return float(right_timestamp) - float(left_timestamp)

    def compatible(self, left_timestamp, right_timestamp):
        """Return whether two timestamps satisfy this finite window."""

        delta = self.delta(left_timestamp, right_timestamp)
        if delta is None:
            return False
        return self.min_delta <= abs(delta) <= self.max_delta

    def __eq__(self, other):
        return (
            isinstance(other, TimeWindow)
            and self.min_delta == other.min_delta
            and self.max_delta == other.max_delta
        )

    def __repr__(self):
        return "<TimeWindow min_delta={0!r} max_delta={1!r}>".format(
            self.min_delta, self.max_delta
        )

    def to_dict(self):
        return {"min_delta": self.min_delta, "max_delta": self.max_delta}


class PacketObservation(object):
    """
    Immutable view of one packet as observed at one capture end.

    ``packet_data`` contains the bytes actually captured.  ``packet_len`` is
    the original on-wire length.  A short ``packet_data`` with a larger
    ``packet_len`` therefore records a truncation, while the missing suffix is
    explicitly not available as evidence.
    """

    __slots__ = (
        "timestamp",
        "packet_data",
        "packet_len",
        "direction",
        "side",
        "interface_id",
        "ordinal",
        "source",
        "link_type",
        "snaplen",
        "interface_name",
        "block",
    )

    def __init__(
        self,
        timestamp=None,
        packet_data=b"",
        packet_len=None,
        direction=None,
        side=None,
        interface_id=None,
        ordinal=None,
        source=None,
        link_type=None,
        snaplen=None,
        interface_name=None,
        block=None,
    ):
        if isinstance(packet_data, bytearray):
            packet_data = bytes(packet_data)
        elif isinstance(packet_data, memoryview):
            packet_data = packet_data.tobytes()
        if not isinstance(packet_data, bytes):
            raise PairingInputError("packet_data must be bytes-like")

        if packet_len is None:
            packet_len = len(packet_data)
        _require_int("packet_len", packet_len, 0)
        if packet_len < len(packet_data):
            raise PairingInputError(
                "packet_len ({0}) must not be smaller than captured data "
                "({1})".format(packet_len, len(packet_data))
            )
        if timestamp is not None and not _is_finite_number(timestamp):
            raise PairingInputError("timestamp must be finite or None")
        if ordinal is not None:
            _require_int("ordinal", ordinal, 0)

        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "packet_data", packet_data)
        object.__setattr__(self, "packet_len", packet_len)
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "side", side)
        object.__setattr__(self, "interface_id", interface_id)
        object.__setattr__(self, "ordinal", ordinal)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "link_type", link_type)
        object.__setattr__(self, "snaplen", snaplen)
        object.__setattr__(self, "interface_name", interface_name)
        object.__setattr__(self, "block", block)

    def __setattr__(self, name, value):
        raise AttributeError("PacketObservation is read-only")

    @classmethod
    def from_block(cls, block, side=None, direction=None, ordinal=None, source=None):
        """Build an observation from a pcap-ng packet block."""

        if not isinstance(block, BasePacketBlock):
            raise TypeError("not a pcap-ng packet block")

        packet_data = block.packet_data
        if packet_data is None:
            packet_data = b""
        packet_len = block.packet_len

        timestamp = None
        if hasattr(block, "timestamp_high") and hasattr(block, "timestamp_low"):
            timestamp = block.timestamp

        interface = getattr(block, "interface", None)
        interface_id = getattr(block, "interface_id", None)
        link_type = getattr(interface, "link_type", None)
        snaplen = getattr(interface, "snaplen", None)

        interface_name = None
        if interface is not None:
            try:
                interface_name = interface.options["if_name"]
            except (KeyError, AttributeError):
                interface_name = None

        return cls(
            timestamp=timestamp,
            packet_data=packet_data,
            packet_len=packet_len,
            direction=direction,
            side=side,
            interface_id=interface_id,
            ordinal=ordinal,
            source=source,
            link_type=link_type,
            snaplen=snaplen,
            interface_name=interface_name,
            block=block,
        )

    def copy(self, **changes):
        """Return a read-only copy with selected fields replaced."""

        values = dict(
            timestamp=self.timestamp,
            packet_data=self.packet_data,
            packet_len=self.packet_len,
            direction=self.direction,
            side=self.side,
            interface_id=self.interface_id,
            ordinal=self.ordinal,
            source=self.source,
            link_type=self.link_type,
            snaplen=self.snaplen,
            interface_name=self.interface_name,
            block=self.block,
        )
        unknown = set(changes) - set(values)
        if unknown:
            raise TypeError("unknown observation fields: {0}".format(sorted(unknown)))
        values.update(changes)
        return type(self)(**values)

    @property
    def captured_len(self):
        return len(self.packet_data)

    @property
    def payload(self):
        return self.packet_data

    @property
    def is_truncated(self):
        return self.captured_len < self.packet_len

    @property
    def missing_len(self):
        return self.packet_len - self.captured_len

    @property
    def label(self):
        side = self.side if self.side is not None else "?"
        if self.ordinal is None:
            return side
        return "{0}#{1}".format(side, self.ordinal)

    def __eq__(self, other):
        if not isinstance(other, PacketObservation):
            return NotImplemented
        return (
            self.timestamp == other.timestamp
            and self.packet_data == other.packet_data
            and self.packet_len == other.packet_len
            and self.direction == other.direction
            and self.side == other.side
            and self.interface_id == other.interface_id
            and self.ordinal == other.ordinal
            and self.source == other.source
            and self.link_type == other.link_type
            and self.snaplen == other.snaplen
            and self.interface_name == other.interface_name
        )

    def __repr__(self):
        return (
            "<PacketObservation {0} direction={1!r} timestamp={2!r} "
            "captured_len={3} packet_len={4} interface_id={5!r}>"
        ).format(
            self.label,
            self.direction,
            self.timestamp,
            self.captured_len,
            self.packet_len,
            self.interface_id,
        )

    def to_dict(self, include_payload=False):
        result = {
            "label": self.label,
            "side": self.side,
            "direction": self.direction,
            "timestamp": self.timestamp,
            "captured_len": self.captured_len,
            "packet_len": self.packet_len,
            "truncated": self.is_truncated,
            "missing_len": self.missing_len,
            "interface_id": self.interface_id,
            "interface_name": self.interface_name,
            "link_type": self.link_type,
            "snaplen": self.snaplen,
            "ordinal": self.ordinal,
            "source": self.source,
            "payload_sha256": hashlib.sha256(self.packet_data).hexdigest(),
        }
        if include_payload:
            result["payload_hex"] = self.packet_data.hex()
        return result


class Truncation(object):
    """Location of the first original byte not captured on one side."""

    __slots__ = (
        "side",
        "offset",
        "captured_length",
        "packet_length",
        "direction",
        "interface_id",
        "ordinal",
        "source",
    )

    def __init__(
        self,
        side,
        offset,
        captured_length,
        packet_length,
        direction=None,
        interface_id=None,
        ordinal=None,
        source=None,
    ):
        _require_int("offset", offset, 0)
        _require_int("captured_length", captured_length, 0)
        _require_int("packet_length", packet_length, 0)
        if captured_length > packet_length:
            raise PairingInputError("captured_length must not exceed packet_length")
        if offset != captured_length:
            raise PairingInputError(
                "offset must equal the number of captured bytes for a prefix"
            )
        object.__setattr__(self, "side", side)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "captured_length", captured_length)
        object.__setattr__(self, "packet_length", packet_length)
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "interface_id", interface_id)
        object.__setattr__(self, "ordinal", ordinal)
        object.__setattr__(self, "source", source)

    def __setattr__(self, name, value):
        raise AttributeError("Truncation is read-only")

    @classmethod
    def from_observation(cls, observation):
        if not observation.is_truncated:
            return None
        return cls(
            side=observation.side,
            offset=observation.captured_len,
            captured_length=observation.captured_len,
            packet_length=observation.packet_len,
            direction=observation.direction,
            interface_id=observation.interface_id,
            ordinal=observation.ordinal,
            source=observation.source,
        )

    @property
    def missing_bytes(self):
        return self.packet_length - self.captured_length

    @property
    def first_missing_byte(self):
        return self.offset

    @property
    def next_unobserved_offset(self):
        return self.offset

    def __eq__(self, other):
        if not isinstance(other, Truncation):
            return NotImplemented
        return (
            self.side == other.side
            and self.offset == other.offset
            and self.captured_length == other.captured_length
            and self.packet_length == other.packet_length
            and self.direction == other.direction
            and self.interface_id == other.interface_id
            and self.ordinal == other.ordinal
            and self.source == other.source
        )

    def __repr__(self):
        return (
            "<Truncation side={0!r} offset={1} captured_length={2} "
            "packet_length={3}>"
        ).format(
            self.side, self.offset, self.captured_length, self.packet_length
        )

    def to_dict(self):
        return {
            "side": self.side,
            "offset": self.offset,
            "first_missing_byte": self.first_missing_byte,
            "captured_length": self.captured_length,
            "packet_length": self.packet_length,
            "missing_bytes": self.missing_bytes,
            "direction": self.direction,
            "interface_id": self.interface_id,
            "ordinal": self.ordinal,
            "source": self.source,
        }


class NearMiss(object):
    """
    Diagnostic for a packet that was not an evidence edge.

    Near misses are kept in the report so that a rejected candidate can be
    explained (for example ``payload_conflict`` or ``time_conflict``) without
    turning it into a pair.
    """

    __slots__ = ("observation", "kind", "common_prefix_length", "time_delta")

    def __init__(self, observation, kind, common_prefix_length=None, time_delta=None):
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "common_prefix_length", common_prefix_length)
        object.__setattr__(self, "time_delta", time_delta)

    def __setattr__(self, name, value):
        raise AttributeError("NearMiss is read-only")

    def __repr__(self):
        return "<NearMiss kind={0!r} observation={1}>".format(
            self.kind, self.observation.label
        )

    def to_dict(self):
        return {
            "kind": self.kind,
            "observation": self.observation.label,
            "common_prefix_length": self.common_prefix_length,
            "time_delta": self.time_delta,
        }


class PacketPair(object):
    """
    A mutually unique, evidence-supported pair of observations.

    ``common_prefix_length`` is the number of leading original bytes observed
    identically on both sides.  If a side is truncated, the corresponding
    :class:`Truncation` gives the first original byte offset that side could not
    observe.
    """

    __slots__ = ("left", "right", "common_prefix_length", "time_delta", "truncations")

    def __init__(self, left, right, common_prefix_length, time_delta, truncations=()):
        _require_int("common_prefix_length", common_prefix_length, 0)
        if common_prefix_length > min(left.captured_len, right.captured_len):
            raise PairingInputError(
                "common_prefix_length must not exceed either captured length"
            )
        object.__setattr__(self, "left", left)
        object.__setattr__(self, "right", right)
        object.__setattr__(self, "common_prefix_length", common_prefix_length)
        object.__setattr__(self, "time_delta", time_delta)
        object.__setattr__(self, "truncations", tuple(truncations))

    def __setattr__(self, name, value):
        raise AttributeError("PacketPair is read-only")

    @property
    def common_prefix(self):
        return self.left.packet_data[: self.common_prefix_length]

    @property
    def common_prefix_sha256(self):
        return hashlib.sha256(self.common_prefix).hexdigest()

    @property
    def truncated_sides(self):
        return tuple(item.side for item in self.truncations)

    @property
    def truncated_side(self):
        """Return the sole truncated side, or ``None`` if ambiguous."""

        if len(self.truncations) == 1:
            return self.truncations[0].side
        return None

    @property
    def first_truncation_offset(self):
        """Lowest original byte offset that either side failed to capture."""

        if not self.truncations:
            return None
        return min(item.offset for item in self.truncations)

    @property
    def left_truncated_at(self):
        item = self.truncation_for(self.left.side)
        return None if item is None else item.offset

    @property
    def right_truncated_at(self):
        item = self.truncation_for(self.right.side)
        return None if item is None else item.offset

    def truncation_for(self, side):
        for item in self.truncations:
            if item.side == side:
                return item
        return None

    def __eq__(self, other):
        if not isinstance(other, PacketPair):
            return NotImplemented
        return (
            self.left == other.left
            and self.right == other.right
            and self.common_prefix_length == other.common_prefix_length
            and self.time_delta == other.time_delta
            and self.truncations == other.truncations
        )

    def __repr__(self):
        return "<PacketPair {0} <-> {1} common_prefix_length={2}>".format(
            self.left.label, self.right.label, self.common_prefix_length
        )

    def to_dict(self, include_payload=False, include_prefix_hex=False):
        result = {
            "left": self.left.to_dict(include_payload=include_payload),
            "right": self.right.to_dict(include_payload=include_payload),
            "time_delta": self.time_delta,
            "common_prefix_length": self.common_prefix_length,
            "common_prefix_sha256": self.common_prefix_sha256,
            "truncated_sides": list(self.truncated_sides),
            "truncated_side": self.truncated_side,
            "first_truncation_offset": self.first_truncation_offset,
            "left_truncated_at": self.left_truncated_at,
            "right_truncated_at": self.right_truncated_at,
            "truncations": [item.to_dict() for item in self.truncations],
            "evidence": {
                "same_direction_condition": True,
                "same_original_length": self.left.packet_len
                == self.right.packet_len,
                "captured_prefix_matches": True,
                "mutually_unique_candidate": True,
            },
        }
        if include_prefix_hex:
            result["common_prefix_hex"] = self.common_prefix.hex()
        return result


class UnresolvedObservation(object):
    """An observation that was not promoted to a pair, with its diagnostics."""

    __slots__ = ("observation", "reason", "candidates", "near_misses")

    def __init__(self, observation, reason, candidates=(), near_misses=()):
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "candidates", tuple(candidates))
        object.__setattr__(self, "near_misses", tuple(near_misses))

    def __setattr__(self, name, value):
        raise AttributeError("UnresolvedObservation is read-only")

    @property
    def side(self):
        return self.observation.side

    @property
    def truncation(self):
        """Truncation record for this observation, if it was shortened."""

        return Truncation.from_observation(self.observation)

    def __repr__(self):
        return "<UnresolvedObservation {0} reason={1!r} candidates={2}>".format(
            self.observation.label, self.reason, len(self.candidates)
        )

    def to_dict(self, include_payload=False):
        truncation = self.truncation
        return {
            "observation": self.observation.to_dict(
                include_payload=include_payload
            ),
            "reason": self.reason,
            "truncation": None if truncation is None else truncation.to_dict(),
            "candidates": [item.label for item in self.candidates],
            "near_misses": [item.to_dict() for item in self.near_misses],
        }


class IgnoredObservation(object):
    """An observation excluded by the caller's direction filter."""

    __slots__ = ("observation", "reason")

    def __init__(self, observation, reason):
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "reason", reason)

    def __setattr__(self, name, value):
        raise AttributeError("IgnoredObservation is read-only")

    def __repr__(self):
        return "<IgnoredObservation {0} reason={1!r}>".format(
            self.observation.label, self.reason
        )

    def to_dict(self, include_payload=False):
        return {
            "observation": self.observation.to_dict(
                include_payload=include_payload
            ),
            "reason": self.reason,
        }


class PairingReport(object):
    """
    Result of a forensic pairing run.

    Every considered observation appears either in ``pairs`` or in
    ``unresolved``.  Observations outside the caller's direction filter are
    listed in ``ignored`` so the report still accounts for the whole input.
    """

    __slots__ = (
        "pairs",
        "unresolved",
        "ignored",
        "time_window",
        "left_direction",
        "right_direction",
        "min_common_prefix",
        "require_complete_side",
        "allow_identical_partial_pairing",
    )

    def __init__(
        self,
        pairs,
        unresolved,
        ignored,
        time_window,
        left_direction=None,
        right_direction=None,
        min_common_prefix=1,
        require_complete_side=False,
        allow_identical_partial_pairing=False,
    ):
        object.__setattr__(self, "pairs", tuple(pairs))
        object.__setattr__(self, "unresolved", tuple(unresolved))
        object.__setattr__(self, "ignored", tuple(ignored))
        object.__setattr__(self, "time_window", time_window)
        object.__setattr__(self, "left_direction", left_direction)
        object.__setattr__(self, "right_direction", right_direction)
        object.__setattr__(self, "min_common_prefix", min_common_prefix)
        object.__setattr__(self, "require_complete_side", require_complete_side)
        object.__setattr__(
            self,
            "allow_identical_partial_pairing",
            allow_identical_partial_pairing,
        )

    def __setattr__(self, name, value):
        raise AttributeError("PairingReport is read-only")

    @property
    def matched(self):
        """Alias for :attr:`pairs`."""

        return self.pairs

    @property
    def matches(self):
        """Alias for :attr:`pairs`."""

        return self.pairs

    @property
    def unmatched(self):
        """Alias for :attr:`unresolved`."""

        return self.unresolved

    @property
    def ambiguous(self):
        return tuple(item for item in self.unresolved if item.candidates)

    @property
    def truncated_pairs(self):
        return tuple(item for item in self.pairs if item.truncations)

    @property
    def paired_count(self):
        return len(self.pairs)

    @property
    def unresolved_count(self):
        return len(self.unresolved)

    @property
    def ignored_count(self):
        return len(self.ignored)

    def pair_for(self, side, ordinal):
        for pair in self.pairs:
            if pair.left.side == side and pair.left.ordinal == ordinal:
                return pair
            if pair.right.side == side and pair.right.ordinal == ordinal:
                return pair
        return None

    def summary(self):
        pieces = [
            "paired={0}".format(self.paired_count),
            "unresolved={0}".format(self.unresolved_count),
            "ignored={0}".format(self.ignored_count),
        ]
        if self.truncated_pairs:
            pieces.append("truncated_pairs={0}".format(len(self.truncated_pairs)))
        return ", ".join(pieces)

    def __repr__(self):
        return "<PairingReport {0}>".format(self.summary())

    def to_dict(self, include_payload=False, include_prefix_hex=False):
        return {
            "time_window": self.time_window.to_dict(),
            "directions": {
                "left": self.left_direction,
                "right": self.right_direction,
            },
            "min_common_prefix": self.min_common_prefix,
            "require_complete_side": self.require_complete_side,
            "allow_identical_partial_pairing": (
                self.allow_identical_partial_pairing
            ),
            "summary": {
                "paired": self.paired_count,
                "unresolved": self.unresolved_count,
                "ignored": self.ignored_count,
                "truncated_pairs": len(self.truncated_pairs),
            },
            "pairs": [
                item.to_dict(
                    include_payload=include_payload,
                    include_prefix_hex=include_prefix_hex,
                )
                for item in self.pairs
            ],
            "unresolved": [
                item.to_dict(include_payload=include_payload)
                for item in self.unresolved
            ],
            "ignored": [
                item.to_dict(include_payload=include_payload)
                for item in self.ignored
            ],
        }

    def to_json(self, indent=None, include_payload=False, include_prefix_hex=False):
        return json.dumps(
            self.to_dict(
                include_payload=include_payload,
                include_prefix_hex=include_prefix_hex,
            ),
            indent=indent,
            sort_keys=True,
        )


def _resolve_direction_arguments(direction, left_direction, right_direction):
    if direction is None:
        return left_direction, right_direction
    if left_direction is not None or right_direction is not None:
        raise PairingInputError(
            "provide direction or left_direction/right_direction, not both"
        )
    if isinstance(direction, (tuple, list)):
        if len(direction) != 2:
            raise PairingInputError(
                "a direction pair must contain exactly two labels"
            )
        return direction[0], direction[1]
    return direction, direction


def _resolve_time_window(time_window, max_time_delta, time_tolerance):
    supplied = [
        value
        for value in (time_window, max_time_delta, time_tolerance)
        if value is not None
    ]
    if not supplied:
        raise PairingInputError(
            "a finite time window is required (use time_window or max_time_delta)"
        )
    if len(supplied) > 1:
        raise PairingInputError(
            "provide only one of time_window, max_time_delta, time_tolerance"
        )
    if time_window is not None:
        if isinstance(time_window, TimeWindow):
            return time_window
        if isinstance(time_window, (tuple, list)) and len(time_window) == 2:
            return TimeWindow(
                max_delta=time_window[1], min_delta=time_window[0]
            )
        if isinstance(time_window, dict):
            try:
                return TimeWindow(
                    max_delta=time_window["max_delta"],
                    min_delta=time_window.get("min_delta", 0.0),
                )
            except KeyError:
                pass
        raise PairingInputError(
            "time_window must be a TimeWindow, a (min, max) pair, or a dict"
        )
    return TimeWindow(supplied[0])


def _coerce_observation(item, side, direction=None):
    if isinstance(item, PacketObservation):
        # Copy even when only the side is unchanged: identity is used as the
        # internal graph key, so the same object passed twice must not collapse
        # two distinct observations into one candidate.
        changes = {"side": side}
        if direction is not None:
            changes["direction"] = direction
        return item.copy(**changes)
    if isinstance(item, BasePacketBlock):
        return PacketObservation.from_block(
            item, side=side, direction=direction
        )
    raise TypeError("expected a PacketObservation or pcap-ng packet block")


def _direction_matches(observation, requested):
    return requested is None or observation.direction == requested


def _directions_compatible(left, right, left_direction, right_direction):
    # When the caller supplied both labels, they explicitly approved that pair
    # of labels (mirrored link ends often use different names).  If only one
    # side was filtered, the other side is unrestricted.  With no direction
    # condition at all, require the observation labels to agree so that
    # opposite directions are never mixed by accident.
    if left_direction is not None and right_direction is not None:
        return True
    if left_direction is None and right_direction is None:
        return left.direction == right.direction
    if left_direction is None or right_direction is None:
        return True
    return left.direction == right.direction


def _near_miss_reason(near_misses):
    priority = (
        "payload_conflict",
        "insufficient_common_prefix",
        "unverified_truncated_suffix",
        "time_conflict",
        "direction_conflict",
        "missing_timestamp",
    )
    kinds = set(item.kind for item in near_misses)
    for kind in priority:
        if kind in kinds:
            return kind
    return "no_candidate"


def pair_observations(
    left,
    right,
    *,
    direction=None,
    left_direction=None,
    right_direction=None,
    max_time_delta=None,
    time_tolerance=None,
    time_window=None,
    min_common_prefix=1,
    require_complete_side=False,
    allow_identical_partial_pairing=False,
    left_label="left",
    right_label="right"
):
    """
    Pair two sequences of packet observations using only evidence.

    :param left: iterable of :class:`PacketObservation` (or packet blocks).
    :param right: iterable of :class:`PacketObservation` (or packet blocks).
    :param direction: A single label applied to both sides, or a
        ``(left_label, right_label)`` pair, when separate labels are not
        supplied.
    :param left_direction:
        Direction label to require on the left, or ``None`` for all.  When both
        direction labels are supplied they are treated as the caller-approved
        direction pair (so ``outbound``/``inbound`` can match).
    :param right_direction: Direction label to require on the right.
    :param max_time_delta:
        Finite maximum absolute timestamp difference, in seconds.
    :param time_tolerance: Alias for ``max_time_delta``.
    :param time_window: A :class:`TimeWindow`, a ``(min_delta, max_delta)``
        pair, or a dict with ``min_delta``/``max_delta`` keys.
    :param min_common_prefix:
        Minimum number of identical leading captured bytes required as
        evidence.  Defaults to 1 so metadata alone can never create a pair.
    :param require_complete_side:
        When true, at least one side must have captured the complete original
        packet.  This is the strictest forensic mode.
    :param allow_identical_partial_pairing:
        When both sides are truncated, different capture lengths are normally
        paired by their verified common prefix.  If both stopped at exactly the
        same offset, only an identical prefix is visible and the unobserved
        suffixes cannot be distinguished; such pairs stay unresolved unless
        this flag is explicitly set.
    :param left_label: Side name used in truncation reports.
    :param right_label: Side name used in truncation reports.
    :return: :class:`PairingReport`.

    A candidate edge requires all of the following:

    * the two observations satisfy the caller's direction condition;
    * their original (on-wire) lengths are equal;
    * their timestamps fit the finite time window;
    * their captured bytes agree over the whole shorter capture;
    * that common prefix has at least ``min_common_prefix`` bytes.

    An edge becomes a pair only when it is the sole candidate for both of its
    endpoints.  Many-to-one, many-to-many, conflicting payloads, and repeated
    prefixes therefore remain in ``report.unresolved``.
    """

    left_direction, right_direction = _resolve_direction_arguments(
        direction, left_direction, right_direction
    )

    window = _resolve_time_window(time_window, max_time_delta, time_tolerance)
    _require_int("min_common_prefix", min_common_prefix, 0)
    if not isinstance(require_complete_side, bool):
        raise PairingInputError("require_complete_side must be a boolean")
    if not isinstance(allow_identical_partial_pairing, bool):
        raise PairingInputError(
            "allow_identical_partial_pairing must be a boolean"
        )

    left_observations = list(left)
    right_observations = list(right)

    ignored = []
    considered_left = []
    considered_right = []

    for ordinal, item in enumerate(left_observations):
        observation = _coerce_observation(item, left_label)
        if observation.direction is None and left_direction is not None:
            observation = observation.copy(direction=left_direction)
        if observation.ordinal is None:
            observation = observation.copy(ordinal=ordinal)
        if _direction_matches(observation, left_direction):
            considered_left.append(observation)
        else:
            ignored.append(
                IgnoredObservation(observation, reason="direction_filtered")
            )

    for ordinal, item in enumerate(right_observations):
        observation = _coerce_observation(item, right_label)
        if observation.direction is None and right_direction is not None:
            observation = observation.copy(direction=right_direction)
        if observation.ordinal is None:
            observation = observation.copy(ordinal=ordinal)
        if _direction_matches(observation, right_direction):
            considered_right.append(observation)
        else:
            ignored.append(
                IgnoredObservation(observation, reason="direction_filtered")
            )

    right_by_length = defaultdict(list)
    for observation in considered_right:
        right_by_length[observation.packet_len].append(observation)

    candidates_left = defaultdict(list)
    candidates_right = defaultdict(list)
    near_left = defaultdict(list)
    near_right = defaultdict(list)

    for left_observation in considered_left:
        for right_observation in right_by_length.get(
            left_observation.packet_len, ()
        ):
            if not _directions_compatible(
                left_observation,
                right_observation,
                left_direction,
                right_direction,
            ):
                kind = "direction_conflict"
                near_left[id(left_observation)].append(
                    NearMiss(right_observation, kind)
                )
                near_right[id(right_observation)].append(
                    NearMiss(left_observation, kind)
                )
                continue

            if (
                left_observation.timestamp is None
                or right_observation.timestamp is None
            ):
                kind = "missing_timestamp"
                near_left[id(left_observation)].append(
                    NearMiss(right_observation, kind)
                )
                near_right[id(right_observation)].append(
                    NearMiss(left_observation, kind)
                )
                continue

            delta = window.delta(
                left_observation.timestamp, right_observation.timestamp
            )
            if not window.compatible(
                left_observation.timestamp, right_observation.timestamp
            ):
                kind = "time_conflict"
                near_left[id(left_observation)].append(
                    NearMiss(right_observation, kind, time_delta=delta)
                )
                near_right[id(right_observation)].append(
                    NearMiss(left_observation, kind, time_delta=delta)
                )
                continue

            prefix_length = common_prefix_length(
                left_observation.packet_data, right_observation.packet_data
            )
            shorter_length = min(
                left_observation.captured_len, right_observation.captured_len
            )
            if prefix_length != shorter_length:
                kind = "payload_conflict"
                near_left[id(left_observation)].append(
                    NearMiss(
                        right_observation,
                        kind,
                        common_prefix_length=prefix_length,
                        time_delta=delta,
                    )
                )
                near_right[id(right_observation)].append(
                    NearMiss(
                        left_observation,
                        kind,
                        common_prefix_length=prefix_length,
                        time_delta=delta,
                    )
                )
                continue

            if prefix_length < min_common_prefix:
                kind = "insufficient_common_prefix"
                near_left[id(left_observation)].append(
                    NearMiss(
                        right_observation,
                        kind,
                        common_prefix_length=prefix_length,
                        time_delta=delta,
                    )
                )
                near_right[id(right_observation)].append(
                    NearMiss(
                        left_observation,
                        kind,
                        common_prefix_length=prefix_length,
                        time_delta=delta,
                    )
                )
                continue

            both_truncated = (
                left_observation.captured_len < left_observation.packet_len
                and right_observation.captured_len
                < right_observation.packet_len
            )
            unverified_suffix = both_truncated and (
                require_complete_side
                or (
                    left_observation.captured_len
                    == right_observation.captured_len
                    and not allow_identical_partial_pairing
                )
            )
            if unverified_suffix:
                kind = "unverified_truncated_suffix"
                near_left[id(left_observation)].append(
                    NearMiss(
                        right_observation,
                        kind,
                        common_prefix_length=prefix_length,
                        time_delta=delta,
                    )
                )
                near_right[id(right_observation)].append(
                    NearMiss(
                        left_observation,
                        kind,
                        common_prefix_length=prefix_length,
                        time_delta=delta,
                    )
                )
                continue

            candidates_left[id(left_observation)].append(
                (right_observation, prefix_length, delta)
            )
            candidates_right[id(right_observation)].append(
                (left_observation, prefix_length, delta)
            )

    pairs = []
    paired_left = set()
    paired_right = set()

    for left_observation in considered_left:
        left_candidates = candidates_left.get(id(left_observation), ())
        if len(left_candidates) != 1:
            continue
        right_observation, prefix_length, delta = left_candidates[0]
        right_candidates = candidates_right.get(id(right_observation), ())
        if len(right_candidates) != 1:
            continue

        truncations = []
        for observation in (left_observation, right_observation):
            truncation = Truncation.from_observation(observation)
            if truncation is not None:
                truncations.append(truncation)

        pairs.append(
            PacketPair(
                left=left_observation,
                right=right_observation,
                common_prefix_length=prefix_length,
                time_delta=delta,
                truncations=truncations,
            )
        )
        paired_left.add(id(left_observation))
        paired_right.add(id(right_observation))

    unresolved = []

    for observation in considered_left:
        if id(observation) in paired_left:
            continue
        candidates = candidates_left.get(id(observation), ())
        if observation.timestamp is None:
            reason = "missing_timestamp"
        elif len(candidates) > 1:
            reason = "multiple_candidates"
        elif len(candidates) == 1:
            reason = "not_mutually_unique"
        else:
            reason = _near_miss_reason(near_left.get(id(observation), ()))
        unresolved.append(
            UnresolvedObservation(
                observation=observation,
                reason=reason,
                candidates=[item[0] for item in candidates],
                near_misses=near_left.get(id(observation), ()),
            )
        )

    for observation in considered_right:
        if id(observation) in paired_right:
            continue
        candidates = candidates_right.get(id(observation), ())
        if observation.timestamp is None:
            reason = "missing_timestamp"
        elif len(candidates) > 1:
            reason = "multiple_candidates"
        elif len(candidates) == 1:
            reason = "not_mutually_unique"
        else:
            reason = _near_miss_reason(near_right.get(id(observation), ()))
        unresolved.append(
            UnresolvedObservation(
                observation=observation,
                reason=reason,
                candidates=[item[0] for item in candidates],
                near_misses=near_right.get(id(observation), ()),
            )
        )

    return PairingReport(
        pairs=pairs,
        unresolved=unresolved,
        ignored=ignored,
        time_window=window,
        left_direction=left_direction,
        right_direction=right_direction,
        min_common_prefix=min_common_prefix,
        require_complete_side=require_complete_side,
        allow_identical_partial_pairing=allow_identical_partial_pairing,
    )


def _is_path(value):
    if isinstance(value, (str, bytes)):
        return True
    return getattr(value, "__fspath__", None) is not None


def iter_packet_observations(source, *, side=None, direction=None, source_name=None):
    """
    Yield read-only :class:`PacketObservation` objects from a pcap-ng source.

    ``source`` may be a path, a binary file-like object, or an iterable of
    pcap-ng packet blocks / observations.  Only packet blocks are yielded;
    section, interface, and statistics blocks are skipped.

    ``direction`` may be a label applied to every packet, or a callable
    receiving the packet block (useful for captures containing both
    directions).
    """

    def make_observation(block, ordinal):
        value = direction(block) if callable(direction) else direction
        return PacketObservation.from_block(
            block,
            side=side,
            direction=value,
            ordinal=ordinal,
            source=source_name,
        )

    if _is_path(source):
        if source_name is None:
            path_value = os.fspath(source) if hasattr(os, "fspath") else source
            if isinstance(path_value, bytes):
                if hasattr(os, "fsdecode"):
                    path_value = os.fsdecode(path_value)
                else:  # pragma: no cover - Python 3.5 fallback
                    path_value = path_value.decode()
            source_name = str(path_value)
        stream = open(source, "rb")
        try:
            ordinal = 0
            for block in FileScanner(stream):
                if isinstance(block, BasePacketBlock):
                    yield make_observation(block, ordinal)
                    ordinal += 1
        finally:
            stream.close()
        return

    if hasattr(source, "read"):
        ordinal = 0
        for block in FileScanner(source):
            if isinstance(block, BasePacketBlock):
                yield make_observation(block, ordinal)
                ordinal += 1
        return

    ordinal = 0
    for item in source:
        if isinstance(item, PacketObservation):
            value = None
            if callable(direction):
                value = direction(item)
            else:
                value = direction
            changes = {"side": side, "ordinal": ordinal, "source": source_name}
            if value is not None:
                changes["direction"] = value
            yield item.copy(**changes)
            ordinal += 1
        elif isinstance(item, BasePacketBlock):
            yield make_observation(item, ordinal)
            ordinal += 1
        else:
            raise TypeError(
                "expected pcap-ng packet blocks or PacketObservation objects"
            )


def observations_from_pcapng(source, *, side=None, direction=None, source_name=None):
    """Materialize :func:`iter_packet_observations` into a list."""

    return list(
        iter_packet_observations(
            source, side=side, direction=direction, source_name=source_name
        )
    )


read_observations = iter_packet_observations


def pair_pcapng(
    left,
    right,
    *,
    direction=None,
    left_direction=None,
    right_direction=None,
    max_time_delta=None,
    time_tolerance=None,
    time_window=None,
    min_common_prefix=1,
    require_complete_side=False,
    allow_identical_partial_pairing=False,
    left_label="left",
    right_label="right"
):
    """
    Read two pcap-ng sources and return their forensic pairing report.

    The sources are only opened for reading.  ``left_direction`` and
    ``right_direction`` may be fixed labels or callables as described in
    :func:`iter_packet_observations`; ``direction`` is a convenience label for
    both sides.
    """

    left_direction, right_direction = _resolve_direction_arguments(
        direction, left_direction, right_direction
    )

    left_observations = list(
        iter_packet_observations(
            left, side=left_label, direction=left_direction
        )
    )
    right_observations = list(
        iter_packet_observations(
            right, side=right_label, direction=right_direction
        )
    )

    left_filter = None if callable(left_direction) else left_direction
    right_filter = None if callable(right_direction) else right_direction

    return pair_observations(
        left_observations,
        right_observations,
        left_direction=left_filter,
        right_direction=right_filter,
        max_time_delta=max_time_delta,
        time_tolerance=time_tolerance,
        time_window=time_window,
        min_common_prefix=min_common_prefix,
        require_complete_side=require_complete_side,
        allow_identical_partial_pairing=allow_identical_partial_pairing,
        left_label=left_label,
        right_label=right_label,
    )


pair_packets = pair_observations
pair_captures = pair_pcapng
compare_captures = pair_pcapng


class ForensicPairer(object):
    """Small reusable wrapper around the pairing functions."""

    __slots__ = (
        "time_window",
        "min_common_prefix",
        "require_complete_side",
        "allow_identical_partial_pairing",
    )

    def __init__(
        self,
        max_time_delta=None,
        *,
        time_tolerance=None,
        time_window=None,
        min_common_prefix=1,
        require_complete_side=False,
        allow_identical_partial_pairing=False
    ):
        self.time_window = _resolve_time_window(
            time_window, max_time_delta, time_tolerance
        )
        _require_int("min_common_prefix", min_common_prefix, 0)
        if not isinstance(require_complete_side, bool):
            raise PairingInputError("require_complete_side must be a boolean")
        if not isinstance(allow_identical_partial_pairing, bool):
            raise PairingInputError(
                "allow_identical_partial_pairing must be a boolean"
            )
        self.min_common_prefix = min_common_prefix
        self.require_complete_side = require_complete_side
        self.allow_identical_partial_pairing = allow_identical_partial_pairing

    def pair(self, left, right, **kwargs):
        kwargs["time_window"] = self.time_window
        kwargs["min_common_prefix"] = self.min_common_prefix
        kwargs["require_complete_side"] = self.require_complete_side
        kwargs["allow_identical_partial_pairing"] = (
            self.allow_identical_partial_pairing
        )
        return pair_observations(left, right, **kwargs)

    def pair_captures(self, left, right, **kwargs):
        kwargs["time_window"] = self.time_window
        kwargs["min_common_prefix"] = self.min_common_prefix
        kwargs["require_complete_side"] = self.require_complete_side
        kwargs["allow_identical_partial_pairing"] = (
            self.allow_identical_partial_pairing
        )
        return pair_pcapng(left, right, **kwargs)
