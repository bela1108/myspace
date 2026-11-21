"""
Read-only forensic pairing of packet observations from two capture points.

This module never writes to a capture.  It loads packet observations from
pcapng files (Enhanced Packet Blocks and the obsolete Packet Block, both
read-only through :class:`pcapng.FileScanner`), groups them by the direction
declared by the caller and compares them on the basis of the *evidence*
present in the captures themselves:

* two observations are only considered compatible when their payloads share
  an evidence-supported common prefix (a prefix that is fully present on
  *both* sides);
* a match is only confirmed (``pair``) when the compatibility is unique and
  any length difference is explained by truncation declared in the capture
  metadata (``captured_len < packet_len``);
* many-to-one candidates, duplicate prefixes and payloads that diverge are
  always left ``undecided`` -- identical packet headers can never by
  themselves justify a pairing.
"""

import enum

from pcapng import FileScanner
from pcapng.blocks import BasePacketBlock, EnhancedPacket, ObsoletePacket
from pcapng.constants.link_types import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    LINKTYPE_NULL,
)


class Direction(enum.Enum):
    """Traffic direction as declared by the caller for a capture source."""

    A_TO_B = "a_to_b"
    B_TO_A = "b_to_a"
    EITHER = "either"


class PairStatus(enum.Enum):
    """Label for the two possible outcomes of a comparison.

    Confirmed outcomes appear in :attr:`PairingReport.pairs`; everything
    else is retained in :attr:`PairingReport.undecided` with an
    :class:`UndecidedReason`, never silently dropped or force-paired.
    """

    PAIRED = "paired"
    UNDECIDED = "undecided"


class UndecidedReason(enum.Enum):
    """Why an observation (or candidate group) could not be confirmed."""

    DUPLICATE_PREFIX = "duplicate_prefix"
    MULTIPLE_CANDIDATES = "multiple_candidates"
    PAYLOAD_DIVERGENCE = "payload_divergence"
    NO_CANDIDATE = "no_candidate"
    DIRECTION_MISMATCH = "direction_mismatch"
    TRUNCATION_UNEXPLAINED = "truncation_unexplained"


class TruncationSide(enum.Enum):
    """Which side of a pair lost bytes relative to the original frame."""

    LEFT = "left"
    RIGHT = "right"
    BOTH = "both"
    NONE = "none"


class Observation(object):
    """A single packet observation as seen by one capture point.

    :ivar source_label: label of the capture source the packet came from.
    :ivar index: zero-based index of the packet within that source.
    :ivar timestamp: packet timestamp in seconds (float).
    :ivar direction: direction resolved for this observation.
    :ivar link_type: interface link type of the capturing interface.
    :ivar interface_id: pcapng interface id the packet was captured on.
    :ivar frame: full captured frame bytes exactly as stored on disk.
    :ivar payload: bytes compared for pairing (frame minus link-layer
        headers).  The frame itself is always retained for the audit trail.
    :ivar captured_len: number of bytes actually captured.
    :ivar original_len: on-the-wire length declared by the capture
        (``packet_len``).  When smaller than ``captured_len`` would allow,
        this is the only evidence that bytes were truncated away.
    :ivar truncated: ``True`` when the capture itself declares truncation.
    """

    __slots__ = (
        "source_label",
        "index",
        "timestamp",
        "direction",
        "link_type",
        "interface_id",
        "frame",
        "payload",
        "captured_len",
        "original_len",
        "truncated",
    )

    def __init__(
        self,
        source_label,
        index,
        timestamp,
        direction,
        link_type,
        interface_id,
        frame,
        payload,
        captured_len,
        original_len,
        truncated,
    ):
        self.source_label = source_label
        self.index = index
        self.timestamp = timestamp
        self.direction = direction
        self.link_type = link_type
        self.interface_id = interface_id
        self.frame = frame
        self.payload = payload
        self.captured_len = captured_len
        self.original_len = original_len
        self.truncated = truncated

    @property
    def ref(self):
        """Stable human-readable reference to this observation."""
        return "{0}#{1}".format(self.source_label, self.index)

    def __repr__(self):
        return (
            "Observation(ref={0!r}, ts={1:.6f}, dir={2!s}, "
            "captured={3}, original={4}, truncated={5})"
        ).format(
            self.ref,
            self.timestamp,
            self.direction.value,
            self.captured_len,
            self.original_len,
            self.truncated,
        )


class PrefixEvidence(object):
    """Byte-level evidence shared by two compatible observations.

    :ivar common_length: length of the byte sequence present, identically,
        on both sides.  This is the only region that can support a pairing.
    :ivar common_prefix: the shared bytes themselves (retained for hashing
        and courtroom-style audit, never truncated or inferred).
    :ivar left_remaining: bytes present on the left side beyond the common
        prefix.
    :ivar right_remaining: bytes present on the right side beyond the
        common prefix.
    :ivar diverges: ``True`` when both sides hold bytes past the common
        prefix and those bytes differ -- the captures disagree about the
        original frame.
    """

    __slots__ = (
        "common_length",
        "common_prefix",
        "left_remaining",
        "right_remaining",
        "diverges",
    )

    def __init__(self, left_payload, right_payload):
        limit = min(len(left_payload), len(right_payload))
        common = 0
        while common < limit and left_payload[common] == right_payload[common]:
            common += 1
        self.common_length = common
        self.common_prefix = left_payload[:common]
        self.left_remaining = left_payload[common:]
        self.right_remaining = right_payload[common:]
        self.diverges = bool(
            self.left_remaining and self.right_remaining
        )

    def __repr__(self):
        return "PrefixEvidence(common={0}, diverges={1})".format(
            self.common_length, self.diverges
        )


class Pairing(object):
    """A confirmed one-to-one pairing between two observations.

    :ivar left: observation from the left capture source.
    :ivar right: observation from the right capture source.
    :ivar evidence: :class:`PrefixEvidence` backing the pairing.
    :ivar time_delta: signed timestamp difference in seconds.
    :ivar truncation_side: where bytes were lost relative to the original
        frame, when the capture metadata proves truncation.
    :ivar truncation_bytes: number of bytes declared missing, keyed by
        side; zero when a side is not truncated.
    """

    __slots__ = (
        "left",
        "right",
        "evidence",
        "time_delta",
        "truncation_side",
        "truncation_bytes",
    )

    def __init__(self, left, right, evidence, time_delta, truncation_side,
                 truncation_bytes):
        self.left = left
        self.right = right
        self.evidence = evidence
        self.time_delta = time_delta
        self.truncation_side = truncation_side
        self.truncation_bytes = truncation_bytes

    def __repr__(self):
        return "Pairing({0} <-> {1}, common={2}, truncation={3!s})".format(
            self.left.ref,
            self.right.ref,
            self.evidence.common_length,
            self.truncation_side.value,
        )


class UndecidedRecord(object):
    """Evidence that was deliberately *not* turned into a confirmed pair.

    :ivar observation: the observation the record concerns.
    :ivar reason: :class:`UndecidedReason`.
    :ivar candidates: other observations sharing an evidence-supported
        common prefix with it (possibly several), each paired with the
        :class:`PrefixEvidence`.
    :ivar detail: human-readable explanation for the audit trail.
    """

    __slots__ = ("observation", "reason", "candidates", "detail")

    def __init__(self, observation, reason, candidates, detail):
        self.observation = observation
        self.reason = reason
        self.candidates = candidates
        self.detail = detail

    def __repr__(self):
        return "UndecidedRecord({0!r}, reason={1!s})".format(
            self.observation.ref, self.reason.value
        )


class PairingReport(object):
    """Full result of a two-source pairing run."""

    __slots__ = ("pairs", "undecided", "left_source", "right_source",
                 "time_tolerance", "clock_offset")

    def __init__(self, pairs, undecided, left_source, right_source,
                 time_tolerance, clock_offset):
        # ``left_source``/``right_source`` are the caller-given labels;
        # the originating file paths live on each observation.
        self.pairs = pairs
        self.undecided = undecided
        self.left_source = left_source
        self.right_source = right_source
        self.time_tolerance = time_tolerance
        self.clock_offset = clock_offset

    @property
    def paired_refs(self):
        """Set of observation references that were confidently paired."""
        refs = set()
        for pairing in self.pairs:
            refs.add(pairing.left.ref)
            refs.add(pairing.right.ref)
        return refs

    def summary(self):
        """Plain-text, audit-friendly summary of the run."""
        lines = [
            "Forensic pairing report",
            "  sources: {0!r} vs {1!r}".format(
                self.left_source, self.right_source
            ),
            "  time tolerance: {0:.6f}s, clock offset: {1:.6f}s".format(
                self.time_tolerance, self.clock_offset
            ),
            "  confirmed pairs: {0}".format(len(self.pairs)),
            "  undecided observations: {0}".format(len(self.undecided)),
        ]
        for pairing in self.pairs:
            lines.append(
                "  [PAIRED] {0} <-> {1}: {2} common bytes, "
                "left={3}B right={4}B, truncation={5!s} "
                "(missing {6}), dt={7:+.6f}s".format(
                    pairing.left.ref,
                    pairing.right.ref,
                    pairing.evidence.common_length,
                    pairing.left.captured_len,
                    pairing.right.captured_len,
                    pairing.truncation_side.value,
                    pairing.truncation_bytes,
                    pairing.time_delta,
                )
            )
        for record in self.undecided:
            refs = ", ".join(
                "{0} (common={1})".format(obs.ref, evidence.common_length)
                for obs, evidence in record.candidates
            ) or "none"
            lines.append(
                "  [UNDECIDED] {0}: {1!s} -- {2}; candidates: {3}".format(
                    record.observation.ref,
                    record.reason,
                    record.detail,
                    refs,
                )
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Read-only loading
# ---------------------------------------------------------------------------

_ETHERNET_HEADER_LEN = 14
_ETHERTYPE_VLAN = 0x8100
_ETHERTYPE_QINQ = 0x88A8
_NULL_HEADER_LEN = 4


def extract_payload(frame, link_type):
    """Strip link-layer headers from a captured frame.

    Only header removal is performed; no protocol decoding that could
    silently "fix" bytes happens here.  Unsupported link types raise
    :class:`ValueError` so the caller must decide explicitly rather than
    comparing the wrong layers.
    """
    if link_type == LINKTYPE_RAW:
        return bytes(frame)
    if link_type == LINKTYPE_NULL:
        if len(frame) < _NULL_HEADER_LEN:
            raise ValueError("LINKTYPE_NULL frame shorter than 4 bytes")
        return bytes(frame[_NULL_HEADER_LEN:])
    if link_type == LINKTYPE_ETHERNET:
        offset = _ETHERNET_HEADER_LEN
        while len(frame) >= offset + 2:
            ethertype = (frame[offset - 2] << 8) | frame[offset - 1]
            if ethertype in (_ETHERTYPE_VLAN, _ETHERTYPE_QINQ):
                offset += 4
                continue
            break
        if len(frame) < offset:
            raise ValueError("Ethernet frame shorter than its headers")
        return bytes(frame[offset:])
    raise ValueError(
        "unsupported link type {0!r}; pass a payload_extractor to handle it"
        .format(link_type)
    )


def _epb_direction(block):
    """Read the epb_flags in/out field without assuming it is present."""
    options = getattr(block, "options", None)
    if not options:
        return None
    flags = None
    for name, value in options.items():
        if name in ("epb_flags", "pack_flags"):
            flags = value
            break
    if flags is None:
        return None
    label = flags.inout
    if label == "inbound":
        return Direction.B_TO_A
    if label == "outbound":
        return Direction.A_TO_B
    return None


def load_observations(path, source_label, direction, payload_extractor=None):
    """Read packet observations from a pcapng file without writing to it.

    :param path: pcapng file path.
    :param source_label: label used in references and the report.
    :param direction: :class:`Direction` declared by the caller.
        :data:`Direction.EITHER` means the per-packet ``epb_flags``
        in/out field is used when present; packets without a usable flag
        keep ``EITHER`` and can pair with any direction.
    :param payload_extractor: optional callable ``(frame, link_type) ->
        bytes`` overriding :func:`extract_payload`.
    """
    if not isinstance(direction, Direction):
        raise TypeError("direction must be a Direction member")

    observations = []
    packet_index = 0
    with open(path, "rb") as stream:
        scanner = FileScanner(stream)
        for block in scanner:
            if not isinstance(block, BasePacketBlock):
                continue
            if not isinstance(
                block, (EnhancedPacket, ObsoletePacket)
            ):
                # Simple Packet Blocks carry no timestamp and therefore
                # cannot take part in a time-bounded comparison.
                continue

            frame = bytes(block.packet_data)
            link_type = block.interface.link_type
            if payload_extractor is not None:
                payload = bytes(payload_extractor(frame, link_type))
            else:
                payload = extract_payload(frame, link_type)

            captured_len = block.captured_len
            original_len = block.packet_len
            truncated = original_len > captured_len

            if direction is Direction.EITHER:
                observed = _epb_direction(block)
                effective = observed or Direction.EITHER
            else:
                effective = direction

            observations.append(
                Observation(
                    source_label=source_label,
                    index=packet_index,
                    timestamp=float(block.timestamp),
                    direction=effective,
                    link_type=link_type,
                    interface_id=block.interface_id,
                    frame=frame,
                    payload=payload,
                    captured_len=captured_len,
                    original_len=original_len,
                    truncated=truncated,
                )
            )
            packet_index += 1
    return observations


# ---------------------------------------------------------------------------
# Compatibility and pairing engine
# ---------------------------------------------------------------------------


def directions_compatible(left, right):
    """Direction evidence must not contradict.

    A concrete direction on one side must match the other side; ``EITHER``
    simply means "no contradictory evidence".  Packets explicitly observed
    in opposite directions are never paired.
    """
    if left is Direction.EITHER or right is Direction.EITHER:
        return True
    return left is right


def time_compatible(left, right, time_tolerance, clock_offset=0.0):
    """Check the caller-supplied, deliberately limited time condition."""
    delta = (right.timestamp + clock_offset) - left.timestamp
    return abs(delta) <= time_tolerance, delta


def _link_header_len(link_type):
    if link_type == LINKTYPE_ETHERNET:
        return _ETHERNET_HEADER_LEN
    if link_type == LINKTYPE_NULL:
        return _NULL_HEADER_LEN
    # LINKTYPE_RAW and anything the caller extracted manually start at L3.
    return 0


def _explain_truncation(left, right, evidence):
    """Decide whether a length difference is explained by capture metadata.

    Returns a ``(TruncationSide, missing_dict)`` tuple or ``None`` when the
    difference is not supported by truncation evidence.  Truncation is only
    accepted when the shorter capture itself declares
    ``original_len > captured_len``.
    """
    left_extra = len(evidence.left_remaining)
    right_extra = len(evidence.right_remaining)
    missing = {TruncationSide.LEFT: 0, TruncationSide.RIGHT: 0}

    if left_extra == 0 and right_extra == 0:
        return TruncationSide.NONE, missing

    if left_extra and right_extra:
        # Both sides hold differing bytes past the common prefix: no
        # truncation story can reconcile genuinely different payloads.
        return None

    if left_extra:
        # Right side is shorter.  Its capture must declare truncation
        # itself, and declare an original frame long enough to contain
        # every byte the left side actually holds.  Original lengths are
        # compared against payload bytes (link-layer headers differ
        # between taps), hence the per-link-type header length is removed.
        if not right.truncated:
            return None
        if right.original_len - _link_header_len(right.link_type) < len(
            left.payload
        ):
            return None
        missing[TruncationSide.RIGHT] = left_extra
        if left.truncated:
            # Both taps cut the frame; only their common region is visible.
            missing[TruncationSide.LEFT] = (
                left.original_len
                - _link_header_len(left.link_type)
                - len(left.payload)
            )
            return TruncationSide.BOTH, missing
        return TruncationSide.RIGHT, missing

    if not left.truncated:
        return None
    if left.original_len - _link_header_len(left.link_type) < len(
        right.payload
    ):
        return None
    missing[TruncationSide.LEFT] = right_extra
    return TruncationSide.LEFT, missing


def pair_captures(
    left_path,
    right_path,
    direction,
    time_tolerance,
    clock_offset=0.0,
    left_label="left",
    right_label="right",
    payload_extractor=None,
):
    """Pair observations from two pcapng captures, read-only.

    :param left_path: path of the first capture point.
    :param right_path: path of the second capture point.
    :param direction: :class:`Direction` limiting which packets are
        compared.  Both files are loaded with this declared direction (use
        :data:`Direction.EITHER` to honour per-packet ``epb_flags``).
    :param time_tolerance: maximum absolute timestamp difference in
        seconds after applying ``clock_offset``.
    :param clock_offset: constant correction added to right-side
        timestamps before comparison (seconds).
    :returns: :class:`PairingReport`.

    A pair is confirmed only when:

    1. directions do not contradict;
    2. the time condition holds;
    3. the payloads share a non-empty common prefix present on both sides;
    4. exactly one such candidate exists on each side (no multi-mapping,
       no auto-pairing of duplicate prefixes);
    5. any length difference is fully explained by self-declared
       truncation.

    Everything else is reported as undecided with the supporting evidence.
    """
    if time_tolerance < 0:
        raise ValueError("time_tolerance must be non-negative")

    left_obs = load_observations(
        left_path, left_label, direction, payload_extractor
    )
    right_obs = load_observations(
        right_path, right_label, direction, payload_extractor
    )
    return _pair_observations(
        left_obs,
        right_obs,
        time_tolerance,
        clock_offset,
        left_label,
        right_label,
    )


def _pair_observations(left_obs, right_obs, time_tolerance, clock_offset,
                       left_label, right_label):
    # Build the full candidate graph first; every edge carries its own
    # byte-level evidence so nothing is decided on headers alone.
    left_edges = {obs: [] for obs in left_obs}
    right_edges = {obs: [] for obs in right_obs}

    direction_mismatch_refs = set()
    for left in left_obs:
        for right in right_obs:
            if not directions_compatible(left.direction, right.direction):
                if abs((right.timestamp + clock_offset) - left.timestamp) \
                        <= time_tolerance:
                    direction_mismatch_refs.add(left.ref)
                continue
            ok, delta = time_compatible(
                left, right, time_tolerance, clock_offset
            )
            if not ok:
                continue
            if not left.payload or not right.payload:
                continue
            evidence = PrefixEvidence(left.payload, right.payload)
            if evidence.common_length == 0:
                continue
            truncation = _explain_truncation(left, right, evidence)
            left_edges[left].append(
                (right, evidence, delta, truncation)
            )
            right_edges[right].append(
                (left, evidence, delta, truncation)
            )

    pairs = []
    undecided = []
    paired_refs = set()

    # Confirm only unique, mutually-singleton, truncation-consistent edges.
    for left in left_obs:
        edges = left_edges[left]
        if not edges and left.ref in direction_mismatch_refs:
            undecided.append(
                UndecidedRecord(
                    left,
                    UndecidedReason.DIRECTION_MISMATCH,
                    [],
                    "time-compatible observations exist but their "
                    "epb_flags/caller direction contradicts",
                )
            )
            continue
        if not edges:
            undecided.append(
                UndecidedRecord(
                    left,
                    UndecidedReason.NO_CANDIDATE,
                    [],
                    "no right-side observation shares a common prefix "
                    "within the time/direction conditions",
                )
            )
            continue

        diverging = [edge for edge in edges if edge[1].diverges]
        if diverging:
            undecided.append(
                UndecidedRecord(
                    left,
                    UndecidedReason.PAYLOAD_DIVERGENCE,
                    [(obs, evidence) for obs, evidence, _, _ in diverging],
                    "candidate payloads differ after the common prefix; "
                    "headers/prefix alone cannot identify the same "
                    "original frame",
                )
            )
            continue

        if len(edges) > 1:
            # Divergence was handled above, so every remaining edge is a
            # strict prefix relationship: the captures genuinely cannot
            # tell same-prefix frames apart -- the duplicate-prefix trap.
            undecided.append(
                UndecidedRecord(
                    left,
                    UndecidedReason.DUPLICATE_PREFIX,
                    [(obs, evidence) for obs, evidence, _, _ in edges],
                    "{0} candidates share an evidence-supported prefix; "
                    "duplicate prefixes are never auto-paired".format(
                        len(edges)
                    ),
                )
            )
            continue

        right, evidence, delta, truncation = edges[0]

        if len(right_edges[right]) > 1:
            undecided.append(
                UndecidedRecord(
                    left,
                    UndecidedReason.DUPLICATE_PREFIX,
                    [(other, ev)
                     for other, ev, _, _ in right_edges[right]],
                    "right-side observation has {0} left-side prefix "
                    "matches; duplicate prefixes are not auto-paired"
                    .format(len(right_edges[right])),
                )
            )
            continue

        if truncation is None:
            undecided.append(
                UndecidedRecord(
                    left,
                    UndecidedReason.TRUNCATION_UNEXPLAINED,
                    [(right, evidence)],
                    "length difference is not backed by self-declared "
                    "truncation (captured_len < packet_len)",
                )
            )
            continue

        truncation_side, missing = truncation
        pairs.append(
            Pairing(left, right, evidence, delta, truncation_side, missing)
        )
        paired_refs.add(left.ref)
        paired_refs.add(right.ref)

    # Right-side observations never referenced by a confirmed pair still
    # need an explicit undecided trail (duplicate-prefix victims, etc.).
    left_records = {
        record.observation.ref: record for record in undecided
    }
    for right in right_obs:
        if right.ref in paired_refs:
            continue
        edges = right_edges[right]
        if not edges:
            undecided.append(
                UndecidedRecord(
                    right,
                    UndecidedReason.NO_CANDIDATE,
                    [],
                    "no left-side observation shares a common prefix "
                    "within the time/direction conditions",
                )
            )
            continue

        if any(edge[1].diverges for edge in edges):
            reason = UndecidedReason.PAYLOAD_DIVERGENCE
            detail = "candidate payloads diverge after the common prefix"
        elif all(not edge[1].diverges for edge in edges) and (
            len(edges) > 1
            or any(
                left_records.get(obs.ref) is not None
                and left_records[obs.ref].reason
                is UndecidedReason.DUPLICATE_PREFIX
                for obs, _, _, _ in edges
            )
        ):
            reason = UndecidedReason.DUPLICATE_PREFIX
            detail = (
                "shares an evidence-supported prefix with more than one "
                "frame; duplicate prefixes are never auto-paired"
            )
        else:
            reason = UndecidedReason.MULTIPLE_CANDIDATES
            detail = "only participates in non-unique or rejected edges"
        undecided.append(
            UndecidedRecord(
                right,
                reason,
                [(obs, evidence) for obs, evidence, _, _ in edges],
                detail,
            )
        )

    return PairingReport(
        pairs=pairs,
        undecided=undecided,
        left_source=left_label,
        right_source=right_label,
        time_tolerance=time_tolerance,
        clock_offset=clock_offset,
    )
