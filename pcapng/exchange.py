"""Preflight checks for exchanging pcapng files with partial readers.

The scanner in :mod:`pcapng.scanner` deliberately tolerates unknown blocks.
That is the right behaviour for a general-purpose reader, but it is not enough
to decide whether an evidence archive may be handed to a reader that only
understands a subset of the format.  This module keeps the raw block bytes,
checks the receiver's capability manifest, and applies an explicit local
discard policy before producing any output.

Unknown local/private blocks can normally be skipped.  Packet and mandatory
structural blocks cannot be skipped merely because a reader managed to walk
past them.  If a policy permits dropping evidence-bearing blocks, the output
may still be exchanged, but the loss and its interface scope are reported
separately.
"""

from __future__ import absolute_import

import os
import struct
from collections import OrderedDict

from pcapng.constants.block_types import (
    BLK_ARINC429,
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_INTERFACE_STATS,
    BLK_IRIG_TIMESTAMP,
    BLK_NAME_RESOLUTION,
    BLK_PACKET,
    BLK_PACKET_SIMPLE,
    BLK_RESERVED,
    BLK_SECTION_HEADER,
)
from pcapng.exceptions import PcapngException, PcapngLoadError


MANDATORY_BLOCK_TYPES = frozenset((BLK_SECTION_HEADER, BLK_INTERFACE))
PACKET_BLOCK_TYPES = frozenset((BLK_PACKET, BLK_PACKET_SIMPLE, BLK_ENHANCED_PACKET))
AUXILIARY_BLOCK_TYPES = frozenset((BLK_NAME_RESOLUTION, BLK_INTERFACE_STATS))
EVIDENCE_BLOCK_TYPES = PACKET_BLOCK_TYPES.union(
    AUXILIARY_BLOCK_TYPES, (BLK_IRIG_TIMESTAMP, BLK_ARINC429)
)
STANDARD_BLOCK_TYPES = MANDATORY_BLOCK_TYPES.union(
    PACKET_BLOCK_TYPES,
    AUXILIARY_BLOCK_TYPES,
    (BLK_IRIG_TIMESTAMP, BLK_ARINC429),
)

ACTION_KEEP = "keep"
ACTION_SKIP = "skip"
ACTION_DROP = "drop"
ACTION_REJECT = "reject"

DECISION_ACCEPT = "accept"
DECISION_ACCEPT_WITH_LOSS = "accept-with-evidence-loss"
DECISION_REJECT = "reject"

BLOCK_NAMES = {
    BLK_SECTION_HEADER: "SectionHeader",
    BLK_INTERFACE: "InterfaceDescription",
    BLK_PACKET: "Packet",
    BLK_PACKET_SIMPLE: "SimplePacket",
    BLK_NAME_RESOLUTION: "NameResolution",
    BLK_INTERFACE_STATS: "InterfaceStatistics",
    BLK_ENHANCED_PACKET: "EnhancedPacket",
    BLK_IRIG_TIMESTAMP: "IRIGTimestamp",
    BLK_ARINC429: "ARINC429",
}

_BLOCK_TYPE_ALIASES = {
    "SHB": BLK_SECTION_HEADER,
    "SECTIONHEADER": BLK_SECTION_HEADER,
    "SECTION_HEADER": BLK_SECTION_HEADER,
    "SECTIONHEADERBLOCK": BLK_SECTION_HEADER,
    "IDB": BLK_INTERFACE,
    "INTERFACEDESCRIPTION": BLK_INTERFACE,
    "INTERFACE_DESCRIPTION": BLK_INTERFACE,
    "INTERFACEDESCRIPTIONBLOCK": BLK_INTERFACE,
    "INTERFACE": BLK_INTERFACE,
    "PB": BLK_PACKET,
    "PACKET": BLK_PACKET,
    "PACKETBLOCK": BLK_PACKET,
    "SPB": BLK_PACKET_SIMPLE,
    "SIMPLEPACKET": BLK_PACKET_SIMPLE,
    "SIMPLE_PACKET": BLK_PACKET_SIMPLE,
    "SIMPLEPACKETBLOCK": BLK_PACKET_SIMPLE,
    "NRB": BLK_NAME_RESOLUTION,
    "NAMERESOLUTION": BLK_NAME_RESOLUTION,
    "NAME_RESOLUTION": BLK_NAME_RESOLUTION,
    "NAMERESOLUTIONBLOCK": BLK_NAME_RESOLUTION,
    "ISB": BLK_INTERFACE_STATS,
    "INTERFACESTATISTICS": BLK_INTERFACE_STATS,
    "INTERFACE_STATISTICS": BLK_INTERFACE_STATS,
    "INTERFACESTATISTICSBLOCK": BLK_INTERFACE_STATS,
    "EPB": BLK_ENHANCED_PACKET,
    "ENHANCEDPACKET": BLK_ENHANCED_PACKET,
    "ENHANCED_PACKET": BLK_ENHANCED_PACKET,
    "ENHANCEDPACKETBLOCK": BLK_ENHANCED_PACKET,
    "ENHANCED_PACKET_BLOCK": BLK_ENHANCED_PACKET,
    "IRIG": BLK_IRIG_TIMESTAMP,
    "IRIGTIMESTAMP": BLK_IRIG_TIMESTAMP,
    "IRIG_TIMESTAMP": BLK_IRIG_TIMESTAMP,
    "IRIGTIMESTAMPBLOCK": BLK_IRIG_TIMESTAMP,
    "ARINC429": BLK_ARINC429,
    "ARINC429BLOCK": BLK_ARINC429,
}


class ExchangeError(PcapngException):
    """Raised when an exchange report cannot produce an accepted output."""

    pass


def normalize_block_type(value):
    """Return a numeric pcapng block type.

    Numeric values and the common short names (``SHB``, ``IDB``, ``EPB``,
    etc.) are accepted.  This keeps manifests readable in configuration
    files while still allowing raw type codes.
    """

    if isinstance(value, bool):
        raise ValueError("block type must not be a bool")
    if isinstance(value, int):
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError("block type out of 32-bit range: {!r}".format(value))
        return value
    if hasattr(value, "magic_number"):
        return normalize_block_type(value.magic_number)
    if not isinstance(value, str):
        raise TypeError(
            "block type must be an int, block class, or string, got {!r}".format(value)
        )

    text = value.strip()
    if not text:
        raise ValueError("empty block type")
    try:
        number = int(text, 0)
    except ValueError:
        try:
            number = int(text, 10)
        except ValueError:
            number = None
    if number is not None:
        return normalize_block_type(number)

    key = text.upper().replace("-", "_").replace(" ", "_").replace(".", "_")
    if key.startswith("BLK_"):
        key = key[4:]
    compact_key = "".join(character for character in key if character.isalnum())
    try:
        return _BLOCK_TYPE_ALIASES[key]
    except KeyError:
        try:
            return _BLOCK_TYPE_ALIASES[compact_key]
        except KeyError:
            raise ValueError("unknown block type name: {!r}".format(value))


def _normalize_block_types(values):
    if values is None:
        return frozenset()
    if isinstance(values, (int, str)):
        values = (values,)
    return frozenset(normalize_block_type(value) for value in values)


def _get_first(mapping, names, default=None):
    if hasattr(mapping, "get"):
        for name in names:
            if name in mapping:
                return mapping[name]
    else:
        for name in names:
            if hasattr(mapping, name):
                return getattr(mapping, name)
    return default


class ReceiverCapabilities(object):
    """Capabilities advertised by one downstream pcapng reader.

    :param block_types:
        Iterable of block types the receiver can interpret.  Values may be
        integers, hexadecimal strings, or names such as ``"SHB"`` and
        ``"EPB"``.
    :param allow_unknown_blocks:
        Whether the receiver follows the pcapng rule that unknown blocks may
        be skipped.  This only permits blocks that are safe to skip; it never
        permits silently skipping packet or mandatory structural blocks.
    :param require_interface_description:
        Whether each section must contain an IDB before packet/statistics
        blocks can be interpreted.  Defaults to ``True``.
    :param name:
        Optional human-readable receiver name used in reports.
    """

    __slots__ = [
        "block_types",
        "allow_unknown_blocks",
        "require_interface_description",
        "name",
    ]

    def __init__(
        self,
        block_types,
        allow_unknown_blocks=True,
        require_interface_description=True,
        name=None,
    ):
        self.block_types = _normalize_block_types(block_types)
        self.allow_unknown_blocks = bool(allow_unknown_blocks)
        self.require_interface_description = bool(require_interface_description)
        self.name = name

    @classmethod
    def from_manifest(cls, manifest):
        """Build capabilities from a dict-like configuration manifest."""

        if isinstance(manifest, cls):
            return manifest
        has_block_attribute = any(
            hasattr(manifest, attribute)
            for attribute in (
                "block_types",
                "supported_block_types",
                "supported_blocks",
            )
        )
        if has_block_attribute:
            block_types = _get_first(
                manifest,
                ("block_types", "supported_block_types", "supported_blocks"),
                (),
            )
            return cls(
                block_types,
                allow_unknown_blocks=_get_first(
                    manifest,
                    ("allow_unknown_blocks", "allow_unknown", "skip_unknown_blocks"),
                    True,
                ),
                require_interface_description=getattr(
                    manifest, "require_interface_description", True
                ),
                name=getattr(manifest, "name", None),
            )
        if not hasattr(manifest, "get"):
            return cls(manifest)

        block_types = _get_first(
            manifest,
            (
                "block_types",
                "supported_block_types",
                "supported_blocks",
                "blocks",
                "supports",
            ),
            (),
        )
        allow_unknown = _get_first(
            manifest,
            (
                "allow_unknown_blocks",
                "allow_unknown",
                "skip_unknown_blocks",
                "skip_unknown",
            ),
            True,
        )
        require_idb = _get_first(
            manifest,
            ("require_interface_description", "require_idb"),
            True,
        )
        return cls(
            block_types=block_types,
            allow_unknown_blocks=allow_unknown,
            require_interface_description=require_idb,
            name=_get_first(manifest, ("name", "receiver_name")),
        )

    def supports(self, block_type):
        """Return whether this receiver can interpret ``block_type``."""

        return normalize_block_type(block_type) in self.block_types

    def __contains__(self, block_type):
        return self.supports(block_type)

    def to_dict(self):
        return {
            "name": self.name,
            "block_types": sorted(self.block_types),
            "allow_unknown_blocks": self.allow_unknown_blocks,
            "require_interface_description": self.require_interface_description,
        }

    def __repr__(self):
        return (
            "<ReceiverCapabilities name={0!r} blocks={1!r} allow_unknown_blocks={2!r}>"
        ).format(
            self.name,
            sorted(self.block_types),
            self.allow_unknown_blocks,
        )


class DiscardPolicy(object):
    """Local rules controlling which unsupported blocks may be omitted.

    :param discardable_block_types:
        Block types that may be dropped when the receiver cannot interpret
        them.  Mandatory SHB/IDB blocks can never be dropped.
    :param required_block_types:
        Block types that must be interpreted even if they would otherwise be
        skippable as an extension.
    :param drop_unknown_extensions:
        If true, omit unknown extension blocks instead of leaving them for
        the receiver to skip.  This is useful when the output should contain
        only data understood by the target.
    :param name:
        Optional human-readable policy name.
    """

    __slots__ = [
        "discardable_block_types",
        "required_block_types",
        "drop_unknown_extensions",
        "name",
    ]

    def __init__(
        self,
        discardable_block_types=(),
        required_block_types=(),
        drop_unknown_extensions=False,
        name=None,
    ):
        self.discardable_block_types = _normalize_block_types(discardable_block_types)
        self.required_block_types = _normalize_block_types(required_block_types)
        self.drop_unknown_extensions = bool(drop_unknown_extensions)
        self.name = name

    @classmethod
    def from_rules(cls, rules, name=None, drop_unknown_extensions=False):
        """Build a policy from an iterable or a block-type/action mapping.

        In a mapping, actions ``drop``, ``discard`` and ``omit`` permit
        removal; ``require`` and ``reject`` force the block to be interpreted.
        """

        if rules is None:
            return cls(name=name, drop_unknown_extensions=drop_unknown_extensions)
        if isinstance(rules, cls):
            return rules
        if not hasattr(rules, "items"):
            return cls(
                discardable_block_types=rules,
                name=name,
                drop_unknown_extensions=drop_unknown_extensions,
            )

        discardable = []
        required = []
        for block_type, action in rules.items():
            action_name = str(action).strip().lower().replace("_", "-")
            if action_name in ("drop", "discard", "omit"):
                discardable.append(block_type)
            elif action_name in ("require", "reject", "interpret"):
                required.append(block_type)
            elif action_name not in ("keep", "preserve", "skip"):
                raise ValueError(
                    "unknown discard rule action {!r} for {!r}".format(
                        action, block_type
                    )
                )
        return cls(
            discardable_block_types=discardable,
            required_block_types=required,
            drop_unknown_extensions=drop_unknown_extensions,
            name=name,
        )

    def can_discard(self, block_type):
        return normalize_block_type(block_type) in self.discardable_block_types

    def requires_interpretation(self, block_type):
        return normalize_block_type(block_type) in self.required_block_types

    def to_dict(self):
        return {
            "name": self.name,
            "discardable_block_types": sorted(self.discardable_block_types),
            "required_block_types": sorted(self.required_block_types),
            "drop_unknown_extensions": self.drop_unknown_extensions,
        }

    def __repr__(self):
        return (
            "<DiscardPolicy name={0!r} discardable={1!r} "
            "required={2!r} drop_unknown_extensions={3!r}>"
        ).format(
            self.name,
            sorted(self.discardable_block_types),
            sorted(self.required_block_types),
            self.drop_unknown_extensions,
        )


class BlockRecord(object):
    """One block's disposition in an exchange report."""

    __slots__ = [
        "section",
        "block_index",
        "block_type",
        "block_name",
        "offset",
        "length",
        "endianness",
        "supported",
        "action",
        "reason",
        "interface_id",
        "evidence_bearing",
        "interface_scope",
    ]

    def __init__(
        self,
        section,
        block_index,
        block_type,
        offset,
        length,
        endianness,
        supported,
        action,
        reason,
        interface_id=None,
        evidence_bearing=False,
        interface_scope=None,
    ):
        self.section = section
        self.block_index = block_index
        self.block_type = block_type
        self.block_name = block_name(block_type)
        self.offset = offset
        self.length = length
        self.endianness = endianness
        self.supported = supported
        self.action = action
        self.reason = reason
        self.interface_id = interface_id
        self.evidence_bearing = evidence_bearing
        self.interface_scope = interface_scope

    @property
    def skippable(self):
        return self.action == ACTION_SKIP

    @property
    def required(self):
        return self.action == ACTION_REJECT

    def to_dict(self):
        return OrderedDict(
            (
                ("section", self.section),
                ("block_index", self.block_index),
                ("block_type", self.block_type),
                ("block_type_hex", "0x{0:08X}".format(self.block_type)),
                ("block_name", self.block_name),
                ("offset", self.offset),
                ("length", self.length),
                ("endianness", self.endianness),
                ("supported", self.supported),
                ("action", self.action),
                ("reason", self.reason),
                ("interface_id", self.interface_id),
                ("evidence_bearing", self.evidence_bearing),
                ("interface_scope", self.interface_scope),
            )
        )

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def keys(self):
        return self.to_dict().keys()

    def __repr__(self):
        return (
            "<BlockRecord section={0} block={1} type=0x{2:08X} "
            "action={3!r} interface_id={4!r}>"
        ).format(
            self.section,
            self.block_index,
            self.block_type,
            self.action,
            self.interface_id,
        )


class ExchangeReport(object):
    """Result of :func:`preflight_exchange`."""

    __slots__ = [
        "receiver",
        "policy",
        "blocks",
        "errors",
        "output",
        "readable_again",
        "evidence_loss",
        "affected_interfaces",
        "affected_interface_scopes",
        "interface_impact",
    ]

    def __init__(
        self,
        receiver,
        policy,
        blocks,
        errors,
        output,
        readable_again,
        evidence_loss,
        affected_interfaces,
        affected_interface_scopes,
        interface_impact,
    ):
        self.receiver = receiver
        self.policy = policy
        self.blocks = blocks
        self.errors = list(errors)
        self.output = output
        self.readable_again = bool(readable_again)
        self.evidence_loss = evidence_loss
        self.affected_interfaces = affected_interfaces
        self.affected_interface_scopes = affected_interface_scopes
        self.interface_impact = interface_impact

    @property
    def exchangeable(self):
        return self.decision != DECISION_REJECT

    @property
    def compatible(self):
        return self.exchangeable

    @property
    def can_exchange(self):
        return self.exchangeable

    @property
    def is_exchangeable(self):
        return self.exchangeable

    @property
    def ok(self):
        return self.exchangeable

    @property
    def accepted(self):
        return self.exchangeable

    @property
    def lossless(self):
        return self.exchangeable and not self.evidence_loss

    @property
    def decision(self):
        if self.errors or self.output is None or not self.readable_again:
            return DECISION_REJECT
        if self.evidence_loss:
            return DECISION_ACCEPT_WITH_LOSS
        return DECISION_ACCEPT

    @property
    def kept_blocks(self):
        return [block for block in self.blocks if block.action == ACTION_KEEP]

    @property
    def skippable_extensions(self):
        return [block for block in self.blocks if block.action == ACTION_SKIP]

    @property
    def required_unknown(self):
        return [block for block in self.blocks if block.action == ACTION_REJECT]

    @property
    def unknown_required(self):
        return self.required_unknown

    @property
    def dropped_blocks(self):
        return [block for block in self.blocks if block.action == ACTION_DROP]

    @property
    def missing_evidence_interfaces(self):
        return self.affected_interfaces

    @property
    def evidence_loss_by_interface(self):
        return self.interface_impact

    def __bool__(self):
        return self.exchangeable

    __nonzero__ = __bool__

    def validate(self):
        """Validate ``output`` again against ``receiver``."""

        if self.output is None:
            return ExchangeValidation(
                self.receiver,
                False,
                list(self.errors) or ["output is not available"],
                [],
            )
        return validate_output(self.output, self.receiver)

    def raise_for_errors(self):
        """Raise :class:`ExchangeError` when the exchange was rejected."""

        if self.exchangeable:
            return self
        messages = list(self.errors)
        if not messages:
            messages.append(
                "output is not readable with receiver {!r}".format(self.receiver.name)
            )
        raise ExchangeError("; ".join(messages))

    def to_bytes(self):
        """Return accepted output bytes or raise :class:`ExchangeError`."""

        self.raise_for_errors()
        return self.output

    def write(self, stream):
        """Write accepted output to ``stream`` and return the byte count."""

        data = self.to_bytes()
        stream.write(data)
        return len(data)

    write_to = write

    def to_dict(self):
        return OrderedDict(
            (
                ("receiver", self.receiver.to_dict()),
                ("policy", self.policy.to_dict()),
                ("decision", self.decision),
                ("exchangeable", self.exchangeable),
                ("compatible", self.compatible),
                ("lossless", self.lossless),
                ("readable_again", self.readable_again),
                ("errors", list(self.errors)),
                (
                    "skippable_extensions",
                    [block.to_dict() for block in self.skippable_extensions],
                ),
                (
                    "required_unknown",
                    [block.to_dict() for block in self.required_unknown],
                ),
                (
                    "dropped_blocks",
                    [block.to_dict() for block in self.dropped_blocks],
                ),
                ("evidence_loss", list(self.evidence_loss)),
                ("affected_interfaces", list(self.affected_interfaces)),
                (
                    "affected_interface_scopes",
                    list(self.affected_interface_scopes),
                ),
                ("interface_impact", list(self.interface_impact)),
                ("output_length", None if self.output is None else len(self.output)),
            )
        )

    def __repr__(self):
        return (
            "<ExchangeReport receiver={0!r} decision={1!r} "
            "skippable={2} required_unknown={3} affected_interfaces={4!r}>"
        ).format(
            self.receiver.name,
            self.decision,
            len(self.skippable_extensions),
            len(self.required_unknown),
            self.affected_interfaces,
        )


class ExchangeValidation(object):
    """Result of validating bytes against a receiver manifest."""

    __slots__ = ["receiver", "ok", "errors", "blocks"]

    def __init__(self, receiver, ok, errors, blocks):
        self.receiver = receiver
        self.ok = bool(ok)
        self.errors = list(errors)
        self.blocks = blocks

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__

    def raise_for_errors(self):
        if not self.ok:
            raise ExchangeError("; ".join(self.errors))
        return self

    def to_dict(self):
        return OrderedDict(
            (
                ("receiver", self.receiver.to_dict()),
                ("ok", self.ok),
                ("errors", list(self.errors)),
                ("block_count", len(self.blocks)),
            )
        )


class _Section(object):
    __slots__ = ["index", "endianness", "offset", "interfaces"]

    def __init__(self, index, endianness, offset):
        self.index = index
        self.endianness = endianness
        self.offset = offset
        self.interfaces = []


class _RawBlock(object):
    __slots__ = [
        "section",
        "block_index",
        "block_type",
        "offset",
        "length",
        "endianness",
        "payload",
        "raw",
        "interface_id",
    ]

    def __init__(
        self,
        section,
        block_index,
        block_type,
        offset,
        length,
        endianness,
        payload,
        raw,
        interface_id=None,
    ):
        self.section = section
        self.block_index = block_index
        self.block_type = block_type
        self.offset = offset
        self.length = length
        self.endianness = endianness
        self.payload = payload
        self.raw = raw
        self.interface_id = interface_id


class _ParsedInput(object):
    __slots__ = ["blocks", "sections", "errors"]

    def __init__(self, blocks, sections, errors):
        self.blocks = blocks
        self.sections = sections
        self.errors = errors


def block_name(block_type):
    """Return a stable display name for a block type."""

    block_type = normalize_block_type(block_type)
    return BLOCK_NAMES.get(block_type, "UnknownBlock")


def _is_extension_block(block_type):
    return block_type not in STANDARD_BLOCK_TYPES


def _is_safe_to_skip(block_type):
    if block_type in AUXILIARY_BLOCK_TYPES:
        return True
    if _is_extension_block(block_type):
        return True
    return False


def _read_source(source):
    if isinstance(source, bytes):
        return source
    if isinstance(source, (bytearray, memoryview)):
        return bytes(source)
    if hasattr(source, "read"):
        data = source.read()
        if isinstance(data, str):
            raise TypeError("pcapng source must be opened in binary mode")
        return bytes(data)
    path_types = (str,) + tuple(
        item for item in (getattr(os, "PathLike", None),) if item is not None
    )
    if isinstance(source, path_types):
        with open(source, "rb") as source_file:
            return source_file.read()
    raise TypeError("source must be bytes, a binary stream, or a filesystem path")


def _check_block_length(data, offset, length, endianness):
    if length < 12:
        raise PcapngLoadError(
            "block at offset {} has invalid length {}".format(offset, length)
        )
    if length % 4:
        raise PcapngLoadError(
            "block at offset {} has unaligned length {}".format(offset, length)
        )
    if offset + length > len(data):
        raise PcapngLoadError(
            "block at offset {} is truncated: {} bytes declared, {} available".format(
                offset, length, len(data) - offset
            )
        )
    trailing_length = struct.unpack(
        endianness + "I", data[offset + length - 4 : offset + length]
    )[0]
    if trailing_length != length:
        raise PcapngLoadError(
            "block at offset {} has mismatching lengths: {} and {}".format(
                offset, length, trailing_length
            )
        )


def _parse_raw_blocks(data):
    blocks = []
    sections = []
    errors = []
    offset = 0
    section = None
    block_index = 0

    if not data:
        return _ParsedInput(
            blocks,
            sections,
            ["input is empty; a Section Header Block is required"],
        )

    try:
        while offset < len(data):
            remaining = len(data) - offset
            if remaining < 12:
                raise PcapngLoadError(
                    "{} trailing bytes at offset {} do not form a block".format(
                        remaining, offset
                    )
                )

            is_shb = data[offset : offset + 4] == b"\x0a\x0d\x0d\x0a"
            if is_shb:
                if remaining < 12:
                    raise PcapngLoadError(
                        "truncated Section Header Block at offset {}".format(offset)
                    )
                bom = data[offset + 8 : offset + 12]
                if bom == b"\x1a\x2b\x3c\x4d":
                    endianness = ">"
                elif bom == b"\x4d\x3c\x2b\x1a":
                    endianness = "<"
                else:
                    raise PcapngLoadError(
                        "invalid byte-order magic at offset {}".format(offset)
                    )
                length = struct.unpack(endianness + "I", data[offset + 4 : offset + 8])[
                    0
                ]
                _check_block_length(data, offset, length, endianness)
                raw = data[offset : offset + length]
                payload = raw[8:-4]
                section = _Section(len(sections), endianness, offset)
                sections.append(section)
                blocks.append(
                    _RawBlock(
                        section=section.index,
                        block_index=block_index,
                        block_type=BLK_SECTION_HEADER,
                        offset=offset,
                        length=length,
                        endianness=endianness,
                        payload=payload,
                        raw=raw,
                    )
                )
                offset += length
                block_index += 1
                continue

            if section is None:
                raise PcapngLoadError("file does not start with a Section Header Block")

            block_type = struct.unpack(
                section.endianness + "I", data[offset : offset + 4]
            )[0]
            if block_type == BLK_RESERVED:
                raise PcapngLoadError(
                    "block type 0x00000000 is reserved for corruption detection"
                )

            length = struct.unpack(
                section.endianness + "I", data[offset + 4 : offset + 8]
            )[0]
            _check_block_length(data, offset, length, section.endianness)
            raw = data[offset : offset + length]
            payload = raw[8:-4]
            interface_id = _interface_id_from_payload(
                block_type, payload, section.endianness
            )

            if block_type == BLK_INTERFACE:
                interface_id = len(section.interfaces)
                section.interfaces.append(interface_id)

            blocks.append(
                _RawBlock(
                    section=section.index,
                    block_index=block_index,
                    block_type=block_type,
                    offset=offset,
                    length=length,
                    endianness=section.endianness,
                    payload=payload,
                    raw=raw,
                    interface_id=interface_id,
                )
            )
            offset += length
            block_index += 1
    except (PcapngLoadError, struct.error) as error:
        errors.append(str(error))

    if not sections:
        errors.append("file does not contain a Section Header Block")

    return _ParsedInput(blocks, sections, errors)


def _interface_id_from_payload(block_type, payload, endianness):
    if block_type in (BLK_ENHANCED_PACKET, BLK_INTERFACE_STATS):
        if len(payload) < 4:
            return None
        return struct.unpack(endianness + "I", payload[:4])[0]
    if block_type == BLK_PACKET:
        if len(payload) < 2:
            return None
        return struct.unpack(endianness + "H", payload[:2])[0]
    if block_type == BLK_PACKET_SIMPLE:
        return 0
    return None


def _section_interfaces(parsed_input, section):
    for item in parsed_input.sections:
        if item.index == section:
            return list(item.interfaces)
    return []


def _scope_for_block(parsed_input, block):
    interfaces = _section_interfaces(parsed_input, block.section)
    if block.block_type in PACKET_BLOCK_TYPES:
        interface_id = block.interface_id
        if block.block_type == BLK_PACKET_SIMPLE and interface_id is None:
            interface_id = 0
        return {
            "kind": "packet",
            "interfaces": [interface_id] if interface_id is not None else [],
            "section_scope": False,
        }
    if block.block_type == BLK_INTERFACE_STATS:
        return {
            "kind": "statistics",
            "interfaces": [block.interface_id]
            if block.interface_id is not None
            else [],
            "section_scope": False,
        }
    if block.block_type == BLK_NAME_RESOLUTION:
        return {
            "kind": "name-resolution",
            "interfaces": interfaces,
            "section_scope": True,
        }
    if block.block_type == BLK_IRIG_TIMESTAMP:
        return {
            "kind": "timestamp",
            "interfaces": interfaces,
            "section_scope": True,
        }
    if block.block_type == BLK_ARINC429:
        return {
            "kind": "arinc429",
            "interfaces": interfaces,
            "section_scope": True,
        }
    return {
        "kind": "unknown",
        "interfaces": [],
        "section_scope": True,
    }


def _evidence_loss_for(parsed_input, block, action, reason):
    scope = _scope_for_block(parsed_input, block)
    interface_ids = scope["interfaces"]
    losses = []
    if interface_ids:
        for interface_id in interface_ids:
            losses.append(
                {
                    "section": block.section,
                    "interface_id": interface_id,
                    "block_type": block.block_type,
                    "block_name": block_name(block.block_type),
                    "offset": block.offset,
                    "action": action,
                    "kind": scope["kind"],
                    "scope": "interface",
                    "reason": reason,
                }
            )
    else:
        losses.append(
            {
                "section": block.section,
                "interface_id": None,
                "block_type": block.block_type,
                "block_name": block_name(block.block_type),
                "offset": block.offset,
                "action": action,
                "kind": scope["kind"],
                "scope": "section",
                "reason": reason,
            }
        )
    return losses


def _aggregate_interface_impact(evidence_loss):
    impact = OrderedDict()
    for item in evidence_loss:
        key = (item["section"], item["interface_id"])
        if key not in impact:
            impact[key] = {
                "section": item["section"],
                "interface_id": item["interface_id"],
                "block_types": [],
                "block_names": [],
                "kinds": [],
                "evidence_count": 0,
            }
        entry = impact[key]
        if item["block_type"] not in entry["block_types"]:
            entry["block_types"].append(item["block_type"])
        if item["block_name"] not in entry["block_names"]:
            entry["block_names"].append(item["block_name"])
        if item["kind"] not in entry["kinds"]:
            entry["kinds"].append(item["kind"])
        entry["evidence_count"] += 1
    return list(impact.values())


def _interface_scope_tuples(evidence_loss):
    seen = set()
    scopes = []
    for item in evidence_loss:
        key = (item["section"], item["interface_id"])
        if key in seen:
            continue
        seen.add(key)
        scopes.append(
            {
                "section": item["section"],
                "interface_id": item["interface_id"],
            }
        )
    return scopes


def _coerce_receiver(receiver):
    if isinstance(receiver, ReceiverCapabilities):
        return receiver
    return ReceiverCapabilities.from_manifest(receiver)


def _coerce_policy(policy):
    if policy is None:
        return DiscardPolicy()
    if isinstance(policy, DiscardPolicy):
        return policy
    if hasattr(policy, "discardable_block_types"):
        return DiscardPolicy(
            discardable_block_types=policy.discardable_block_types,
            required_block_types=getattr(policy, "required_block_types", ()),
            drop_unknown_extensions=getattr(policy, "drop_unknown_extensions", False),
            name=getattr(policy, "name", None),
        )
    return DiscardPolicy.from_rules(policy)


def validate_output(source, receiver):
    """Validate pcapng bytes against a receiver capability manifest.

    A successful validation means every block is either understood by the
    receiver or explicitly permitted to be skipped as an unknown auxiliary or
    extension block.  It does not claim that skipped blocks are lossless.
    """

    capabilities = _coerce_receiver(receiver)
    data = _read_source(source)
    parsed = _parse_raw_blocks(data)
    errors = list(parsed.errors)
    blocks = []

    for raw_block in parsed.blocks:
        supported = capabilities.supports(raw_block.block_type)
        skippable = capabilities.allow_unknown_blocks and _is_safe_to_skip(
            raw_block.block_type
        )
        if not supported and not skippable:
            errors.append(
                "block 0x{0:08X} ({1}) in section {2} is not supported by "
                "receiver {3!r} and is not safely skippable".format(
                    raw_block.block_type,
                    block_name(raw_block.block_type),
                    raw_block.section,
                    capabilities.name,
                )
            )
        blocks.append(
            {
                "section": raw_block.section,
                "block_type": raw_block.block_type,
                "block_name": block_name(raw_block.block_type),
                "supported": supported,
                "skipped": not supported and skippable,
            }
        )

    for section in parsed.sections:
        if (
            capabilities.require_interface_description
            and not section.interfaces
            and any(
                block.section == section.index
                and block.block_type in PACKET_BLOCK_TYPES
                for block in parsed.blocks
            )
        ):
            errors.append(
                "section {} contains packet blocks but no Interface "
                "Description Block".format(section.index)
            )

    return ExchangeValidation(capabilities, not errors, errors, blocks)


validate_exchange_output = validate_output


def preflight_exchange(source, receiver, discard_policy=None):
    """Check whether ``source`` may be exchanged with ``receiver``.

    The function parses the original blocks without normalising their
    endianness.  Each section therefore keeps its own byte order, including in
    the generated output.

    :param source:
        Raw pcapng bytes, a binary stream, or a path.
    :param receiver:
        A :class:`ReceiverCapabilities` instance or a compatible mapping.
    :param discard_policy:
        A :class:`DiscardPolicy` instance, an iterable of droppable block
        types, or a mapping of block type to action.
    :returns:
        :class:`ExchangeReport`.
    """

    capabilities = _coerce_receiver(receiver)
    policy = _coerce_policy(discard_policy)
    data = _read_source(source)
    parsed = _parse_raw_blocks(data)
    errors = list(parsed.errors)
    records = []
    evidence_loss = []
    output_parts = []

    for raw_block in parsed.blocks:
        supported = capabilities.supports(raw_block.block_type)
        evidence_bearing = raw_block.block_type in EVIDENCE_BLOCK_TYPES
        interface_scope = _scope_for_block(parsed, raw_block)
        reason = ""
        action = ACTION_KEEP

        if supported:
            reason = "block is supported by the receiver"
        elif raw_block.block_type in MANDATORY_BLOCK_TYPES:
            action = ACTION_REJECT
            reason = "mandatory structural block must be interpreted by the receiver"
        elif policy.requires_interpretation(raw_block.block_type):
            action = ACTION_REJECT
            reason = "local policy requires this block to be interpreted"
        elif policy.can_discard(raw_block.block_type):
            action = ACTION_DROP
            reason = "block omitted by local discard policy"
        elif policy.drop_unknown_extensions and _is_extension_block(
            raw_block.block_type
        ):
            action = ACTION_DROP
            reason = "unknown extension omitted by local discard policy"
        elif capabilities.allow_unknown_blocks and _is_safe_to_skip(
            raw_block.block_type
        ):
            action = ACTION_SKIP
            reason = "receiver may skip this unknown block"
        else:
            action = ACTION_REJECT
            reason = (
                "unknown block must be interpreted; the receiver cannot safely skip it"
            )

        record = BlockRecord(
            section=raw_block.section,
            block_index=raw_block.block_index,
            block_type=raw_block.block_type,
            offset=raw_block.offset,
            length=raw_block.length,
            endianness=raw_block.endianness,
            supported=supported,
            action=action,
            reason=reason,
            interface_id=raw_block.interface_id,
            evidence_bearing=evidence_bearing,
            interface_scope=interface_scope,
        )
        records.append(record)

        if action in (ACTION_KEEP, ACTION_SKIP):
            output_parts.append(raw_block.raw)

        if action in (ACTION_SKIP, ACTION_DROP, ACTION_REJECT) and evidence_bearing:
            evidence_loss.extend(_evidence_loss_for(parsed, raw_block, action, reason))

    for section in parsed.sections:
        if not section.interfaces and any(
            block.section == section.index and block.block_type in PACKET_BLOCK_TYPES
            for block in parsed.blocks
        ):
            errors.append(
                "section {} contains packet blocks but no Interface "
                "Description Block".format(section.index)
            )

    rejected = [record for record in records if record.action == ACTION_REJECT]
    for record in rejected:
        errors.append(
            "section {} block 0x{:08X} ({}) at offset {} requires "
            "interpretation: {}".format(
                record.section,
                record.block_type,
                record.block_name,
                record.offset,
                record.reason,
            )
        )

    output = None
    readable_again = False
    if not errors and not rejected:
        output = b"".join(output_parts)
        validation = validate_output(output, capabilities)
        readable_again = validation.ok
        if not validation.ok:
            errors.extend(validation.errors)
            output = None

    if errors:
        output = None
        readable_again = False

    affected_scopes = _interface_scope_tuples(evidence_loss)
    affected_interfaces = sorted(
        {
            item["interface_id"]
            for item in affected_scopes
            if item["interface_id"] is not None
        }
    )
    interface_impact = _aggregate_interface_impact(evidence_loss)

    return ExchangeReport(
        receiver=capabilities,
        policy=policy,
        blocks=records,
        errors=errors,
        output=output,
        readable_again=readable_again,
        evidence_loss=evidence_loss,
        affected_interfaces=affected_interfaces,
        affected_interface_scopes=affected_scopes,
        interface_impact=interface_impact,
    )


def can_exchange(source, receiver, discard_policy=None):
    """Return only the boolean decision from :func:`preflight_exchange`."""

    return preflight_exchange(source, receiver, discard_policy).exchangeable


CapabilityManifest = ReceiverCapabilities
DownstreamCapabilities = ReceiverCapabilities
ReaderCapabilities = ReceiverCapabilities
ExchangeCapabilities = ReceiverCapabilities
LocalDiscardPolicy = DiscardPolicy
DiscardRules = DiscardPolicy
ExchangeAudit = ExchangeReport

audit_exchange = preflight_exchange
check_exchange = preflight_exchange
exchange_preflight = preflight_exchange
prepare_exchange = preflight_exchange
preflight = preflight_exchange


__all__ = [
    "ACTION_DROP",
    "ACTION_KEEP",
    "ACTION_REJECT",
    "ACTION_SKIP",
    "AUXILIARY_BLOCK_TYPES",
    "BLOCK_NAMES",
    "BlockRecord",
    "CapabilityManifest",
    "DECISION_ACCEPT",
    "DECISION_ACCEPT_WITH_LOSS",
    "DECISION_REJECT",
    "DiscardPolicy",
    "DiscardRules",
    "DownstreamCapabilities",
    "EVIDENCE_BLOCK_TYPES",
    "ExchangeAudit",
    "ExchangeCapabilities",
    "ExchangeError",
    "ExchangeReport",
    "ExchangeValidation",
    "LocalDiscardPolicy",
    "MANDATORY_BLOCK_TYPES",
    "PACKET_BLOCK_TYPES",
    "ReaderCapabilities",
    "ReceiverCapabilities",
    "STANDARD_BLOCK_TYPES",
    "audit_exchange",
    "block_name",
    "can_exchange",
    "check_exchange",
    "exchange_preflight",
    "normalize_block_type",
    "preflight",
    "preflight_exchange",
    "prepare_exchange",
    "validate_exchange_output",
    "validate_output",
]
