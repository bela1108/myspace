"""
Read-only sign-off manifest backend for pcapng version verification.

When a capture file is re-exported by a different tool, the raw packet
bytes usually survive untouched while the surrounding descriptions
(interface names, comments, option ordering, ...) may change.  This
module scans a pcapng stream *read-only* and produces a recomputable
electronic manifest ("sign-off sheet") recording, for every packet:

* the capture position (byte offset of the packet block in the stream),
* the actual interface attribution (the resolved identity of the
  interface the packet was captured on, not just the numeric id),
* the subset of options the caller explicitly trusts.

Descriptive material that does not affect attribution (eg. option
ordering, repeated comments) is canonicalized, so reordering it does
not change the manifest digest.  If a key interface description is
missing, the manifest points out the related packets.

The module never writes to the scanned stream; only ``read()`` is used.
"""

import hashlib
import json

from pcapng import blocks
from pcapng.scanner import FileScanner

MANIFEST_FORMAT = "pcapng-signoff-manifest/1"

#: Options trusted by default when the caller does not pass an explicit
#: mapping to :func:`build_manifest`.
DEFAULT_TRUSTED_OPTIONS = {
    "section": (),
    "interface": ("if_name", "if_description"),
    "packet": (),
}

#: Interface options considered "key descriptions": when any of them is
#: missing from an interface, packets captured on it are flagged.
DEFAULT_REQUIRED_INTERFACE_OPTIONS = ("if_name", "if_description")

_PACKET_BLOCK_TYPES = (
    blocks.EnhancedPacket,
    blocks.SimplePacket,
    blocks.ObsoletePacket,
)


class _CountingStream(object):
    """Wrap a stream, tracking how many bytes have been read so far."""

    __slots__ = ["stream", "offset"]

    def __init__(self, stream):
        self.stream = stream
        self.offset = 0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.offset += len(data)
        return data

    def tell(self):
        return self.offset


def _canonical_value(value):
    """Convert a decoded option value into a JSON-stable canonical form."""
    if isinstance(value, (bytes, bytearray)):
        return {"hex": bytes(value).hex()}
    if isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    # Flags objects (eg. EPBFlags) wrap an integer in ``_value``
    if hasattr(value, "_value") and isinstance(value._value, int):
        return value._value
    return {"repr": repr(value)}


def _canonical_options(options, trusted):
    """
    Extract the caller-trusted options as an order-insensitive mapping.

    Options are keyed by their well-known name (or ``opt_<code>`` for
    options without a name in the schema); values are sorted so that
    reordering descriptive material in the file does not change the
    resulting manifest.
    """
    result = {}
    for name in trusted:
        try:
            code = options._resolve_name(name)
        except KeyError:
            continue
        if code not in options.data:
            continue
        alias = options._get_name_alias(code)
        key = alias if isinstance(alias, str) else "opt_{0}".format(code)
        # Sort via the canonical JSON form so multi-value options are
        # insensitive to the order they appeared in the file.
        canonical = sorted(
            json.dumps(_canonical_value(value), sort_keys=True)
            for value in options.data[code]
        )
        result[key] = [json.loads(item) for item in canonical]
    return result


def _digest_json(payload):
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _normalize_trusted(trusted_options):
    trusted = {key: list(value) for key, value in DEFAULT_TRUSTED_OPTIONS.items()}
    if trusted_options:
        for key, value in trusted_options.items():
            if key not in trusted:
                raise ValueError(
                    "unknown trusted-options context: {0!r}".format(key)
                )
            trusted[key] = list(value)
    return trusted


class Manifest(object):
    """
    A recomputable electronic sign-off sheet for a pcapng stream.

    ``content`` holds the manifest payload; :attr:`digest` is derived
    from it deterministically, so anyone can recompute it and compare.
    """

    __slots__ = ["content"]

    def __init__(self, content):
        self.content = content

    @property
    def digest(self):
        return _digest_json(self.content)

    def to_dict(self):
        data = dict(self.content)
        data["digest"] = self.digest
        return data

    def to_json(self, indent=None):
        if indent is None:
            return json.dumps(
                self.to_dict(), sort_keys=True, separators=(",", ":")
            )
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        stored = data.pop("digest", None)
        manifest = cls(data)
        if stored is not None and stored != manifest.digest:
            raise ValueError(
                "manifest digest mismatch: stored {0}, "
                "recomputed {1}".format(stored, manifest.digest)
            )
        return manifest

    @classmethod
    def from_json(cls, text):
        return cls.from_dict(json.loads(text))

    def __eq__(self, other):
        if not isinstance(other, Manifest):
            return NotImplemented
        return self.digest == other.digest

    def __repr__(self):
        return "<Manifest digest={0}>".format(self.digest)


def build_manifest(
    stream,
    trusted_options=None,
    required_interface_options=DEFAULT_REQUIRED_INTERFACE_OPTIONS,
):
    """
    Scan a pcapng stream read-only and build a sign-off manifest.

    :param stream:
        a file-like object; only ``read()`` is ever called on it.
    :param trusted_options:
        optional mapping ``{"section": [...], "interface": [...],
        "packet": [...]}`` naming the options (by name or numeric code)
        the caller explicitly trusts; merged over
        :data:`DEFAULT_TRUSTED_OPTIONS`.  Untrusted options never enter
        the manifest, so changing them does not change the digest.
    :param required_interface_options:
        interface options treated as key descriptions; packets captured
        on an interface missing any of them are flagged in the manifest.
    :return: a :class:`Manifest`.
    """
    trusted = _normalize_trusted(trusted_options)
    required = list(required_interface_options)

    counting = _CountingStream(stream)
    scanner = FileScanner(counting)

    sections = []
    current_section = None
    interfaces_by_id = {}
    packets_missing_context = []
    packet_index = 0

    iterator = iter(scanner)
    while True:
        offset = counting.offset
        try:
            block = next(iterator)
        except StopIteration:
            break

        if isinstance(block, blocks.SectionHeader):
            current_section = {
                "index": len(sections),
                "offset": offset,
                "endianness": block.endianness,
                "version": [block.version_major, block.version_minor],
                "options": _canonical_options(block.options, trusted["section"]),
                "interfaces": [],
                "packets": [],
            }
            sections.append(current_section)
            interfaces_by_id = {}

        elif isinstance(block, blocks.InterfaceDescription):
            missing = [name for name in required if name not in block.options]
            identity = {
                "link_type": block.link_type,
                "options": _canonical_options(block.options, trusted["interface"]),
            }
            entry = {
                "interface_id": block.interface_id,
                "offset": offset,
                "link_type": block.link_type,
                "link_type_description": block.link_type_description,
                "options": identity["options"],
                "missing_descriptions": missing,
                "identity_digest": _digest_json(identity),
            }
            current_section["interfaces"].append(entry)
            interfaces_by_id[block.interface_id] = entry

        elif isinstance(block, _PACKET_BLOCK_TYPES):
            interface_id = block.interface_id
            interface_entry = interfaces_by_id.get(interface_id)
            entry = {
                "index": packet_index,
                "offset": offset,
                "block_type": type(block).__name__,
                "interface_id": interface_id,
                "interface_digest": (
                    interface_entry["identity_digest"] if interface_entry else None
                ),
                "unresolved_interface": interface_entry is None,
                "captured_len": len(block.packet_data),
                "packet_len": block.packet_len,
                "packet_sha256": "sha256:"
                + hashlib.sha256(bytes(block.packet_data)).hexdigest(),
            }
            if any(field[0] == "options" for field in block.schema):
                entry["options"] = _canonical_options(
                    block.options, trusted["packet"]
                )
            if interface_entry is not None and interface_entry[
                "missing_descriptions"
            ]:
                entry["missing_context"] = list(
                    interface_entry["missing_descriptions"]
                )
                packets_missing_context.append(
                    {
                        "section_index": current_section["index"],
                        "packet_index": packet_index,
                        "offset": offset,
                        "interface_id": interface_id,
                        "missing": list(interface_entry["missing_descriptions"]),
                    }
                )
            current_section["packets"].append(entry)
            packet_index += 1

        # Any other block (name resolution, statistics, unknown, ...) is
        # descriptive material that does not affect packet attribution,
        # so it is intentionally left out of the manifest.

    content = {
        "format": MANIFEST_FORMAT,
        "trusted_options": trusted,
        "required_interface_options": required,
        "sections": sections,
        "packets_missing_context": packets_missing_context,
    }
    return Manifest(content)


def _flatten_packets(manifest):
    return [
        packet
        for section in manifest.content["sections"]
        for packet in section["packets"]
    ]


def _ensure_manifest(value):
    if isinstance(value, Manifest):
        return value
    if isinstance(value, dict):
        return Manifest.from_dict(value)
    raise TypeError(
        "expected a Manifest or manifest dict, got {0!r}".format(value)
    )


def compare_manifests(old, new):
    """
    Compare two sign-off manifests and produce a sign-off report.

    The report states whether the two captures may be signed off as the
    same version: identical raw packet bytes but diverging interface
    attribution (or any other trusted content) yields a ``reject``
    verdict, with the affected packets pointed out explicitly.
    """
    old = _ensure_manifest(old)
    new = _ensure_manifest(new)

    old_packets = _flatten_packets(old)
    new_packets = _flatten_packets(new)

    attribution_changes = []
    for old_packet, new_packet in zip(old_packets, new_packets):
        if (
            old_packet["interface_digest"] != new_packet["interface_digest"]
            or old_packet["unresolved_interface"]
            != new_packet["unresolved_interface"]
        ):
            attribution_changes.append(
                {
                    "packet_index": new_packet["index"],
                    "old_offset": old_packet["offset"],
                    "new_offset": new_packet["offset"],
                    "packet_sha256": new_packet["packet_sha256"],
                    "old_interface_digest": old_packet["interface_digest"],
                    "new_interface_digest": new_packet["interface_digest"],
                }
            )

    digests_match = old.digest == new.digest
    return {
        "verdict": "accept" if digests_match else "reject",
        "old_digest": old.digest,
        "new_digest": new.digest,
        "digests_match": digests_match,
        "packet_counts": {"old": len(old_packets), "new": len(new_packets)},
        "raw_packets_identical": [
            packet["packet_sha256"] for packet in old_packets
        ]
        == [packet["packet_sha256"] for packet in new_packets],
        "attribution_changes": attribution_changes,
        "packets_missing_context": new.content["packets_missing_context"],
    }
