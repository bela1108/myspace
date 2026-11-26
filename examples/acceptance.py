# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.cstruct"]
# ///
"""Bit-precise evidence projection of a device acceptance sample.

The status word of the sample carries a safety flag that two review forms interpret differently:

- review form A (status) writes the flag separately, as its own bit field;
- review form B (review) shares the original storage through a union, while an explicit alias
  (status_alias) re-references the same bytes through a manual offset.

The projection preserves every sampled byte exactly once (a single bytes blob) while each
interpretation references it separately through its own (offset, size, bit range) coordinates.
After the baseline projection, two variants are run -- one renaming the label, one moving the flag
to the next bit -- and the precise preservation delta of each is reported for the administrator.
"""

from __future__ import annotations

from typing import Any

from dissect.cstruct import cstruct, dumpstruct

# tag, status word (safety flag set), shared review word, tail
SAMPLE_DATA = bytes([0xA5, 0x10, 0x00, 0x2A, 0x01, 0x5A])

BASE_DEFINITION = """
struct status_word {
    uint16  mode     : 4;
    uint16  safety   : 1;
    uint16  reserved : 11;
};

union shared_review {
    status_word bits;   // review form B: reinterpret the shared original
    uint16      raw;
};

struct acceptance_sample {
    uint8          tag;
    status_word    status;  // review form A: safety flag written separately
    shared_review  review;
    uint8          tail;
};
"""

# Variant 1: rename the label, keep the flag on the same bit
RENAMED_DEFINITION = BASE_DEFINITION.replace("safety", "interlock")

# Variant 2: move the flag to the next bit of the status word
MOVED_DEFINITION = BASE_DEFINITION.replace(
    "uint16  safety   : 1;", "uint16  spare    : 1;\n    uint16  safety   : 1;"
).replace("uint16  reserved : 11;", "uint16  reserved : 10;")

ENDIANNESSES = (("<", "little"), (">", "big"))


def project(definition: str, endian: str, data: bytes) -> dict[str, Any]:
    """Project data onto a definition as a bit-precise evidence tree."""
    cs = cstruct(endian=endian)
    cs.load(definition)
    # Explicit alias: a second name bound to the status word's storage by manual offset
    cs.acceptance_sample.add_field("status_alias", cs.uint16, offset=1)
    result = dumpstruct(cs.acceptance_sample, data, output="dict")
    annotate_bit_ranges(result["fields"], endian)
    return result


def annotate_bit_ranges(nodes: list[dict[str, Any]], endian: str) -> None:
    """Annotate bit field nodes with their bit_range (low, high) inside the storage unit.

    Like BitBuffer, little-endian storage units are consumed from the least significant bit up,
    big-endian units from the most significant bit down.
    """
    unit_offset = None
    consumed = 0
    for node in nodes:
        if "bits" in node:
            if node["offset"] != unit_offset:
                unit_offset = node["offset"]
                consumed = 0
            total = node["size"] * 8
            low = consumed if endian == "<" else total - consumed - node["bits"]
            node["bit_range"] = (low, low + node["bits"] - 1)
            consumed += node["bits"]
        else:
            unit_offset = None
        if "fields" in node:
            annotate_bit_ranges(node["fields"], endian)


def flatten(nodes: list[dict[str, Any]], prefix: str = "") -> dict[str, dict[str, Any]]:
    """Flatten a projection tree into path -> node for comparison."""
    flat = {}
    for node in nodes:
        path = f"{prefix}.{node['name']}" if prefix else str(node["name"])
        flat[path] = node
        if "fields" in node:
            flat.update(flatten(node["fields"], path))
    return flat


def coordinates(node: dict[str, Any]) -> tuple:
    """The preservation coordinates of a node: where and how its bits are kept."""
    return (node["offset"], node["size"], node.get("bits"), node.get("bit_range"), node.get("display"))


def describe(node: dict[str, Any]) -> str:
    """Describe the preservation coordinates of a node in one line."""
    parts = [f"offset {node['offset']}", f"size {node['size']}"]
    if "bit_range" in node:
        low, high = node["bit_range"]
        parts.append(f"bits {low}..{high}")
    if node.get("display") is not None:
        parts.append(f"value {node['display']}")
    return ", ".join(parts)


def preservation_summary(projection: dict[str, Any]) -> str:
    """Summarize how the projection preserves the sample: one blob, separate references."""
    blob = bytes.fromhex(projection["bytes"])
    references = [
        (path, node["offset"], node["size"])
        for path, node in flatten(projection["fields"]).items()
        if node["offset"] is not None and node["size"]
    ]
    covered: set[int] = set()
    shared: set[int] = set()
    for _, offset, size in references:
        for byte in range(offset, offset + size):
            if byte in covered:
                shared.add(byte)
            covered.add(byte)
    return (
        f"{len(blob)} bytes preserved once, {len(references)} field references, "
        f"{len(covered)}/{len(blob)} bytes referenced, "
        f"shared bytes referenced by multiple interpretations: {sorted(shared)}"
    )


def diff_projections(base: dict[str, Any], variant: dict[str, Any]) -> list[str]:
    """Field-precise preservation delta between two projections of the same sample."""
    deltas = []
    base_flat = flatten(base["fields"])
    variant_flat = flatten(variant["fields"])
    removed = {path: node for path, node in base_flat.items() if path not in variant_flat}
    added = {path: node for path, node in variant_flat.items() if path not in base_flat}

    # A removed and an added node with identical coordinates are a rename
    for removed_path, removed_node in list(removed.items()):
        for added_path, added_node in list(added.items()):
            if coordinates(removed_node) == coordinates(added_node):
                deltas.append(f"rename {removed_path} -> {added_path} ({describe(removed_node)} unchanged)")
                del removed[removed_path], added[added_path]
                break

    for path, node in removed.items():
        deltas.append(f"removed {path} ({describe(node)})")
    for path, node in added.items():
        deltas.append(f"added {path} ({describe(node)})")

    for path in base_flat.keys() & variant_flat.keys():
        before, after = base_flat[path], variant_flat[path]
        changes = [
            f"{key} {before.get(key)} -> {after.get(key)}"
            for key in ("offset", "size", "bits", "bit_range", "display")
            if before.get(key) != after.get(key)
        ]
        if changes:
            deltas.append(f"changed {path}: {', '.join(changes)}")

    if base["bytes"] == variant["bytes"]:
        deltas.append(f"preserved bytes identical: {base['bytes']}")
    else:
        before, after = bytes.fromhex(base["bytes"]), bytes.fromhex(variant["bytes"])
        offsets = [i for i, pair in enumerate(zip(before, after, strict=True)) if pair[0] != pair[1]]
        deltas.append(f"preserved bytes differ at offsets {offsets}")

    return deltas


def print_projection(projection: dict[str, Any]) -> None:
    """Print the projection table and its preservation summary."""
    for path, node in flatten(projection["fields"]).items():
        print(f"  {path:<28} {describe(node)}")
    print(f"  {preservation_summary(projection)}")


def main() -> None:
    for endian, label in ENDIANNESSES:
        print(f"=== endianness: {label} ===")
        base = project(BASE_DEFINITION, endian, SAMPLE_DATA)
        print_projection(base)
        for title, definition in (
            ("rename label safety -> interlock", RENAMED_DEFINITION),
            ("move flag to the next bit", MOVED_DEFINITION),
        ):
            print(f"--- variant: {title} ---")
            variant = project(definition, endian, SAMPLE_DATA)
            for delta in diff_projections(base, variant):
                print(f"  {delta}")


if __name__ == "__main__":
    main()
