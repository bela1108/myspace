# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.cstruct"]
# ///
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dissect.cstruct import cstruct
from dissect.cstruct.tools.compat import verify_compatibility

SAFE_OLD = """
struct SensorFrame {
    uint8 magic;
    uint8 reading_count;
    uint16 readings[reading_count];
};
"""

SAFE_NEW = """
struct SensorFrame {
    uint8 magic;
    uint8 reading_count;
    uint16 readings[reading_count];
    uint32 crc32;
};
"""


GREEDY_OLD = """
struct DeviceMessage {
    uint8 kind;
    char label[EOF];
};
"""

GREEDY_NEW = """
struct DeviceMessage {
    uint8 kind;
    char label[EOF];
    uint32 serial;
};
"""


def _print_byte_count_warning() -> None:
    frame = bytes.fromhex("016f6b78563412")
    old = cstruct().load(GREEDY_OLD, compiled=False).DeviceMessage
    new = cstruct().load(GREEDY_NEW, compiled=False).DeviceMessage
    parsed = old(frame)
    print("## Equal byte count, different wire meaning")
    print(f"wire bytes: {frame.hex()} ({len(frame)} bytes)")
    print(f"v1 label[EOF] interpretation: {parsed.label!r}, label length={parsed.__sizes__['label']}")
    try:
        new(frame)
    except Exception as exc:
        print(f"v2 declaration read: {type(exc).__name__}: {exc}")
    print()


def main() -> int:
    safe = verify_compatibility(
        SAFE_OLD,
        SAFE_NEW,
        "SensorFrame",
        observable=["magic", "reading_count", "readings"],
        old_label="v1.0",
        new_label="v1.1",
        old_version="1.0",
        new_version="1.1",
        old_constraint=">=1.0,<1.1",
        new_constraint=">=1.1,<2.0",
        samples_per_version=2,
    )
    incompatible = verify_compatibility(
        GREEDY_OLD,
        GREEDY_NEW,
        "DeviceMessage",
        observable=["kind", "label"],
        old_label="fw-1.0",
        new_label="fw-1.1",
        old_version="1.0",
        new_version="1.1",
        old_constraint=">=1.0,<1.1",
        new_constraint=">=1.1,<2.0",
        samples_per_version=2,
        extra_samples=[("seven-byte-frame", bytes.fromhex("016f6b78563412"))],
    )

    _print_byte_count_warning()
    print(safe.markdown())
    print(incompatible.markdown())

    if not safe.compatible:
        raise RuntimeError("safe append example was reported as incompatible")
    if incompatible.compatible:
        raise RuntimeError("greedy EOF append example was reported as compatible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
