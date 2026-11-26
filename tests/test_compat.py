from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct.tools.compat import markers_from_cdef, verify_compatibility

if TYPE_CHECKING:
    from dissect.cstruct.tools.compat import (
        CompatibilityReport,
        SampleReport,
    )

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


def _sample(report: CompatibilityReport, sample_id: str) -> SampleReport:
    return next(sample for sample in report.samples if sample.sample_id == sample_id)


def test_safe_append_preserves_marked_prefix() -> None:
    report = verify_compatibility(
        SAFE_OLD,
        SAFE_NEW,
        "SensorFrame",
        observable=["magic", "reading_count", "readings"],
        samples_per_version=2,
        old_constraint=">=1.0,<1.1",
        new_constraint=">=1.1,<2.0",
    )

    assert report.compatible
    assert report.append_only
    assert not [finding for finding in report.findings if finding.severity == "error"]
    assert report.suggested_prefix_constraint == ">=1.0,<2.0"

    old_sample = _sample(report, "v1-small")
    new_sample = _sample(report, "v2-small")

    assert old_sample.compatible
    assert old_sample.exact_read_versions == ["v1"]
    assert old_sample.applicable_constraints == [">=1.0,<1.1", ">=1.1,<2.0"]
    assert old_sample.read_dispositions["v2"] == "prefix readable; full tail read failed"

    assert new_sample.compatible
    assert new_sample.exact_read_versions == ["v2"]
    assert new_sample.read_dispositions["v1"].startswith("trailing 4 bytes ignored")
    assert new_sample.applicable_constraints == [">=1.0,<1.1", ">=1.1,<2.0"]


def test_eof_length_is_semantically_broken_by_append() -> None:
    report = verify_compatibility(
        GREEDY_OLD,
        GREEDY_NEW,
        "DeviceMessage",
        observable=["kind", "label"],
        samples_per_version=2,
        old_constraint=">=1.0,<1.1",
        new_constraint=">=1.1,<2.0",
    )

    assert not report.compatible
    assert report.append_only
    finding = next(finding for finding in report.findings if finding.code == "eof-tail-extension")
    assert finding.path == "label"

    sample = _sample(report, "v2-small")
    length_difference = next(difference for difference in sample.differences if difference.kind == "read-length")
    assert length_difference.path == "label"
    assert length_difference.expected == 3
    assert length_difference.actual == 7

    old_parse = sample.parses["v1:full"]
    new_parse = sample.parses["v2:full"]
    assert old_parse.ok
    assert old_parse.consumed == sample.length
    assert old_parse.paths["label"].length == 7
    assert not new_parse.ok
    assert "expected 4" in (new_parse.error or "")


def test_equal_byte_count_does_not_mean_equal_parse() -> None:
    report = verify_compatibility(
        GREEDY_OLD,
        GREEDY_NEW,
        "DeviceMessage",
        observable=["kind", "label"],
        samples_per_version=0,
        extra_samples=[("frame", bytes.fromhex("016f6b78563412"))],
    )

    sample = report.samples[0]
    old_prefix = sample.parses["v1:prefix"]
    new_full = sample.parses["v2:full"]

    assert sample.length == 7
    assert old_prefix.paths["label"].length == 6
    assert old_prefix.paths["label"].value == {"__bytes__": "6f6b78563412"}
    assert not new_full.ok
    assert new_full.consumed == 7


def test_sizeof_length_expression_detects_referenced_extension() -> None:
    old = """
    struct Meta { uint8 version; };
    struct Block { uint8 tag; uint8 mirror[sizeof(Meta)]; };
    """
    new = """
    struct Meta { uint8 version; uint16 extra; };
    struct Block { uint8 tag; uint8 mirror[sizeof(Meta)]; };
    """

    report = verify_compatibility(old, new, "Block", observable=["tag", "mirror"], samples_per_version=1)

    assert not report.compatible
    assert any(finding.path == "mirror" for finding in report.findings if finding.severity == "error")
    sample = _sample(report, "v2-zero")
    difference = next(
        d for d in sample.differences if d.kind == "read-length" and d.path == "mirror" and d.version == "v1:prefix"
    )
    assert (difference.expected, difference.actual) == (3, 1)


def test_markers_from_cdef_comments() -> None:
    cdef = """
    struct M {
        uint8 a; // @compat-prefix
        uint16 count;
        uint8 values[count]; /// observable-prefix
        uint32 tail;
    };
    """

    assert markers_from_cdef(cdef) == ["a", "values"]
