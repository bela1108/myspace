from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dissect.cstruct import dumpstruct, manifest

if TYPE_CHECKING:
    from dissect.cstruct import cstruct


def _field(result: dict[str, Any], path: str) -> dict[str, Any]:
    def walk(fields: list[dict[str, Any]]) -> dict[str, Any] | None:
        for field in fields:
            if field["path"] == path:
                return field
            if nested := walk(field.get("fields", [])):
                return nested
        return None

    field = walk(result["fields"])
    assert field is not None
    return field


def test_manifest_count_dependency_withheld(cs: cstruct, compiled: bool) -> None:
    """A variable-length member can be located, but not interpreted, without its count."""
    cs.load(
        """
        struct test {
            uint8 count;
            uint8 data[count];
            uint16 tail;
        };
        """,
        compiled=compiled,
    )

    result = manifest(cs.test(b"\x02\xaa\xbb\x34\x12"), allowlist=["data"], offset=0x20)

    count = _field(result, "count")
    data = _field(result, "data")
    tail = _field(result, "tail")

    assert count["approved"] is False
    assert data["approved"] is True
    assert data["depends_on_count"] is True
    assert data["dependencies"] == ["count"]
    assert data["restorable"] is False
    assert "count" in data["reason"]
    assert "approved" in data["reason"]
    assert data["offset"] == 0x21
    assert tail["approved"] is False

    assert result["slices"] == [{"offset": 0x21, "size": 2}]
    assert result["unrestorable"] == [{"path": "data", "reason": data["reason"]}]


def test_manifest_count_dependency_approved(cs: cstruct, compiled: bool) -> None:
    """A member is restorable when its count is part of the approved slices."""
    cs.load(
        """
        struct test {
            uint8 count;
            uint8 data[count];
            uint16 tail;
        };
        """,
        compiled=compiled,
    )

    result = manifest(cs.test(b"\x02\xaa\xbb\x34\x12"), allowlist=["count", "data"])

    data = _field(result, "data")
    assert data["approved"] is True
    assert data["depends_on_count"] is True
    assert data["restorable"] is True
    assert data["reason"] is None
    assert result["slices"] == [{"offset": 0, "size": 3}]
    assert result["unrestorable"] == []


def test_manifest_shared_union_bytes(cs: cstruct, compiled: bool) -> None:
    """Union alternatives that overlap an approved member are reported as shared bytes."""
    cs.load(
        """
        struct test {
            union {
                uint32 a;
                uint16 b;
                uint8  c;
            };
            uint8 tail;
        };
        """,
        compiled=compiled,
    )

    result = manifest(cs.test(b"\x01\x02\x03\x04\x05"), allowlist=["a", "tail"])

    a = _field(result, "a")
    b = _field(result, "b")
    c = _field(result, "c")
    assert a["approved"] is True
    assert b["approved"] is False
    assert c["approved"] is False
    assert a["shared_with"] == ["b", "c"]
    assert b["shared_with"] == ["a", "c"]
    assert result["shared"] == [
        {"offset": 0, "size": 1, "members": ["a", "b", "c"]},
        {"offset": 1, "size": 1, "members": ["a", "b"]},
    ]
    assert result["slices"] == [{"offset": 0, "size": 5}]


def test_manifest_shared_bitfield_bytes(cs: cstruct, compiled: bool) -> None:
    """Bit fields share their storage unit, even when only one field is approved."""
    cs.load(
        """
        struct test {
            uint8 a : 4;
            uint8 b : 4;
            uint8 tail;
        };
        """,
        compiled=compiled,
    )

    result = manifest(cs.test(b"\x12\x34"), allowlist=["a", "tail"])

    a = _field(result, "a")
    b = _field(result, "b")
    assert a["shared_with"] == ["b"]
    assert b["shared_with"] == ["a"]
    assert result["shared"] == [{"offset": 0, "size": 1, "members": ["a", "b"]}]


def test_manifest_nested_count_dependencies(cs: cstruct, compiled: bool) -> None:
    """Array elements resolve counts in their own and in an enclosing structure."""
    cs.load(
        """
        struct item {
            uint8 length;
            char  data[length];
        };
        struct test {
            uint8 count;
            item  items[count];
            uint8 tail;
        };
        """,
        compiled=compiled,
    )

    result = manifest(cs.test(b"\x02\x01a\x02bc\xff"), allowlist=["items[*]"])

    assert _field(result, "items")["dependencies"] == ["count", "items[0].length", "items[1].length"]
    assert _field(result, "items[0].data")["dependencies"] == ["items[0].length"]
    assert _field(result, "items[1].data")["dependencies"] == ["items[1].length"]
    assert _field(result, "items[1]")["dependencies"] == ["count", "items[1].length"]
    assert _field(result, "items[0].data")["restorable"] is True
    assert result["slices"] == [{"offset": 1, "size": 5}]


def test_manifest_dotted_count_dependency(cs: cstruct, compiled: bool) -> None:
    """A count inside a preceding structure is a dependency of a following member."""
    cs.load(
        """
        struct header { uint8 count; };
        struct test {
            header h;
            uint8  data[h.count];
        };
        """,
        compiled=compiled,
    )

    result = manifest(cs.test(b"\x03abc"), allowlist=["data"])

    data = _field(result, "data")
    assert data["dependencies"] == ["h.count"]
    assert data["restorable"] is False
    assert "h.count" in data["reason"]
    assert result["slices"] == [{"offset": 1, "size": 3}]


def test_manifest_null_terminated_has_no_count_dependency(cs: cstruct, compiled: bool) -> None:
    """A null-terminated member is delimited by its sentinel, not a preceding count."""
    cs.load(
        """
        struct test {
            char  data[];
            uint8 tail;
        };
        """,
        compiled=compiled,
    )

    result = manifest(cs.test(b"abc\x00\xff"), allowlist=["data"])

    data = _field(result, "data")
    assert data["depends_on_count"] is False
    assert data["dependencies"] == []
    assert data["restorable"] is True
    assert result["slices"] == [{"offset": 0, "size": 4}]


def test_manifest_unknown_dynamic_size(cs: cstruct, compiled: bool) -> None:
    """Without a parsed byte length, the manifest explains why a dynamic member cannot be restored."""
    cs.load(
        """
        struct test {
            uint8 count;
            uint8 data[count];
            uint8 tail;
        };
        """,
        compiled=compiled,
    )

    obj = cs.test(count=2, data=[6, 7], tail=9)
    result = manifest(obj, allowlist=["data"])

    data = _field(result, "data")
    assert data["size"] is None
    assert data["restorable"] is False
    assert "size is unknown" in data["reason"]
    assert result["slices"] == []


def test_dumpstruct_manifest_output(cs: cstruct, compiled: bool) -> None:
    """Passing an allowlist to dumpstruct returns the manifest in dict and string form."""
    cs.load(
        """
        struct test {
            uint8 count;
            uint8 data[count];
        };
        """,
        compiled=compiled,
    )

    data = b"\x02\xaa\xbb"
    assert dumpstruct(cs.test, data, output="dict", allowlist=["data"])["slices"] == [{"offset": 1, "size": 2}]

    out = dumpstruct(cs.test, data, output="string", allowlist=["data"])
    assert "approved" in out
    assert "withheld" in out
    assert "depends on count" in out
