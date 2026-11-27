from __future__ import annotations

from dissect.cstruct import cstruct
from dissect.cstruct.verification import (
    CollectionMethod,
    FieldClaim,
    Observation,
    UnprovableField,
    verify_structure,
)


def test_verify_structure_common_and_optional_fields() -> None:
    cs = cstruct().load(
        """
        struct record {
            uint32 common_id;
            uint16 optional_count;
            char optional_name[optional_count];
            uint8 common_flags;
        };
        """
    )
    data = (1).to_bytes(4, "little") + (3).to_bytes(2, "little") + b"abc" + b"\x0f"

    results = verify_structure(
        cs.record,
        data,
        {
            "full": (0, len(data)),
            "partial": (0, 9),
        },
    )

    full = results["full"]
    assert [claim.path for claim in full.claims] == [
        "common_id",
        "optional_count",
        "optional_name",
        "common_flags",
    ]
    assert [claim.value for claim in full.claims] == [1, 3, b"abc", 0x0F]
    assert full.observations == (Observation(0, len(data)),)
    assert full.unprovable == ()

    partial = results["partial"]
    assert [claim.path for claim in partial.claims] == ["common_id", "optional_count", "optional_name"]
    assert partial.claims[2].observations == (Observation(6, 9),)
    assert partial.claims[2].dependencies == ("optional_count",)
    assert partial.unprovable == (UnprovableField("common_flags", "truncated"),)
    assert partial.observations == (Observation(0, 9),)


def test_verify_structure_collection_methods_are_independent() -> None:
    cs = cstruct().load(
        """
        struct record {
            uint32 common_id;
            uint16 optional_count;
            char optional_name[optional_count];
        };
        """
    )
    data = (7).to_bytes(4, "little") + (2).to_bytes(2, "little") + b"xy"
    methods = [
        CollectionMethod("first", (0, 6)),
        CollectionMethod("second", (0, len(data))),
    ]

    results = verify_structure(cs.record, data, methods)
    assert [claim.path for claim in results["first"].claims] == ["common_id", "optional_count"]
    assert results["first"].unprovable == (UnprovableField("optional_name", "truncated"),)
    assert [claim.path for claim in results["second"].claims] == [
        "common_id",
        "optional_count",
        "optional_name",
    ]

    without_first = verify_structure(cs.record, data, methods[1:])
    assert set(without_first) == {"second"}
    assert without_first["second"] == results["second"]


def test_verify_structure_records_dependencies_for_dynamic_field() -> None:
    cs = cstruct().load(
        """
        struct record {
            uint8 count;
            uint32 values[count];
        };
        """
    )
    data = b"\x02" + (1).to_bytes(4, "little") + (2).to_bytes(4, "little")

    result = verify_structure(cs.record, data, {"method": (0, len(data))})["method"]

    assert [claim.path for claim in result.claims] == ["count", "values"]
    assert [claim.value for claim in result.claims] == [2, [1, 2]]
    assert [claim.observations for claim in result.claims] == [
        (Observation(0, 1),),
        (Observation(1, len(data)),),
    ]
    assert [claim.dependencies for claim in result.claims] == [(), ("count",)]


def test_verify_structure_continues_after_static_gap() -> None:
    cs = cstruct().load(
        """
        struct inner {
            uint16 a;
            uint16 b;
        };

        struct outer {
            uint32 id;
            inner item;
            uint8 tail;
        };
        """
    )
    data = (7).to_bytes(4, "little") + (11).to_bytes(2, "little") + (12).to_bytes(2, "little") + b"\x09"

    result = verify_structure(cs.outer, data, {"split": [(0, 5), (6, 8)]})["split"]

    assert [(claim.path, claim.value) for claim in result.claims] == [("id", 7), ("item.b", 12)]
    assert result.observations == (Observation(0, 5), Observation(6, 8))
    assert result.unprovable == (
        UnprovableField("item.a", "truncated"),
        UnprovableField("tail", "truncated"),
    )


def test_verify_structure_eof_requires_actual_end_of_data() -> None:
    cs = cstruct().load(
        """
        struct record {
            uint8 head;
            char tail[EOF];
        };
        """
    )
    data = b"\x01abcdef"

    full = verify_structure(cs.record, data, {"full": (0, len(data))})["full"]
    partial = verify_structure(cs.record, data, {"partial": (0, 4)})["partial"]

    assert [(claim.path, claim.value) for claim in full.claims] == [("head", 1), ("tail", b"abcdef")]
    assert [claim.path for claim in partial.claims] == ["head"]
    assert partial.unprovable == (UnprovableField("tail", "undecidable"),)


def test_verify_structure_null_terminated_field_includes_terminator() -> None:
    cs = cstruct().load(
        """
        struct record {
            uint8 id;
            char name[];
            uint8 after;
        };
        """
    )
    data = b"\x01abc\x00\x09"

    result = verify_structure(cs.record, data, {"method": (0, len(data))})["method"]

    assert [(claim.path, claim.value) for claim in result.claims] == [
        ("id", 1),
        ("name", b"abc"),
        ("after", 9),
    ]
    assert [claim.observations for claim in result.claims] == [
        (Observation(0, 1),),
        (Observation(1, 5),),
        (Observation(5, 6),),
    ]
