from __future__ import annotations

import struct
from io import BytesIO
from threading import Event, Thread
from typing import TYPE_CHECKING, Any

import pytest

from dissect.cstruct import DeclarationContext, cstruct

if TYPE_CHECKING:
    from threading import Event as EventType


STATIC_OLD = """
#define RECORD_WORDS 2
typedef uint32 word_t;

struct Record {
    uint8 tag;
    word_t words[RECORD_WORDS];
};
"""

STATIC_NEW = """
#define RECORD_WORDS 4
typedef uint64 word_t;

struct Record {
    uint64 tag;
    word_t words[RECORD_WORDS];
};
"""

DYNAMIC_OLD = """
#define SCALE 1
typedef uint32 word_t;

struct Job {
    uint32 count;
    word_t words[count * SCALE + (sizeof(word_t) - 4)];
};
"""

DYNAMIC_NEW = """
#define SCALE 4
typedef uint64 word_t;

struct Job {
    uint64 count;
    word_t words[count * SCALE + (sizeof(word_t) - 4)];
};
"""


def _static_old_payload() -> bytes:
    return bytes([0x7F]) + struct.pack("<II", 0x11223344, 0x55667788)


def _static_new_payload() -> bytes:
    return struct.pack("<Q", 0x10) + b"".join(struct.pack("<Q", value) for value in (1, 2, 3, 4))


def _dynamic_old_payload() -> bytes:
    return struct.pack("<I", 2) + struct.pack("<II", 0x11223344, 0x55667788)


def _dynamic_new_payload() -> bytes:
    # count=1, SCALE=4 and sizeof(word_t)=8 yields 1*4 + (8-4) = 8 entries.
    return struct.pack("<Q", 1) + b"".join(struct.pack("<Q", value) for value in range(8))


class BlockingReadStream:
    """BytesIO wrapper that blocks its first read until the test releases it."""

    def __init__(self, payload: bytes, entered: EventType, release: EventType) -> None:
        self._buffer = BytesIO(payload)
        self._entered = entered
        self._release = release
        self._armed = True

    def read(self, size: int = -1) -> bytes:
        if self._armed:
            self._armed = False
            self._entered.set()
            if not self._release.wait(10):
                raise TimeoutError("Timed out waiting for declaration redefinition")

        return self._buffer.read(size)

    def tell(self) -> int:
        return self._buffer.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._buffer.seek(offset, whence)


class BlockingConstants(dict):
    """Constant mapping that blocks when the old read resolves ``SCALE``."""

    def __init__(self, values: dict[str, object], entered: EventType, release: EventType) -> None:
        super().__init__(values)
        self._entered = entered
        self._release = release
        self._armed = True

    def __contains__(self, name: object) -> bool:
        if name == "SCALE" and self._armed:
            self._armed = False
            self._entered.set()
            if not self._release.wait(10):
                raise TimeoutError("Timed out waiting for declaration redefinition")

        return super().__contains__(name)


def test_snapshot_creates_independent_type_graph_and_freeze_seals_context() -> None:
    cs = cstruct()
    cs.load(STATIC_OLD)

    old_abi = cs.snapshot("case-old")

    # Freezing must not rebind the source registry's classes to the snapshot.
    assert cs.Record.__cs__ is cs
    assert old_abi.Record is not cs.Record
    assert old_abi.Record.__cs__ is old_abi
    assert old_abi.Record.__fields__[1].type.__cs__ is old_abi
    assert cs.contexts["case-old"] is old_abi

    assert old_abi.is_frozen
    with pytest.raises(TypeError, match="frozen"):
        old_abi.load(STATIC_NEW)
    with pytest.raises(TypeError, match="frozen"):
        old_abi.add_const("LATE", 1)

    sealed = DeclarationContext()
    sealed.load(STATIC_OLD)
    assert sealed.freeze() is sealed
    assert sealed.is_frozen
    with pytest.raises(TypeError, match="frozen"):
        sealed.load(STATIC_NEW)


def test_explicit_context_selection() -> None:
    cs = cstruct()
    cs.load(STATIC_OLD)
    cs.snapshot("old")
    cs.load(STATIC_NEW, replace=True)
    cs.snapshot("new")

    old_value = cs.read("Record", _static_old_payload(), context="old")
    new_value = cs.read("Record", _static_new_payload(), context="new")

    assert old_value.tag == 0x7F
    assert old_value.words == [0x11223344, 0x55667788]
    assert new_value.tag == 0x10
    assert new_value.words == [1, 2, 3, 4]

    with cs.context("new"):
        scoped_value = cs.read("Record", _static_new_payload())
    assert scoped_value.words == [1, 2, 3, 4]


def test_inflight_static_read_keeps_original_abi_after_compiled_redefinition() -> None:
    cs = cstruct()
    cs.load(STATIC_OLD, compiled=True)
    old_abi = cs.snapshot()
    old_type = old_abi.Record

    read_entered = Event()
    release_old_read = Event()
    stream = BlockingReadStream(_static_old_payload(), read_entered, release_old_read)
    outcome: dict[str, Any] = {}

    def read_old_record() -> None:
        try:
            outcome["record"] = old_type.read(stream)
        except BaseException as exc:  # pragma: no cover - asserted in the main thread
            outcome["error"] = exc

    worker = Thread(target=read_old_record)
    worker.start()

    try:
        assert read_entered.wait(10)

        # The replacement is compiled and exercised while the old read is still inside read().
        cs.load(STATIC_NEW, replace=True, compiled=True)
        cs.Record.reads(_static_new_payload())
        assert cs.Record.__compiled__
    finally:
        release_old_read.set()

    worker.join(10)
    assert not worker.is_alive()
    assert "error" not in outcome, outcome.get("error")

    old_record = outcome["record"]
    assert len(old_type) == 9
    assert [field.offset for field in old_type.__fields__] == [0, 1]
    assert old_type.__fields__[1].offset == 1
    assert old_type.__fields__[1].type.__size__ == 8
    assert old_type.__fields__[1].type.__type__.__size__ == 4
    assert old_abi.consts["RECORD_WORDS"] == 2

    assert old_record.tag == 0x7F
    assert old_record.words == [0x11223344, 0x55667788]

    old_compiled_read = old_type.__dict__["_read"]
    assert old_compiled_read.__func__.__globals__["cs"] is old_abi

    assert len(cs.Record) == 40
    assert [field.offset for field in cs.Record.__fields__] == [0, 8]
    assert cs.Record.__fields__[1].type.__type__.__size__ == 8


def test_inflight_dynamic_read_keeps_frozen_constant_and_alias() -> None:
    cs = cstruct()
    cs.load(DYNAMIC_OLD, compiled=True)
    old_abi = cs.snapshot()

    scale_lookup_entered = Event()
    release_scale_lookup = Event()
    old_abi.consts = BlockingConstants(old_abi.consts, scale_lookup_entered, release_scale_lookup)
    task = old_abi.claim("Job")

    outcome: dict[str, Any] = {}

    def read_old_job() -> None:
        try:
            outcome["job"] = task.reads(_dynamic_old_payload())
        except BaseException as exc:  # pragma: no cover - asserted in the main thread
            outcome["error"] = exc

    worker = Thread(target=read_old_job)
    worker.start()

    try:
        assert scale_lookup_entered.wait(10)

        cs.load(DYNAMIC_NEW, replace=True, compiled=True)
        cs.Job.reads(_dynamic_new_payload())
        assert cs.Job.__compiled__
    finally:
        release_scale_lookup.set()

    worker.join(10)
    assert not worker.is_alive()
    assert "error" not in outcome, outcome.get("error")

    old_job = outcome["job"]
    assert [field.offset for field in task.type.__fields__] == [0, 4]
    assert task.type.__fields__[1].offset == 4
    assert task.type.__fields__[1].type.__type__.__size__ == 4
    assert old_job.count == 2
    assert old_job.words == [0x11223344, 0x55667788]
    assert old_job.__dynamic_sizes__["words"] == 8


def test_declaration_context_is_a_cstruct_with_named_contexts() -> None:
    declarations = DeclarationContext()
    old_abi = declarations.create_context("case-a", frozen=True)
    new_abi = declarations.create_context("case-b")
    new_abi.load(STATIC_NEW)

    assert declarations.get_context("case-a").is_frozen
    assert declarations.select_context("case-b") is new_abi
    assert declarations.read("Record", _static_new_payload(), context="case-b").tag == 0x10
    assert old_abi is declarations.contexts["case-a"]
