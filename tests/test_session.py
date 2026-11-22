import hashlib
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any

import pytest

from cbor2 import (
    CBORDecodeEOF,
    CBORDecoder,
    ReadSession,
    Receipt,
    SessionStateError,
    dumps,
    load,
    loads,
)

TZ_PLUS_8 = timezone(timedelta(hours=8))
STAMP = datetime(2026, 11, 23, 9, 30, tzinfo=TZ_PLUS_8)


def numbered_records(count: int = 4) -> list[dict[str, Any]]:
    return [{"seq": seq, "at": STAMP + timedelta(minutes=seq)} for seq in range(1, count + 1)]


def encode_records(records: list[Any]) -> bytes:
    return b"".join(dumps(record) for record in records)


def chunked(data: bytes, size: int) -> list[bytes]:
    return [data[offset : offset + size] for offset in range(0, len(data), size)]


def drain(session: ReadSession) -> list[Receipt]:
    receipts = []
    while (receipt := session.confirm_next()) is not None:
        receipts.append(receipt)
    return receipts


def test_receipt_binds_each_top_level_object() -> None:
    records = numbered_records()
    stream = encode_records(records)
    session = ReadSession(BytesIO(stream))

    receipts = drain(session)

    assert [receipt.value for receipt in receipts] == records
    assert [receipt.sequence for receipt in receipts] == list(range(len(records)))
    assert session.exhausted
    assert session.confirmed_count == len(records)
    offset = 0
    for receipt in receipts:
        raw = stream[receipt.start : receipt.end]
        assert receipt.start == offset
        assert receipt.size == len(raw)
        assert receipt.digest == hashlib.sha256(raw).hexdigest()
        assert loads(raw) == receipt.value
        offset = receipt.end
    assert offset == len(stream)


def test_receipt_preserves_timezone_tag() -> None:
    record = numbered_records(1)[0]
    receipt = ReadSession(encode_records([record])).confirm_next()

    assert receipt is not None
    assert receipt.value == record
    assert receipt.value["at"].utcoffset() == timedelta(hours=8)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(lambda s: BytesIO(s), id="bytesio"),
        pytest.param(lambda s: chunked(s, 5), id="chunk-list"),
        pytest.param(lambda s: s, id="bytes"),
    ],
)
def test_chunked_sources(source: Any) -> None:
    records = numbered_records()
    stream = encode_records(records)
    session = ReadSession(source(stream), chunk_size=3)

    assert [receipt.value for receipt in drain(session)] == records
    assert session.exhausted


def test_segmented_withdrawal_stops_handoff_at_last_confirmed() -> None:
    records: list[Any] = numbered_records(3)
    records.append(STAMP)  # epoch-based timezone tag (tag 1)
    stream = encode_records(records[:3]) + dumps(STAMP, datetime_as_timestamp=True)
    session = ReadSession(BytesIO(stream), chunk_size=7)

    first = session.confirm_next()
    second = session.confirm_next()
    assert first is not None and second is not None
    session.withdraw()

    handed_off = list(session.handoff())
    assert handed_off == [first, second]
    assert [receipt.value for receipt in handed_off] == records[:2]
    assert session.pending_count == 0
    assert list(session.handoff()) == []

    with pytest.raises(SessionStateError, match="accept"):
        session.confirm_next()

    session.accept()
    rest = drain(session)
    assert [receipt.sequence for receipt in rest] == [2, 3]
    assert rest[0].value == records[2]
    assert rest[1].value == STAMP
    assert session.confirm_next() is None
    assert [receipt.value for receipt in session.handoff()] == records[2:]


def test_handoff_yields_one_confirmed_receipt_at_a_time() -> None:
    records = numbered_records(3)
    session = ReadSession(encode_records(records))
    expected = [session.confirm_next() for _ in range(2)]
    session.withdraw()

    handoff = session.handoff()
    assert isinstance(handoff, Iterator)
    assert next(handoff) == expected[0]
    assert session.pending_count == 1
    assert next(handoff) == expected[1]
    with pytest.raises(StopIteration):
        next(handoff)


def test_truncated_tail_keeps_confirmed_receipts() -> None:
    records = numbered_records(3)
    stream = encode_records(records)
    session = ReadSession(stream[:-1])

    confirmed = [session.confirm_next(), session.confirm_next()]
    with pytest.raises(CBORDecodeEOF):
        session.confirm_next()

    assert [receipt.value for receipt in session.handoff()] == records[:2]
    assert all(receipt is not None for receipt in confirmed)


def test_confirm_next_after_exhaustion_returns_none() -> None:
    session = ReadSession(encode_records(numbered_records(1)))
    assert session.confirm_next() is not None
    assert session.confirm_next() is None
    assert session.confirm_next() is None
    assert session.exhausted


def test_empty_source_yields_no_receipts() -> None:
    session = ReadSession(b"")
    assert session.confirm_next() is None
    assert list(session.handoff()) == []


def test_invalid_chunk_size_rejected() -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        ReadSession(b"", chunk_size=0)


def test_classic_api_still_decodes_same_stream() -> None:
    records = numbered_records()
    stream = encode_records(records)

    decoder = CBORDecoder(BytesIO(stream))
    assert [decoder.decode() for _ in records] == records
    assert load(BytesIO(encode_records(records[:1]))) == records[0]
    assert loads(dumps(records[0])) == records[0]
