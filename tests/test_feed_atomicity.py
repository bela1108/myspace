"""
Tests for the transactional, fragment-based ``Decoder.feed`` API.

A header block may arrive one byte at a time (for example through an HTTP/2
proxy that re-fragments CONTINUATION frames). Parsing must be atomic: until a
whole block has been decoded successfully, the committed dynamic table must
not observe any of the block's table updates, so a failed or truncated block
cannot poison the compression context used by the next block.
"""

from __future__ import annotations

import pytest

from hpack import (
    Decoder,
    Encoder,
    FeedResult,
    FeedStatus,
    HeaderTuple,
    HPACKDecodingError,
    NeverIndexedHeaderTuple,
    OversizedHeaderListError,
)
from hpack.exceptions import HPACKError
from hpack.huffman_table import decode_huffman


def _byte_feeds(decoder: Decoder, data: bytes) -> list[FeedResult]:
    """Feeds ``data`` one byte at a time, ending the block on the last byte."""
    results = []
    last_index = len(data) - 1
    for index, byte in enumerate(data):
        results.append(
            decoder.feed(bytes([byte]), final=index == last_index),
        )
    return results


def _huffman_name_block() -> bytes:
    """
    A header block containing a dynamic-table insertion whose name and value
    are both Huffman-encoded.
    """
    encoder = Encoder()
    return encoder.encode([("custom-key", "custom-value")], huffman=True)


def _definite_corruption(block: bytes) -> bytes:
    """
    Mutates a byte inside the Huffman-encoded name so that the block is
    guaranteed to be rejected as a definite decoding error rather than merely
    being truncated.
    """
    name = bytes(block[2:10])
    for position in range(len(name)):
        candidate = bytearray(name)
        candidate[position] = 0xFE
        try:
            decode_huffman(bytes(candidate))
        except HPACKDecodingError:
            corrupted = bytearray(block)
            corrupted[position + 2] = 0xFE
            return bytes(corrupted)
    pytest.fail("Could not construct a deterministically invalid block")


class TestFeedStatusContract:
    def test_feed_returns_typed_result_and_string_status(self):
        decoder = Decoder()
        result = decoder.feed(b"\x82", final=True)

        assert isinstance(result, FeedResult)
        assert result.status is FeedStatus.COMPLETE
        assert result.status == "complete"
        assert result.headers == ((":method", "GET"),)
        assert result.error is None

    def test_partial_fragments_report_incomplete(self):
        decoder = Decoder()
        block = _huffman_name_block()

        results = [decoder.feed(bytes([byte])) for byte in block[:-1]]

        assert results
        assert all(result.status is FeedStatus.INCOMPLETE for result in results)
        assert all(result.headers == () for result in results)
        assert all(result.error is None for result in results)
        assert list(decoder.header_table.dynamic_entries) == []

    def test_complete_block_via_feed_matches_single_shot_decode(self):
        block = _huffman_name_block()

        streaming_decoder = Decoder()
        streaming_results = _byte_feeds(streaming_decoder, block)

        single_shot_decoder = Decoder()
        single_shot_headers = single_shot_decoder.decode(block)

        assert streaming_results[-1].status is FeedStatus.COMPLETE
        assert list(streaming_results[-1].headers) == single_shot_headers
        assert list(streaming_decoder.header_table.dynamic_entries) == list(
            single_shot_decoder.header_table.dynamic_entries,
        )

    def test_empty_block_is_distinguishable(self):
        decoder = Decoder()

        result = decoder.feed(final=True)

        assert result.status is FeedStatus.EMPTY
        assert result.headers == ()
        assert result.error is None
        assert list(decoder.header_table.dynamic_entries) == []

    def test_empty_fragment_then_final_is_still_empty(self):
        decoder = Decoder()

        assert decoder.feed().status is FeedStatus.INCOMPLETE
        result = decoder.feed(final=True)

        assert result.status is FeedStatus.EMPTY

    def test_truncated_block_is_distinguishable(self):
        decoder = Decoder()
        block = _huffman_name_block()

        for byte in block[:-1]:
            assert decoder.feed(bytes([byte])).status is FeedStatus.INCOMPLETE

        result = decoder.feed(final=True)

        assert result.status is FeedStatus.TRUNCATED
        assert isinstance(result.error, HPACKDecodingError)
        assert result.headers == ()
        assert list(decoder.header_table.dynamic_entries) == []

    def test_malformed_block_is_distinguishable_from_truncation(self):
        decoder = Decoder()
        corrupted = _definite_corruption(_huffman_name_block())

        results = _byte_feeds(decoder, corrupted)
        terminal = next(result for result in results if result.status in (FeedStatus.ERROR, FeedStatus.TRUNCATED))

        assert terminal.status is FeedStatus.ERROR
        assert isinstance(terminal.error, HPACKDecodingError)
        assert list(decoder.header_table.dynamic_entries) == []


class TestFeedAtomicity:
    def test_failed_fragment_does_not_mutate_committed_table(self):
        block = _huffman_name_block()
        corrupted = _definite_corruption(block)

        decoder = Decoder()
        for index, byte in enumerate(corrupted):
            result = decoder.feed(
                bytes([byte]),
                final=index == len(corrupted) - 1,
            )
            if result.status is FeedStatus.ERROR:
                break
        else:
            pytest.fail("Corrupted block was accepted")

        # The scratch table held the half-built entry, but the committed
        # table must be exactly as it was before the block started.
        assert list(decoder.header_table.dynamic_entries) == []

    def test_next_block_after_failure_uses_unpolluted_indices(self):
        block = _huffman_name_block()
        corrupted = _definite_corruption(block)

        decoder = Decoder()
        for index, byte in enumerate(corrupted):
            result = decoder.feed(
                bytes([byte]),
                final=index == len(corrupted) - 1,
            )
            if result.status is FeedStatus.ERROR:
                break

        decoder.reset_feed()
        recovered = _byte_feeds(decoder, block)[-1]
        reference = Decoder().decode(block)

        assert recovered.status is FeedStatus.COMPLETE
        assert list(recovered.headers) == reference
        assert list(decoder.header_table.dynamic_entries) == [
            (b"custom-key", b"custom-value"),
        ]

    def test_truncated_block_does_not_mutate_committed_table(self):
        block = _huffman_name_block()
        decoder = Decoder()

        for byte in block[:-1]:
            decoder.feed(bytes([byte]))
        assert decoder.feed(final=True).status is FeedStatus.TRUNCATED

        assert list(decoder.header_table.dynamic_entries) == []

        decoder.reset_feed()
        recovered = _byte_feeds(decoder, block)[-1]
        reference = Decoder().decode(block)

        assert list(recovered.headers) == reference
        assert list(decoder.header_table.dynamic_entries) == [
            (b"custom-key", b"custom-value"),
        ]

    def test_repeated_calls_after_failure_are_duplicate_until_reset(self):
        corrupted = _definite_corruption(_huffman_name_block())
        decoder = Decoder()

        for index, byte in enumerate(corrupted):
            result = decoder.feed(
                bytes([byte]),
                final=index == len(corrupted) - 1,
            )
            if result.status is FeedStatus.ERROR:
                break

        assert decoder.feed(b"\x00").status is FeedStatus.DUPLICATE
        assert decoder.feed(b"\x00", final=True).status is FeedStatus.DUPLICATE

        decoder.reset_feed()
        assert _byte_feeds(decoder, _huffman_name_block())[-1].status is FeedStatus.COMPLETE

    def test_repeated_calls_after_completion_are_duplicate_until_reset(self):
        decoder = Decoder()

        first = decoder.feed(b"\x82", final=True)
        assert first.status is FeedStatus.COMPLETE

        assert decoder.feed(b"\x82").status is FeedStatus.DUPLICATE
        assert decoder.feed(b"\x82", final=True).status is FeedStatus.DUPLICATE

        decoder.reset_feed()
        second = decoder.feed(b"\x82", final=True)
        assert second.status is FeedStatus.COMPLETE
        assert second.headers == first.headers

    def test_repeated_calls_after_empty_block_are_duplicate_until_reset(self):
        decoder = Decoder()

        assert decoder.feed(final=True).status is FeedStatus.EMPTY
        assert decoder.feed(final=True).status is FeedStatus.DUPLICATE

        decoder.reset_feed()
        assert decoder.feed(b"\x82", final=True).status is FeedStatus.COMPLETE

    def test_reset_feed_abandons_partial_block_without_table_changes(self):
        block = _huffman_name_block()
        decoder = Decoder()

        for byte in block[:5]:
            assert decoder.feed(bytes([byte])).status is FeedStatus.INCOMPLETE

        decoder.reset_feed()

        assert decoder.feed(block, final=True).status is FeedStatus.COMPLETE
        assert list(decoder.header_table.dynamic_entries) == [
            (b"custom-key", b"custom-value"),
        ]


class TestFeedTableSemantics:
    def test_dynamic_insertion_is_only_visible_after_commit(self):
        decoder = Decoder()
        block = _huffman_name_block()

        for byte in block[:-1]:
            decoder.feed(bytes([byte]))
            assert list(decoder.header_table.dynamic_entries) == []

        result = decoder.feed(bytes([block[-1]]), final=True)

        assert result.status is FeedStatus.COMPLETE
        assert list(decoder.header_table.dynamic_entries) == [
            (b"custom-key", b"custom-value"),
        ]

    def test_two_sequential_blocks_accumulate_table_state(self):
        encoder = Encoder()
        first_block = encoder.encode([("first-key", "first-value")], huffman=True)
        second_block = encoder.encode([("second-key", "second-value")], huffman=True)

        decoder = Decoder()
        assert _byte_feeds(decoder, first_block)[-1].status is FeedStatus.COMPLETE
        decoder.reset_feed()
        assert _byte_feeds(decoder, second_block)[-1].status is FeedStatus.COMPLETE

        assert [entry[0] for entry in decoder.header_table.dynamic_entries] == [
            b"second-key",
            b"first-key",
        ]

    def test_feed_respects_max_header_list_size(self):
        decoder = Decoder(max_header_list_size=10)
        block = _huffman_name_block()

        results = _byte_feeds(decoder, block)
        terminal = results[-1]

        assert terminal.status is FeedStatus.ERROR
        assert isinstance(terminal.error, OversizedHeaderListError)
        assert list(decoder.header_table.dynamic_entries) == []

    def test_raw_mode_returns_byte_strings(self):
        decoder = Decoder()
        result = decoder.feed(b"\x82", final=True, raw=True)

        assert result.status is FeedStatus.COMPLETE
        name, value = result.headers[0]
        assert isinstance(name, bytes)
        assert isinstance(value, bytes)

    def test_invalid_index_is_definite_error_and_atomic(self):
        decoder = Decoder()
        # Indexed representation referencing an index that does not exist.
        results = _byte_feeds(decoder, b"\xbe\x86")

        assert results[0].status is FeedStatus.ERROR
        assert isinstance(results[0].error, HPACKError)
        assert list(decoder.header_table.dynamic_entries) == []

    def test_never_indexed_tuple_type_is_preserved(self):
        decoder = Decoder()
        # Literal header field that must never be indexed.
        result = decoder.feed(
            b"\x10\x0acustom-key\x0dcustom-header",
            final=True,
            raw=True,
        )

        assert result.status is FeedStatus.COMPLETE
        assert isinstance(result.headers[0], NeverIndexedHeaderTuple)
        assert list(decoder.header_table.dynamic_entries) == []

    def test_indexed_header_emits_plain_header_tuple(self):
        decoder = Decoder()
        result = decoder.feed(b"\x82", final=True)

        assert result.status is FeedStatus.COMPLETE
        assert isinstance(result.headers[0], HeaderTuple)
        assert not isinstance(result.headers[0], NeverIndexedHeaderTuple)

    def test_single_shot_decode_still_raises_and_remains_atomic(self):
        block = _huffman_name_block()
        corrupted = _definite_corruption(block)
        decoder = Decoder()

        with pytest.raises(HPACKDecodingError):
            decoder.decode(corrupted)

        assert list(decoder.header_table.dynamic_entries) == []

        assert decoder.decode(block) == Decoder().decode(block)

    def test_table_size_change_is_committed_with_the_block(self):
        decoder = Decoder()
        decoder.max_allowed_table_size = 128
        # Dynamic table size update to 64, followed by an indexed :method GET.
        block = b"\x3f\x21\x82"

        result = decoder.feed(block, final=True)

        assert result.status is FeedStatus.COMPLETE
        assert decoder.header_table_size == 64

    def test_oversized_table_change_is_a_definite_error(self):
        decoder = Decoder()
        decoder.max_allowed_table_size = 127
        block = b"?a\x82"

        result = decoder.feed(block, final=True)

        assert result.status is FeedStatus.ERROR
        assert decoder.header_table_size == 4096
