"""Bounded, reproducible property tests for the offline archive wrapper.

An independent ledger (no cbor2 involved) computes the expected intake
result from generation metadata; the wrapper under test decodes for real
with cbor2 and must agree on every batch. Batches are built from small
well-formed objects (empty and plain nested maps included), some of which
are corrupted so that failed previews occur. The generation is bounded
and derandomized, so the dozens of batches are exactly rerunnable.
"""

from __future__ import annotations

from dataclasses import dataclass

import hypothesis.strategies as st
from hypothesis import given, settings

from cbor2 import dumps

from .offline_archive import receive_batch

MAX_BATCH = 8
MAX_EXAMPLES = 72


@dataclass(frozen=True)
class LedgerEntry:
    encoded: bytes
    decodes: bool


def ledger_receive_batch(
    entries: list[LedgerEntry], *, batch_budget: int, item_budget: int
) -> tuple[tuple[int, ...], int, int | None]:
    accepted: list[int] = []
    first_rejected: int | None = None
    billed = 0
    for index, entry in enumerate(entries):
        if billed >= batch_budget:
            break
        if len(entry.encoded) > item_budget:
            if first_rejected is None:
                first_rejected = index
            continue
        billed += 1
        if not entry.decodes:
            if first_rejected is None:
                first_rejected = index
            continue
        accepted.append(index)
    return tuple(accepted), billed, first_rejected


small_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-24, max_value=256),
    st.text(max_size=4),
)
small_object = st.recursive(
    st.one_of(
        st.just({}),
        st.dictionaries(st.text(max_size=3), small_scalars, max_size=3),
    ),
    lambda children: st.dictionaries(st.text(max_size=3), children, max_size=3),
    max_leaves=8,
)


@st.composite
def batch_entry(draw: st.DrawFn) -> LedgerEntry:
    encoded = dumps(draw(small_object))
    if not draw(st.booleans()):
        return LedgerEntry(encoded, True)
    if draw(st.booleans()):
        # any proper prefix of a well-formed item fails to decode
        cut = draw(st.integers(min_value=0, max_value=len(encoded) - 1))
        return LedgerEntry(encoded[:cut], False)
    return LedgerEntry(b"\xff", False)


batch_strategy = st.lists(batch_entry(), max_size=MAX_BATCH)


def interesting_item_budgets(entries: list[LedgerEntry]) -> list[int]:
    sizes = {len(entry.encoded) for entry in entries}
    candidates = {0, 1, 64}
    for size in sizes:
        candidates.update({size - 1, size, size + 1})
    return sorted(size for size in candidates if size >= 0)


@given(st.data())
@settings(max_examples=MAX_EXAMPLES, derandomize=True, deadline=None)
def test_batch_acceptance_matches_ledger(data: st.DataObject) -> None:
    entries = data.draw(batch_strategy)
    item_budget = data.draw(st.sampled_from(interesting_item_budgets(entries)))
    batch_budget = data.draw(st.integers(min_value=0, max_value=len(entries) + 1))

    result = receive_batch(
        [entry.encoded for entry in entries],
        batch_budget=batch_budget,
        item_budget=item_budget,
    )
    expected_accepted, expected_billed, expected_first_rejected = ledger_receive_batch(
        entries, batch_budget=batch_budget, item_budget=item_budget
    )

    assert result.accepted == expected_accepted
    assert result.billed == expected_billed
    assert result.first_rejected == expected_first_rejected
    assert result.billed <= min(batch_budget, len(entries))
    assert len(result.accepted) <= result.billed
    assert result.accepted == tuple(sorted(result.accepted))


def test_failed_previews_are_billed_against_the_batch_budget() -> None:
    result = receive_batch([b"\xff", b"\xff", dumps({})], batch_budget=2, item_budget=64)
    assert result.accepted == ()
    assert result.billed == 2
    assert result.first_rejected == 0


def test_oversized_items_are_rejected_without_a_billed_preview() -> None:
    result = receive_batch([dumps({"too": "big"}), dumps({})], batch_budget=1, item_budget=1)
    assert result.accepted == (1,)
    assert result.billed == 1
    assert result.first_rejected == 0


def test_first_rejected_index_distinguishes_acceptance_orders() -> None:
    items = [dumps({"ok": 1}), b"\xff", dumps({"ok": 2})]
    result = receive_batch(items, batch_budget=3, item_budget=64)
    assert result.accepted == (0, 2)
    assert result.first_rejected == 1
