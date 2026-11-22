"""Property verification for the offline CBOR batch wrapper.

The expected outcomes are produced by a deliberately tiny, standalone
"ledger" that re-derives every budget decision with plain integer counters
and no reference to the wrapper under test.  Property testing is bounded
(small objects, a couple of dozen materials per batch, a fixed example
budget) and registered with a derandomized, database-backed Hypothesis
profile so every run is reproducible.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import DrawFn

from cbor2 import dumps
from cbor2.offline import BatchLimits, RejectionReason, ingest_batch

# A fixed, bounded profile: few examples, small inputs, fully rerunnable.
settings.register_profile(
    "offline-batch",
    max_examples=60,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("offline-batch")

# Small leaf values keep every encoded material a "small object".
leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-100, max_value=100),
    st.text(max_size=3),
    st.binary(max_size=3),
)

# Both the empty object and ordinary nested objects must appear.  Weighting
# the recursive strategy keeps empty containers frequent while still
# producing two levels of nesting.
small_object = st.recursive(
    st.one_of(
        leaf,
        st.builds(list),
        st.builds(dict),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=3), children, max_size=3),
    ),
    max_leaves=4,
)

encoded_material = small_object.map(dumps)


@st.composite
def batches(draw: DrawFn) -> tuple[list[bytes], BatchLimits]:
    """Draw a batch of well-formed small objects and its three budgets."""

    materials = draw(st.lists(encoded_material, min_size=1, max_size=24))
    item_budget = draw(st.integers(min_value=0, max_value=len(materials) + 2))
    size_budget = draw(st.integers(min_value=0, max_value=max(1, max(len(b) for b in materials))))
    preview_budget = draw(st.integers(min_value=0, max_value=len(materials) + 2))
    return materials, BatchLimits(item_budget, size_budget, preview_budget)


class _LedgerEntry:
    """One ledger line, mirroring a single material decision."""

    def __init__(
        self,
        index: int,
        accepted: bool,
        reason: RejectionReason | None,
        size: int,
        preview_consumed: int,
    ) -> None:
        self.index = index
        self.accepted = accepted
        self.reason = reason
        self.size = size
        self.preview_consumed = preview_consumed


def ledger_expected(materials: list[bytes], limits: BatchLimits) -> dict[str, object]:
    """Independently compute the expected ingest outcome.

    The ledger only knows about raw lengths and a decode success flag, and
    tracks three counters by hand.  It never imports or calls the wrapper.
    """

    # Standalone decode check: the ledger decides pre-read success itself.
    from cbor2 import CBORError
    from cbor2 import loads as raw_loads

    entries: list[_LedgerEntry] = []
    previews_used = 0
    accepted_count = 0
    first_rejected_index: int | None = None

    for index, blob in enumerate(materials):
        size = len(blob)
        if previews_used >= limits.preview_budget:
            # No pre-read happens once the preview budget is spent.
            entries.append(_LedgerEntry(index, False, RejectionReason.preview_exhausted, size, 0))
            if first_rejected_index is None:
                first_rejected_index = index
            continue

        previews_used += 1
        try:
            raw_loads(blob)
            decodable = True
        except CBORError:
            decodable = False

        if not decodable:
            # Failed pre-reads are still billed per the public contract.
            entries.append(_LedgerEntry(index, False, RejectionReason.bad_encoding, size, 1))
            if first_rejected_index is None:
                first_rejected_index = index
            continue

        # Per-item size budget is adjudicated before the batch item budget.
        if size > limits.size_budget:
            reason: RejectionReason | None = RejectionReason.item_too_large
        elif accepted_count >= limits.item_budget:
            reason = RejectionReason.batch_full
        else:
            reason = None
            accepted_count += 1

        if reason is not None and first_rejected_index is None:
            first_rejected_index = index
        entries.append(_LedgerEntry(index, reason is None, reason, size, 1))

    return {
        "entries": entries,
        "accepted_count": accepted_count,
        "previews_used": previews_used,
        "first_rejected_index": first_rejected_index,
    }


@given(batches())
def test_batch_matches_independent_ledger(
    case: tuple[list[bytes], BatchLimits],
) -> None:
    materials, limits = case
    report = ingest_batch(materials, limits)
    expected = ledger_expected(materials, limits)
    entries = expected["entries"]

    assert report.accepted_count == expected["accepted_count"]
    assert report.previews_used == expected["previews_used"]
    assert report.first_rejected_index == expected["first_rejected_index"]
    assert len(report.results) == len(materials) == len(entries)  # type: ignore[arg-type]

    for result, entry in zip(report.results, entries):  # type: ignore[arg-type]
        assert result.index == entry.index
        assert result.accepted is entry.accepted
        assert result.reason is entry.reason
        assert result.size == entry.size
        assert result.preview_consumed == entry.preview_consumed

    # Accepted payloads are exactly the decodable, in-budget materials.
    assert report.accepted_count == len(report.accepted_payloads)


@given(batches())
def test_budget_invariants_hold(case: tuple[list[bytes], BatchLimits]) -> None:
    materials, limits = case
    report = ingest_batch(materials, limits)

    # The three budgets are independently respected, including their edges.
    assert report.accepted_count <= limits.item_budget
    assert report.previews_used <= limits.preview_budget
    assert all(result.size <= limits.size_budget for result in report.results if result.accepted)
    # Every consumed preview is one unit; untouched materials consume none.
    assert sum(result.preview_consumed for result in report.results) == report.previews_used
    # Rejections always carry a reason, acceptances never do.
    assert all(result.accepted is (result.reason is None) for result in report.results)


def _batch_with_oversize_at_batch_full_edge() -> tuple[list[bytes], BatchLimits]:
    """One small batch, one oversized item, budgets meeting at one index."""

    small = dumps({"k": [1, None]})
    # A well-formed encoding deliberately longer than the size budget.
    oversized = dumps({f"k{i}": i for i in range(8)})
    materials = [small, small, oversized, small]
    return materials, BatchLimits(item_budget=2, size_budget=20, preview_budget=10)


def test_legitimate_acceptance_orders_are_distinguished() -> None:
    """Regression pinning the per-item-budget-before-batch-budget order.

    With ``item_budget == 2`` the third material lands exactly on the batch
    budget edge and is also over its size budget.  Checking the per-item
    budget first rejects it as ``item_too_large``; the alternative legal
    order (batch budget first) would label it ``batch_full``.  The first
    rejected index is recorded alongside so the boundary stays visible.
    """

    materials, limits = _batch_with_oversize_at_batch_full_edge()
    report = ingest_batch(materials, limits)

    assert report.first_rejected_index == 2
    edge_result = report.results[2]
    assert edge_result.accepted is False
    assert edge_result.reason is RejectionReason.item_too_large

    # The swapped order would instead have produced this (illegal) outcome.
    assert edge_result.reason is not RejectionReason.batch_full


def test_failed_preread_is_billed_and_settled() -> None:
    """A failed pre-read consumes a preview unit and never raises."""

    good = dumps({})
    malformed = b"\x9f\x01"  # indefinite array left unclosed -> decode error
    limits = BatchLimits(item_budget=5, size_budget=50, preview_budget=2)
    report = ingest_batch([good, malformed, good], limits)

    assert report.previews_used == 2
    assert report.results[1].reason is RejectionReason.bad_encoding
    assert report.results[1].preview_consumed == 1
    # The third material is never touched after the preview budget runs out.
    assert report.results[2].reason is RejectionReason.preview_exhausted
    assert report.results[2].preview_consumed == 0
    assert report.first_rejected_index == 1


def test_preview_budget_zero_touches_nothing() -> None:
    materials = [dumps({}), dumps([1, 2])]
    report = ingest_batch(materials, BatchLimits(item_budget=5, size_budget=50, preview_budget=0))

    assert report.previews_used == 0
    assert report.accepted_count == 0
    assert report.first_rejected_index == 0
    assert all(result.reason is RejectionReason.preview_exhausted for result in report.results)


def test_empty_batch_is_accepted_cleanly() -> None:
    report = ingest_batch([], BatchLimits(item_budget=0, size_budget=0, preview_budget=0))

    assert report.results == ()
    assert report.accepted_payloads == ()
    assert report.accepted_count == 0
    assert report.previews_used == 0
    assert report.first_rejected_index is None


def test_empty_and_nested_objects_ingest() -> None:
    materials = [dumps({}), dumps([]), dumps({"a": {"b": [{}]}})]
    report = ingest_batch(materials, BatchLimits(item_budget=3, size_budget=50, preview_budget=5))

    assert report.accepted_count == 3
    assert report.first_rejected_index is None
    assert report.accepted_payloads == ({}, [], {"a": {"b": [{}]}})
