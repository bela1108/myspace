"""Offline batch-intake wrapper around cbor2 for the archive service.

Public contract:
- items are processed in arrival order;
- an item whose encoded size fits the per-item budget is previewed (decoded);
- every preview is billed against the batch budget, even a failed one;
- an oversized item is rejected at intake without a preview and is not billed;
- once the batch budget is spent, the remaining items are not received at all.

Encoded items are stored as-is; no compression is applied.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from cbor2 import CBORError, loads


@dataclass(frozen=True)
class BatchResult:
    accepted: tuple[int, ...]
    billed: int
    first_rejected: int | None


def receive_batch(items: Sequence[bytes], *, batch_budget: int, item_budget: int) -> BatchResult:
    accepted: list[int] = []
    first_rejected: int | None = None
    billed = 0
    for index, item in enumerate(items):
        if billed >= batch_budget:
            break
        if len(item) > item_budget:
            if first_rejected is None:
                first_rejected = index
            continue
        billed += 1
        try:
            loads(item)
        except CBORError:
            if first_rejected is None:
                first_rejected = index
            continue
        accepted.append(index)
    return BatchResult(tuple(accepted), billed, first_rejected)
