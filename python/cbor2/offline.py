"""Offline batch wrapper around the CBOR codec.

The wrapper models an archival service that ingests one *batch* of reviewed
materials, each material being an independently encoded CBOR object.  Three
independent budgets are enforced:

* the :attr:`BatchLimits.item_budget` caps how many materials a single batch
  may accept (the archival cap on reviewed materials);
* the :attr:`BatchLimits.size_budget` caps the encoded size of any single
  material (the per-item budget);
* the :attr:`BatchLimits.preview_budget` caps how many pre-reads the service
  may perform while scanning the batch (the preview consumption).

The wrapper is deliberately offline: it works on material already held in
memory and never applies compression or any other transport transformation.
A failed pre-read still consumes one preview unit, as required by the public
contract: pre-reads are billed regardless of whether they succeed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from ._cbor2 import CBORError
from ._cbor2 import dumps as _dumps
from ._cbor2 import loads as _loads

__all__ = [
    "BatchLimits",
    "BatchReport",
    "RejectionReason",
    "encode_material",
    "ingest_batch",
]


class RejectionReason(Enum):
    """Why a material was not accepted into the archive."""

    preview_exhausted = "preview_exhausted"
    item_too_large = "item_too_large"
    batch_full = "batch_full"
    bad_encoding = "bad_encoding"


@dataclass(frozen=True)
class BatchLimits:
    """The three budgets governing a single batch ingest.

    All budgets are non-negative.  ``item_budget`` bounds the number of
    accepted materials, ``size_budget`` bounds the encoded length of one
    material and ``preview_budget`` bounds the number of pre-reads performed.
    """

    item_budget: int
    size_budget: int
    preview_budget: int

    def __post_init__(self) -> None:
        for name, value in (
            ("item_budget", self.item_budget),
            ("size_budget", self.size_budget),
            ("preview_budget", self.preview_budget),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an int")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")


@dataclass(frozen=True)
class MaterialResult:
    """Outcome for one material at its position in the batch."""

    index: int
    accepted: bool
    reason: RejectionReason | None
    size: int
    preview_consumed: int


@dataclass(frozen=True)
class BatchReport:
    """Full, independently inspectable result of a batch ingest."""

    results: tuple[MaterialResult, ...]
    accepted_payloads: tuple[object, ...]
    accepted_count: int
    previews_used: int
    first_rejected_index: int | None


def encode_material(value: object) -> bytes:
    """Encode one reviewed material as a standalone CBOR object."""

    return _dumps(value)


def ingest_batch(materials: Sequence[bytes], limits: BatchLimits) -> BatchReport:
    """Ingest one batch of encoded materials under ``limits``.

    Every material is scanned in order.  A pre-read is attempted first and
    always consumes one unit of the preview budget, even when the bytes fail
    to decode.  Once the preview budget is exhausted no further material is
    touched.  Materials that survive the pre-read are then checked against the
    per-item size budget and finally the batch item budget, in that order.

    The function never raises for malformed material: the failure is recorded
    as :attr:`RejectionReason.bad_encoding` and billed as a consumed preview.
    """

    results: list[MaterialResult] = []
    accepted_payloads: list[object] = []
    previews_used = 0
    accepted_count = 0
    first_rejected_index: int | None = None

    for index, blob in enumerate(materials):
        size = len(blob)
        if previews_used >= limits.preview_budget:
            results.append(
                MaterialResult(
                    index=index,
                    accepted=False,
                    reason=RejectionReason.preview_exhausted,
                    size=size,
                    preview_consumed=0,
                )
            )
            if first_rejected_index is None:
                first_rejected_index = index
            continue

        previews_used += 1
        try:
            payload = _loads(blob)
        except CBORError:
            results.append(
                MaterialResult(
                    index=index,
                    accepted=False,
                    reason=RejectionReason.bad_encoding,
                    size=size,
                    preview_consumed=1,
                )
            )
            if first_rejected_index is None:
                first_rejected_index = index
            continue

        if size > limits.size_budget:
            reason = RejectionReason.item_too_large
        elif accepted_count >= limits.item_budget:
            reason = RejectionReason.batch_full
        else:
            reason = None

        if reason is None:
            accepted_payloads.append(payload)
            accepted_count += 1
        elif first_rejected_index is None:
            first_rejected_index = index

        results.append(
            MaterialResult(
                index=index,
                accepted=reason is None,
                reason=reason,
                size=size,
                preview_consumed=1,
            )
        )

    return BatchReport(
        results=tuple(results),
        accepted_payloads=tuple(accepted_payloads),
        accepted_count=accepted_count,
        previews_used=previews_used,
        first_rejected_index=first_rejected_index,
    )
