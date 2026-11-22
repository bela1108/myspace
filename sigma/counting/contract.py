"""Counting contract data model.

A counting contract is an *offline* declaration attached to a log source.  It
describes everything the correlation layer needs to decide whether a counting
operation on events from that source is deterministically de-duplicable:

* ``identity_fields``: one or more field names whose combined values uniquely
  identify a single logical operation (e.g. an audit record id).
* ``equivalences``: field mappings that are *provably equivalent* -- either a
  documented 1:1 rename or a bijective (reversible) transformation -- so that
  the same identity expressed under different field names can be compared.
* ``time_precision``: the smallest timestamp granularity the source can
  guarantee.  Two records whose timestamps only differ by less than this
  granularity cannot be proven distinct by time alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import yaml

from sigma.exceptions import SigmaError


class CountingContractError(SigmaError):
    """Raised when a counting contract declaration is malformed."""


class EquivalenceKind(str, Enum):
    """How two field names are proven equivalent."""

    RENAME = "rename"
    """The fields carry identical values under different names (1:1 rename)."""

    BIJECTIVE_TRANSFORM = "bijective_transform"
    """A named, reversible transformation maps one field value to the other."""


_TIMESPEC_RE = re.compile(r"(?P<count>[0-9]+(?:\.[0-9]+)?)(?P<unit>ms|s|m|h|d)")
_UNIT_SECONDS: dict[str, float] = {
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}


@dataclass(frozen=True)
class TimePrecision:
    """Minimum timestamp precision guaranteed by a log source.

    Expressed as a duration such as ``"500ms"`` or ``"1s"``.  Two events whose
    timestamps differ by strictly less than ``seconds`` may in fact be the same
    observation rounded differently, so time alone can never prove them
    distinct.
    """

    spec: str
    seconds: float = field(init=False)

    def __post_init__(self) -> None:
        match = _TIMESPEC_RE.fullmatch(self.spec) if isinstance(self.spec, str) else None
        if match is None:
            raise CountingContractError(
                f"Time precision '{self.spec}' is invalid; expected e.g. '500ms', '1s'."
            )
        seconds = float(match.group("count")) * _UNIT_SECONDS[match.group("unit")]
        if seconds <= 0:
            raise CountingContractError(f"Time precision '{self.spec}' must be positive.")
        object.__setattr__(self, "seconds", seconds)

    def __str__(self) -> str:
        return self.spec


@dataclass(frozen=True)
class FieldEquivalence:
    """A provably-equivalent field mapping between two field names.

    The equivalence is only *provable* for counting purposes when it is either
    a plain 1:1 rename or a transformation declared bijective (reversible).
    Non-bijective transforms (e.g. lowercasing, hashing) collapse distinct
    identities and therefore must not be accepted as identity equivalences.
    """

    fields: tuple[str, str]
    kind: EquivalenceKind = EquivalenceKind.RENAME
    transform: str | None = None
    justification: str | None = None

    def __post_init__(self) -> None:
        if len(self.fields) != 2 or self.fields[0] == self.fields[1]:
            raise CountingContractError(
                f"Field equivalence must declare two distinct fields, got {self.fields!r}."
            )
        if self.kind is EquivalenceKind.BIJECTIVE_TRANSFORM and not self.transform:
            raise CountingContractError(
                f"Bijective equivalence {self.fields!r} requires a named transform."
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FieldEquivalence:
        try:
            raw_fields = data["fields"]
            fields = (str(raw_fields[0]), str(raw_fields[1]))
        except (KeyError, TypeError, IndexError) as exc:
            raise CountingContractError(
                f"Equivalence declaration requires a 'fields' list of two names: {data!r}"
            ) from exc
        kind = EquivalenceKind(data.get("kind", "rename"))
        return cls(
            fields=fields,
            kind=kind,
            transform=data.get("transform"),
            justification=data.get("justification"),
        )

    def involves(self, field_name: str) -> bool:
        return field_name in self.fields

    def other(self, field_name: str) -> str | None:
        if field_name == self.fields[0]:
            return self.fields[1]
        if field_name == self.fields[1]:
            return self.fields[0]
        return None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"fields": list(self.fields), "kind": self.kind.value}
        if self.transform is not None:
            result["transform"] = self.transform
        if self.justification is not None:
            result["justification"] = self.justification
        return result


@dataclass(frozen=True)
class LogSourceKey:
    """Canonical identifier of a log source (any component may be ``None``)."""

    category: str | None = None
    product: str | None = None
    service: str | None = None

    def as_tuple(self) -> tuple[str | None, str | None, str | None]:
        return (self.category, self.product, self.service)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogSourceKey:
        return cls(
            category=data.get("category"),
            product=data.get("product"),
            service=data.get("service"),
        )

    def to_dict(self) -> dict[str, str]:
        return {key: value for key, value in (
            ("category", self.category),
            ("product", self.product),
            ("service", self.service),
        ) if value is not None}

    def __str__(self) -> str:
        parts = self.to_dict()
        return "/".join(f"{key}={value}" for key, value in parts.items()) or "<empty>"


@dataclass
class LogSourceCountingContract:
    """Counting contract declared for a single log source."""

    logsource: LogSourceKey
    identity_fields: tuple[str, ...]
    time_precision: TimePrecision
    equivalences: tuple[FieldEquivalence, ...] = field(default_factory=tuple)
    description: str | None = None

    def __post_init__(self) -> None:
        if not self.identity_fields:
            raise CountingContractError(
                f"Counting contract for {self.logsource} must declare at least one identity field."
            )
        if len(set(self.identity_fields)) != len(self.identity_fields):
            raise CountingContractError(
                f"Counting contract for {self.logsource} has duplicate identity fields."
            )
        self._validate_equivalence_graph()

    def _validate_equivalence_graph(self) -> None:
        """Reject equivalences that touch fields in provably-different ways.

        A single field must not be mapped to two different partner fields: such
        a graph could equate values that are not actually identical and would
        invalidate counting proofs.
        """
        partners: dict[str, str] = {}
        for equivalence in self.equivalences:
            left, right = equivalence.fields
            for field_name, candidate in ((left, right), (right, left)):
                existing = partners.get(field_name)
                if existing is not None and existing != candidate:
                    raise CountingContractError(
                        f"Field '{field_name}' has conflicting equivalence mappings "
                        f"('{existing}' and '{candidate}') in contract for {self.logsource}."
                    )
                partners[field_name] = candidate

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogSourceCountingContract:
        try:
            logsource_data = data["logsource"]
        except KeyError as exc:
            raise CountingContractError(
                f"Counting contract requires a 'logsource' section: {data!r}"
            ) from exc
        logsource = LogSourceKey.from_dict(logsource_data)
        try:
            raw_identity = data["identity_fields"]
            identity_fields = (
                tuple(raw_identity)
                if isinstance(raw_identity, list)
                else (str(raw_identity),)
            )
        except KeyError as exc:
            raise CountingContractError(
                f"Counting contract for {logsource} requires 'identity_fields'."
            ) from exc
        try:
            time_precision = TimePrecision(data["time_precision"])
        except KeyError as exc:
            raise CountingContractError(
                f"Counting contract for {logsource} requires 'time_precision'."
            ) from exc
        equivalences = tuple(
            FieldEquivalence.from_dict(item) for item in data.get("equivalences", [])
        )
        return cls(
            logsource=logsource,
            identity_fields=tuple(str(name) for name in identity_fields),
            time_precision=time_precision,
            equivalences=equivalences,
            description=data.get("description"),
        )

    def canonical_identity(self, field_name: str) -> str | None:
        """Return the canonical identity field name for an equivalent field.

        Identity fields are canonical.  A field connected to an identity field
        by a provable equivalence resolves to that identity field.  Fields
        outside the equivalence graph resolve to ``None`` -- their identity is
        not provable.
        """
        if field_name in self.identity_fields:
            return field_name
        for equivalence in self.equivalences:
            partner = equivalence.other(field_name)
            if partner is not None and partner in self.identity_fields:
                return partner
        return None

    def proves_identity(self, field_name: str) -> bool:
        return self.canonical_identity(field_name) is not None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "logsource": self.logsource.to_dict(),
            "identity_fields": list(self.identity_fields),
            "time_precision": str(self.time_precision),
        }
        if self.equivalences:
            result["equivalences"] = [item.to_dict() for item in self.equivalences]
        if self.description is not None:
            result["description"] = self.description
        return result


def contracts_from_yaml(text: str) -> list[LogSourceCountingContract]:
    """Parse one or more counting contracts from a YAML document.

    Accepts either a single mapping with a ``contracts:`` list or a plain list
    of contract mappings.
    """
    loaded = yaml.safe_load(text)
    if loaded is None:
        return []
    if isinstance(loaded, dict) and "contracts" in loaded:
        entries = loaded["contracts"]
    elif isinstance(loaded, list):
        entries = loaded
    else:
        raise CountingContractError(
            "Contract YAML must be a list of contracts or a mapping containing 'contracts'."
        )
    if not isinstance(entries, list):
        raise CountingContractError("'contracts' must be a list of contract declarations.")
    return [LogSourceCountingContract.from_dict(entry) for entry in entries]
