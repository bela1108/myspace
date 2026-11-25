from __future__ import annotations

from typing import Any


class MissingSentinel:
    """Distinct marker for a field that is absent from an event."""

    _instance: "MissingSentinel | None" = None

    def __new__(cls) -> "MissingSentinel":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING = MissingSentinel()


def read_present_field(data: dict[str, Any], field_name: str) -> tuple[bool, Any]:
    """Return field presence/value without collapsing missing into ``None``."""

    if field_name not in data:
        return False, MISSING
    return True, data[field_name]
