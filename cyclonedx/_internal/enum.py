
from enum import Enum


class DecisionEnum(str, Enum):
    """String enum used by non-schema policy decisions."""

    def __str__(self) -> str:
        return str(self.value)
