"""Registry of counting contracts keyed by log source.

The registry resolves the counting contract applicable to a given Sigma rule
from the rule's log source.  A less specific contract (fewer log source
components) applies to more specific sources, mirroring Sigma's log source
containment semantics.
"""

from __future__ import annotations

from pathlib import Path

from sigma.counting.contract import (
    LogSourceCountingContract,
    LogSourceKey,
    contracts_from_yaml,
)
from sigma.rule.logsource import SigmaLogSource


class CountingContractRegistry:
    """Holds counting contracts and resolves them against Sigma log sources."""

    def __init__(self, contracts: list[LogSourceCountingContract] | None = None) -> None:
        self._contracts: list[LogSourceCountingContract] = list(contracts or [])
        self._index: dict[tuple[str | None, str | None, str | None], LogSourceCountingContract] = {
            contract.logsource.as_tuple(): contract for contract in self._contracts
        }

    @classmethod
    def from_yaml(cls, text: str) -> CountingContractRegistry:
        return cls(contracts_from_yaml(text))

    @classmethod
    def from_file(cls, path: str | Path) -> CountingContractRegistry:
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))

    def add(self, contract: LogSourceCountingContract) -> None:
        key = contract.logsource.as_tuple()
        if key not in self._index:
            self._contracts.append(contract)
        self._index[key] = contract

    def __len__(self) -> int:
        return len(self._contracts)

    def __iter__(self):
        return iter(self._contracts)

    def lookup(self, logsource: SigmaLogSource | LogSourceKey) -> LogSourceCountingContract | None:
        """Return the most specific contract matching ``logsource``.

        A contract matches when every component it declares equals the
        corresponding log source component (undeclared components act as
        wildcards).  Among matching contracts the one declaring the most
        components wins.
        """
        if isinstance(logsource, SigmaLogSource):
            target = (logsource.category, logsource.product, logsource.service)
        else:
            target = logsource.as_tuple()

        best: LogSourceCountingContract | None = None
        best_specificity = -1
        for contract in self._contracts:
            candidate = contract.logsource.as_tuple()
            if all(
                component is None or component == target[index]
                for index, component in enumerate(candidate)
            ):
                specificity = sum(component is not None for component in candidate)
                if specificity > best_specificity:
                    best = contract
                    best_specificity = specificity
        return best

    def require(self, logsource: SigmaLogSource | LogSourceKey) -> LogSourceCountingContract:
        """Like :meth:`lookup` but raises when no contract is registered."""
        contract = self.lookup(logsource)
        if contract is None:
            key = logsource if isinstance(logsource, LogSourceKey) else LogSourceKey(
                category=logsource.category,
                product=logsource.product,
                service=logsource.service,
            )
            raise KeyError(f"No counting contract registered for log source {key}.")
        return contract
