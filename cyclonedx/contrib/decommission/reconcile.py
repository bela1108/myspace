# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


"""Offline reconciliation of a service decommission against CycloneDX BOMs.

The :class:`DecommissionReconciler` joins locally provided evidence
(credential claims, service usage declarations and retirement receipts) with
the services and dependency references recorded in one or more BOMs.
It is fully offline: BOMs are passed in as already deserialized
:class:`~cyclonedx.model.bom.Bom` instances.

Dependency edges follow the CycloneDX semantics where a ``Dependency(ref=A)``
with ``dependsOn=[B]`` states that *A depends on B*. For the retired
interface ``R`` this means:

* the direct callers are the refs ``A`` with an edge ``A -> R``;
* everything that (transitively) depends on such an ``A`` is a downstream
  consumer whose traffic may still reach ``R`` through a forwarding proxy;
* when service ``P`` is declared as forwarding proxy, the inbound direction
  is confirmed only once ``P`` itself and every downstream consumer routed
  via ``P`` returned a local confirmation receipt.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Optional

from ...model.bom import Bom
from .model import (
    CredentialClaim,
    ReconciliationItem,
    ReconciliationStatus,
    RetirementReceipt,
    ServiceRevision,
    ServiceUsageDeclaration,
    TrafficDirection,
    UsageRole,
)

#: mapping of a usage role to the direction under which it is reconciled
_ROLE_DIRECTION = {
    UsageRole.DIRECT_CONSUMER: TrafficDirection.OUTBOUND,
    UsageRole.FORWARDING_PROXY: TrafficDirection.INBOUND,
}


class DutyTicket:
    """Read model of the on-call ticket for the retired interface.

    The ticket exposes, as its last section, exactly which services still owe
    a consumer confirmation receipt.
    """

    def __init__(
        self, *,
        retired_ref: str,
        items: Sequence[ReconciliationItem],
    ) -> None:
        self._retired_ref = retired_ref
        # preserve the reconciliation order, drop duplicate pending services
        self._items = tuple(items)
        pending: list[str] = []
        for item in self._items:
            if item.status is ReconciliationStatus.PENDING_CONFIRMATION \
                    and item.service_ref not in pending:
                pending.append(item.service_ref)
        self._missing_receipt_refs = tuple(pending)

    @property
    def retired_ref(self) -> str:
        return self._retired_ref

    @property
    def items(self) -> tuple[ReconciliationItem, ...]:
        return self._items

    @property
    def missing_receipt_refs(self) -> tuple[str, ...]:
        """Service refs whose consumer receipt is still missing."""
        return self._missing_receipt_refs

    def render(self) -> str:
        """Render a human-readable ticket.

        The ticket always ends with the missing-receipt section, so the last
        paragraph states exactly which consumer receipts are still owed.
        """
        lines = [
            f'Decommission duty ticket for {self._retired_ref}',
            f'reconciled directions: {len(self._items)}',
            '',
        ]
        for item in self._items:
            lines.append(
                f'- {item.service_ref} [{item.role.value}/{item.direction.value}] '
                f'status={item.status.value}'
            )
            if item.credential_types:
                lines.append(
                    f'    credential types: {", ".join(item.credential_types)}'
                )
            for revision in item.revisions:
                lines.append(
                    f'    seen in BOM {revision.revision_label} '
                    f'as service version {revision.service_version or "unknown"}'
                )
        lines.extend(('', 'missing consumer receipts:'))
        if self._missing_receipt_refs:
            lines.extend(f'- {ref}' for ref in self._missing_receipt_refs)
        else:
            lines.append('- none')
        return '\n'.join(lines)

    def __repr__(self) -> str:
        return (
            f'DutyTicket(retired_ref={self._retired_ref!r}, '
            f'missing_receipt_refs={list(self._missing_receipt_refs)!r})'
        )


class DecommissionReconciler:
    """Reconcile the retirement of one interface/service.

    Args:
        retired_ref: ``bom-ref`` of the service/interface being decommissioned.
        boms: BOMs that keep service and dependency references. The same
            reference appearing in several BOMs is read per BOM revision and
            never merged.
        credential_claims: out-of-band credential category evidence.
        usage_declarations: out-of-band service usage declarations.
        receipts: locally collected consumer confirmation receipts.
    """

    def __init__(
        self, *,
        retired_ref: str,
        boms: Iterable[Bom],
        credential_claims: Iterable[CredentialClaim] = (),
        usage_declarations: Iterable[ServiceUsageDeclaration] = (),
        receipts: Iterable[RetirementReceipt] = (),
    ) -> None:
        self._retired_ref = retired_ref
        self._boms = tuple(boms)
        self._credential_claims = tuple(credential_claims)
        self._usage_declarations = tuple(usage_declarations)
        self._receipts = tuple(receipts)

    def reconcile(self) -> DutyTicket:
        """Run the offline reconciliation and build the duty ticket."""
        revisions_by_ref = self._collect_revisions()
        credentials_by_ref = self._collect_credentials()
        receipt_refs = {receipt.service_ref for receipt in self._receipts}

        # services that reach the retired interface through the dependency graph
        graph_consumers = self._collect_graph_consumers()

        items: list[ReconciliationItem] = []
        for declaration in self._ordered_declarations():
            for role, direction in self._role_directions(declaration):
                refs_needing_receipt = self._refs_for_direction(
                    role, declaration.service_ref, graph_consumers,
                )
                receipt_present = self._receipt_present(
                    declaration.service_ref, refs_needing_receipt, receipt_refs,
                )
                items.append(ReconciliationItem(
                    service_ref=declaration.service_ref,
                    service_name=self._display_name(
                        declaration.service_ref, revisions_by_ref),
                    role=role,
                    direction=direction,
                    credential_types=tuple(sorted(
                        credentials_by_ref.get(declaration.service_ref, ()))),
                    revisions=revisions_by_ref.get(
                        declaration.service_ref, ()),
                    receipt_present=receipt_present,
                ))

        return DutyTicket(retired_ref=self._retired_ref, items=items)

    # -- evidence collection ------------------------------------------------

    def _collect_revisions(self) -> dict[str, tuple[ServiceRevision, ...]]:
        revisions: dict[str, list[ServiceRevision]] = defaultdict(list)
        for bom in self._boms:
            serial = str(bom.serial_number)
            revision = bom.version
            for service in bom.services:
                ref = service.bom_ref.value
                if ref is None:
                    continue
                revisions[ref].append(ServiceRevision(
                    bom_ref=ref,
                    name=service.name,
                    service_version=service.version,
                    bom_serial=serial,
                    bom_revision=revision,
                ))
        return {ref: tuple(entries) for ref, entries in revisions.items()}

    def _collect_credentials(self) -> dict[str, frozenset[str]]:
        credentials: dict[str, set[str]] = defaultdict(set)
        for claim in self._credential_claims:
            credentials[claim.service_ref].add(claim.credential_type)
        return {ref: frozenset(types) for ref, types in credentials.items()}

    def _collect_graph_consumers(self) -> frozenset[str]:
        """Services with a dependency edge that reaches the retired ref."""
        consumers: set[str] = set()
        for bom in self._boms:
            direct = self._direct_dependents(bom)
            consumers.update(direct)
            consumers.update(self._transitive_dependents(bom, direct))
        return frozenset(consumers)

    def _direct_dependents(self, bom: Bom) -> set[str]:
        dependents: set[str] = set()
        for dependency in bom.dependencies:
            target_refs = {
                nested.ref.value for nested in dependency.dependencies
            }
            if self._retired_ref in target_refs and dependency.ref.value:
                dependents.add(dependency.ref.value)  # type: ignore[arg-type]
        return dependents

    def _transitive_dependents(self, bom: Bom, seeds: set[str]) -> set[str]:
        # build reverse edges: target -> set of dependents
        reverse: dict[str, set[str]] = defaultdict(set)
        for dependency in bom.dependencies:
            source = dependency.ref.value
            if source is None:
                continue
            for nested in dependency.dependencies:
                if nested.ref.value is not None:
                    reverse[nested.ref.value].add(source)  # type: ignore[index]
        seen: set[str] = set()
        todo = list(seeds)
        while todo:
            current = todo.pop()
            for dependent in reverse.get(current, ()):
                if dependent not in seen:
                    seen.add(dependent)
                    todo.append(dependent)
        return seen

    # -- direction handling -------------------------------------------------

    def _ordered_declarations(self) -> list[ServiceUsageDeclaration]:
        return sorted(
            self._usage_declarations,
            key=lambda declaration: declaration.service_ref,
        )

    @staticmethod
    def _role_directions(
        declaration: ServiceUsageDeclaration,
    ) -> tuple[tuple[UsageRole, TrafficDirection], ...]:
        return tuple(
            (role, _ROLE_DIRECTION[role])
            for role in sorted(declaration.roles, key=lambda role: role.value)
        )

    def _refs_for_direction(
        self,
        role: UsageRole,
        service_ref: str,
        graph_consumers: frozenset[str],
    ) -> frozenset[str]:
        # the declaring service itself always has to return a receipt
        refs = {service_ref}
        if role is UsageRole.FORWARDING_PROXY:
            # plus every service whose traffic reaches the retired interface
            # through this proxy, as recorded by the BOM dependency graphs
            refs.update(
                ref for ref in graph_consumers
                if self._reaches_interface_through(ref, service_ref)
            )
        return frozenset(refs)

    def _reaches_interface_through(self, ref: str, proxy_ref: str) -> bool:
        for bom in self._boms:
            # a caller reaches the interface through the proxy when it depends
            # (transitively) on the proxy, and the proxy itself depends on the
            # retired interface within the same BOM
            if self._depends_transitively(bom, ref, proxy_ref) \
                    and self._depends_transitively(bom, proxy_ref, self._retired_ref):
                return True
        return False

    def _depends_transitively(
        self, bom: Bom, source_ref: str, target_ref: str,
    ) -> bool:
        edges: dict[str, set[str]] = {}
        for dependency in bom.dependencies:
            source = dependency.ref.value
            if source is None:
                continue
            edges[source] = {
                nested.ref.value  # type: ignore[misc]
                for nested in dependency.dependencies
                if nested.ref.value is not None
            }
        seen: set[str] = set()
        todo = [source_ref]
        while todo:
            current = todo.pop()
            for nested in edges.get(current, ()):
                if nested == target_ref:
                    return True
                if nested not in seen:
                    seen.add(nested)
                    todo.append(nested)
        return False

    @staticmethod
    def _receipt_present(
        service_ref: str,
        refs_needing_receipt: frozenset[str],
        receipt_refs: frozenset[str],
    ) -> bool:
        # the declaring service always needs its own consumer receipt;
        # missing receipts keep the item pending confirmation
        expected = set(refs_needing_receipt)
        expected.add(service_ref)
        return expected.issubset(receipt_refs)

    @staticmethod
    def _display_name(
        service_ref: str,
        revisions_by_ref: dict[str, tuple[ServiceRevision, ...]],
    ) -> Optional[str]:
        revisions = revisions_by_ref.get(service_ref)
        if not revisions:
            return None
        return revisions[0].name
