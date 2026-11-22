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

from unittest import TestCase
from uuid import UUID

from cyclonedx.contrib.decommission import (
    CredentialClaim,
    DecommissionReconciler,
    ReconciliationStatus,
    RetirementReceipt,
    ServiceUsageDeclaration,
    TrafficDirection,
    UsageRole,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service

RETIRED_REF = 'test-service-legacy-api'
PROXY_REF = 'test-service-gateway'
DIRECT_REF = 'test-service-billing'
DOWNSTREAM_REF = 'test-service-reporting'

CRED_API_KEY = 'test-credential-api-key'
CRED_MTLS = 'test-credential-mtls'

BOM_A_SERIAL = UUID('11111111-1111-1111-1111-111111111111')
BOM_B_SERIAL = UUID('22222222-2222-2222-2222-222222222222')


def _service(ref: str, name: str, version: str) -> Service:
    return Service(name=name, bom_ref=BomRef(ref), version=version)


def _edge(source: str, targets: list[str]) -> Dependency:
    return Dependency(BomRef(source), [Dependency(BomRef(t)) for t in targets])


def _build_bom_a() -> Bom:
    # revision 1: gateway both proxies and directly consumes; billing direct;
    # reporting reaches the legacy api through the gateway
    return Bom(
        services=[
            _service(RETIRED_REF, "Test Legacy API", "1.0.0"),
            _service(PROXY_REF, "Test Gateway", "3.1.0"),
            _service(DIRECT_REF, "Test Billing", "2.0.0"),
            _service(DOWNSTREAM_REF, "Test Reporting", "0.9.0"),
        ],
        dependencies=[
            _edge(PROXY_REF, [RETIRED_REF]),
            _edge(DIRECT_REF, [RETIRED_REF]),
            _edge(DOWNSTREAM_REF, [PROXY_REF]),
        ],
        serial_number=BOM_A_SERIAL,
        version=1,
    )


def _build_bom_b() -> Bom:
    # revision 2 of the same references, with bumped service versions
    return Bom(
        services=[
            _service(RETIRED_REF, "Test Legacy API", "1.0.1"),
            _service(PROXY_REF, "Test Gateway", "3.2.0"),
            _service(DIRECT_REF, "Test Billing", "2.1.0"),
            _service(DOWNSTREAM_REF, "Test Reporting", "1.0.0"),
        ],
        dependencies=[
            _edge(PROXY_REF, [RETIRED_REF]),
            _edge(DIRECT_REF, [RETIRED_REF]),
        ],
        serial_number=BOM_B_SERIAL,
        version=2,
    )


def _claims() -> set[CredentialClaim]:
    return {
        CredentialClaim(service_ref=PROXY_REF, credential_type=CRED_API_KEY),
        CredentialClaim(service_ref=PROXY_REF, credential_type=CRED_MTLS),
        CredentialClaim(service_ref=DIRECT_REF, credential_type=CRED_API_KEY),
        CredentialClaim(service_ref=DOWNSTREAM_REF, credential_type=CRED_API_KEY),
    }


def _declarations() -> set[ServiceUsageDeclaration]:
    return {
        # gateway carries both roles and must split into two directions
        ServiceUsageDeclaration(
            service_ref=PROXY_REF,
            roles={UsageRole.FORWARDING_PROXY, UsageRole.DIRECT_CONSUMER},
        ),
        ServiceUsageDeclaration(
            service_ref=DIRECT_REF,
            roles={UsageRole.DIRECT_CONSUMER},
        ),
        ServiceUsageDeclaration(
            service_ref=DOWNSTREAM_REF,
            roles={UsageRole.DIRECT_CONSUMER},
        ),
    }


class TestDecommissionReconciler(TestCase):

    def _reconcile(self, receipts: set[RetirementReceipt]) -> object:
        return DecommissionReconciler(
            retired_ref=RETIRED_REF,
            boms=[_build_bom_a(), _build_bom_b()],
            credential_claims=_claims(),
            usage_declarations=_declarations(),
            receipts=receipts,
        ).reconcile()

    def test_dual_role_service_splits_into_two_directions(self) -> None:
        ticket = self._reconcile(set())
        gateway = [i for i in ticket.items if i.service_ref == PROXY_REF]
        self.assertEqual(2, len(gateway))
        directions = {(i.role, i.direction) for i in gateway}
        self.assertEqual({
            (UsageRole.DIRECT_CONSUMER, TrafficDirection.OUTBOUND),
            (UsageRole.FORWARDING_PROXY, TrafficDirection.INBOUND),
        }, directions)

    def test_same_ref_read_per_bom_revision(self) -> None:
        ticket = self._reconcile(set())
        gateway = next(i for i in ticket.items if i.service_ref == PROXY_REF)
        labels = sorted(r.revision_label for r in gateway.revisions)
        self.assertEqual([
            f"{BOM_A_SERIAL}/1", f"{BOM_B_SERIAL}/2",
        ], labels)
        versions = sorted(r.service_version for r in gateway.revisions)
        self.assertEqual(["3.1.0", "3.2.0"], versions)
        self.assertEqual(2, len(gateway.revisions))

    def test_missing_consumer_receipt_keeps_pending(self) -> None:
        ticket = self._reconcile(set())
        pending = {i.service_ref for i in ticket.items
                   if i.status is ReconciliationStatus.PENDING_CONFIRMATION}
        self.assertEqual({
            PROXY_REF, DIRECT_REF, DOWNSTREAM_REF,
        }, pending)
        self.assertEqual(set(), {
            i.service_ref for i in ticket.items
            if i.status is ReconciliationStatus.CONFIRMED
        })

    def test_proxy_direction_requires_downstream_receipts(self) -> None:
        # gateway proxy item stays pending until reporting also confirms;
        # its own direct-consumer item is independent and can confirm
        ticket = self._reconcile({RetirementReceipt(service_ref=PROXY_REF)})
        proxy_item = next(i for i in ticket.items
                          if i.service_ref == PROXY_REF
                          and i.direction is TrafficDirection.INBOUND)
        direct_item = next(i for i in ticket.items
                           if i.service_ref == PROXY_REF
                           and i.direction is TrafficDirection.OUTBOUND)
        self.assertEqual(ReconciliationStatus.PENDING_CONFIRMATION, proxy_item.status)
        self.assertEqual(ReconciliationStatus.CONFIRMED, direct_item.status)
        self.assertIn(DOWNSTREAM_REF, ticket.missing_receipt_refs)

    def test_all_receipts_confirm_every_direction(self) -> None:
        ticket = self._reconcile({
            RetirementReceipt(service_ref=PROXY_REF),
            RetirementReceipt(service_ref=DIRECT_REF),
            RetirementReceipt(service_ref=DOWNSTREAM_REF),
        })
        self.assertTrue(all(
            i.status is ReconciliationStatus.CONFIRMED for i in ticket.items
        ))
        self.assertEqual((), ticket.missing_receipt_refs)

    def test_ticket_render_ends_with_missing_receipt_list(self) -> None:
        ticket = self._reconcile({RetirementReceipt(service_ref=DIRECT_REF)})
        rendered = ticket.render()
        lines = rendered.splitlines()
        self.assertEqual("missing consumer receipts:", lines[-3])
        tail = set(lines[-2:])
        self.assertIn(f"- {PROXY_REF}", tail)
        self.assertIn(f"- {DOWNSTREAM_REF}", tail)
        self.assertNotIn(f"- {DIRECT_REF}", tail)
        self.assertIn(RETIRED_REF, lines[0])

    def test_no_missing_receipts_renders_none(self) -> None:
        ticket = self._reconcile({
            RetirementReceipt(service_ref=PROXY_REF),
            RetirementReceipt(service_ref=DIRECT_REF),
            RetirementReceipt(service_ref=DOWNSTREAM_REF),
        })
        self.assertEqual("- none", ticket.render().splitlines()[-1])

    def test_credential_categories_are_joined_per_service(self) -> None:
        ticket = self._reconcile(set())
        gateway = next(i for i in ticket.items if i.service_ref == PROXY_REF)
        self.assertEqual((CRED_API_KEY, CRED_MTLS), gateway.credential_types)
        billing = next(i for i in ticket.items if i.service_ref == DIRECT_REF)
        self.assertEqual((CRED_API_KEY,), billing.credential_types)

    def test_service_without_any_evidence_still_pending(self) -> None:
        bom = Bom(
            services=[_service(RETIRED_REF, "Test Legacy API", "1.0.0")],
            dependencies=[],
            serial_number=BOM_A_SERIAL,
            version=1,
        )
        ticket = DecommissionReconciler(
            retired_ref=RETIRED_REF,
            boms=[bom],
            credential_claims=set(),
            usage_declarations=set(),
            receipts=set(),
        ).reconcile()
        self.assertEqual((), ticket.items)
        self.assertEqual((), ticket.missing_receipt_refs)

    def test_proxy_downstream_read_from_graph_not_declarations(self) -> None:
        # reporting only has the edge via gateway in bom A revision 1;
        # its missing receipt must still keep the gateway proxy item pending
        ticket = self._reconcile({
            RetirementReceipt(service_ref=PROXY_REF),
            RetirementReceipt(service_ref=DIRECT_REF),
        })
        proxy_item = next(i for i in ticket.items
                          if i.service_ref == PROXY_REF
                          and i.direction is TrafficDirection.INBOUND)
        self.assertEqual(ReconciliationStatus.PENDING_CONFIRMATION, proxy_item.status)
        self.assertEqual((PROXY_REF, DOWNSTREAM_REF), ticket.missing_receipt_refs)

    def test_unknown_declared_ref_still_reconciled_without_revisions(self) -> None:
        unknown = "test-service-ghost"
        ticket = DecommissionReconciler(
            retired_ref=RETIRED_REF,
            boms=[_build_bom_a()],
            credential_claims=set(),
            usage_declarations={ServiceUsageDeclaration(
                service_ref=unknown, roles={UsageRole.DIRECT_CONSUMER})},
            receipts=set(),
        ).reconcile()
        item = next(i for i in ticket.items if i.service_ref == unknown)
        self.assertEqual((), item.revisions)
        self.assertIsNone(item.service_name)
        self.assertEqual(ReconciliationStatus.PENDING_CONFIRMATION, item.status)
        self.assertEqual((unknown,), ticket.missing_receipt_refs)
