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

from cyclonedx.model.bom import Bom
from cyclonedx.model.service import Service
from cyclonedx.retirement import (
    ConfirmationReceipt,
    ConsumerRole,
    CredentialClass,
    DutyTicket,
    FlowDirection,
    ReconciliationStatus,
    RetirementReconciler,
    UsageClaim,
    UsageDeclaration,
)

# Revision labels and service/credential names in this test are intentionally
# plain test names, as requested.
REV_A = 'revision-alpha'
REV_B = 'revision-beta'
CRED_API_KEY = 'test-credential-api-key'
CRED_MTLS = 'test-credential-mtls'
SHARED_REF = 'shared-service-ref'


def _bom(revision: str, services: list[Service]) -> Bom:
    return Bom(version=1, services=services)


def _revisions() -> dict[str, Bom]:
    # The same bom-ref appears in both BOMs but identifies a different service
    # name per revision; the reconciler must always read it per revision.
    return {
        REV_A: _bom(REV_A, [
            Service(name='test-retired-interface', bom_ref='retired-interface-ref'),
            Service(name='test-forwarder-alpha', bom_ref='forwarder-ref'),
            Service(name='test-consumer-alpha', bom_ref='consumer-ref'),
            Service(name='test-shared-service-alpha', bom_ref=SHARED_REF),
        ]),
        REV_B: _bom(REV_B, [
            Service(name='test-retired-interface', bom_ref='retired-interface-ref'),
            Service(name='test-shared-service-beta', bom_ref=SHARED_REF),
        ]),
    }


def _credentials() -> list[CredentialClass]:
    return [
        CredentialClass(name=CRED_API_KEY, description='test api key'),
        CredentialClass(name=CRED_MTLS, description='test mTLS cert'),
    ]


class TestRetirementReconciler(TestCase):

    def test_direct_consumer_with_receipt_is_confirmed(self) -> None:
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[
                ConfirmationReceipt(
                    bom_ref='consumer-ref',
                    credential_name=CRED_API_KEY,
                    bom_revision=REV_A,
                ),
            ],
        )
        declaration = UsageDeclaration(
            bom_ref='consumer-ref',
            role=ConsumerRole.DIRECT_CONSUMER,
            direction=FlowDirection.OUTBOUND,
            credential_name=CRED_API_KEY,
            bom_revision=REV_A,
        )

        report = reconciler.reconcile([declaration])

        self.assertEqual(1, len(report.lines))
        line = report.lines[0]
        self.assertEqual(ReconciliationStatus.CONFIRMED, line.status)
        self.assertEqual('test-consumer-alpha', line.service_name)
        self.assertFalse(line.is_pending)
        self.assertEqual(0, len(report.pending_lines))

    def test_missing_consumer_receipt_stays_pending(self) -> None:
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[],
        )
        declaration = UsageDeclaration(
            bom_ref='consumer-ref',
            role=ConsumerRole.DIRECT_CONSUMER,
            direction=FlowDirection.OUTBOUND,
            credential_name=CRED_API_KEY,
            bom_revision=REV_A,
        )

        report = reconciler.reconcile([declaration])

        line = report.lines[0]
        self.assertEqual(
            ReconciliationStatus.PENDING_CONFIRMATION, line.status,
        )
        self.assertTrue(line.is_pending)
        self.assertIsNone(line.receipt)
        self.assertIn('test-consumer-alpha', line.missing_reason or '')

    def test_dual_role_service_is_split_per_direction(self) -> None:
        claims = [
            UsageClaim(
                bom_ref='forwarder-ref',
                credential_name=CRED_MTLS,
                bom_revision=REV_A,
                roles=(
                    ConsumerRole.PROXY,
                    ConsumerRole.DIRECT_CONSUMER,
                ),
            ),
        ]

        declarations = RetirementReconciler.expand_claims(claims)

        self.assertEqual(3, len(declarations))
        legs = {(d.role, d.direction) for d in declarations}
        self.assertEqual({
            (ConsumerRole.PROXY, FlowDirection.INBOUND),
            (ConsumerRole.PROXY, FlowDirection.OUTBOUND),
            (ConsumerRole.DIRECT_CONSUMER, FlowDirection.OUTBOUND),
        }, legs)
        for declaration in declarations:
            self.assertEqual('forwarder-ref', declaration.bom_ref)
            self.assertEqual(REV_A, declaration.bom_revision)

    def test_proxy_needs_one_receipt_per_direction(self) -> None:
        claims = [
            UsageClaim(
                bom_ref='forwarder-ref',
                credential_name=CRED_MTLS,
                bom_revision=REV_A,
                roles=(ConsumerRole.PROXY,),
            ),
        ]
        declarations = RetirementReconciler.expand_claims(claims)
        # Only the outbound leg has a receipt; the inbound leg stays pending.
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[
                ConfirmationReceipt(
                    bom_ref='forwarder-ref',
                    credential_name=CRED_MTLS,
                    bom_revision=REV_A,
                    direction=FlowDirection.OUTBOUND,
                ),
            ],
        )

        report = reconciler.reconcile(declarations)

        statuses = {
            line.declaration.direction: line.status for line in report.lines
        }
        self.assertEqual(
            ReconciliationStatus.CONFIRMED, statuses[FlowDirection.OUTBOUND],
        )
        self.assertEqual(
            ReconciliationStatus.PENDING_CONFIRMATION,
            statuses[FlowDirection.INBOUND],
        )

    def test_generic_receipt_covers_any_direction(self) -> None:
        declarations = RetirementReconciler.expand_claims([
            UsageClaim(
                bom_ref='forwarder-ref',
                credential_name=CRED_API_KEY,
                bom_revision=REV_A,
                roles=(ConsumerRole.PROXY,),
            ),
        ])
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[
                ConfirmationReceipt(
                    bom_ref='forwarder-ref',
                    credential_name=CRED_API_KEY,
                    bom_revision=REV_A,
                ),
            ],
        )

        report = reconciler.reconcile(declarations)

        self.assertTrue(all(
            line.status is ReconciliationStatus.CONFIRMED
            for line in report.lines
        ))

    def test_same_ref_across_two_boms_is_read_per_revision(self) -> None:
        # Same bom-ref, different revision: names differ and receipts are
        # scoped per revision, so a receipt under REV_A must not satisfy REV_B.
        declarations = [
            UsageDeclaration(
                bom_ref=SHARED_REF,
                role=ConsumerRole.DIRECT_CONSUMER,
                direction=FlowDirection.OUTBOUND,
                credential_name=CRED_API_KEY,
                bom_revision=REV_A,
            ),
            UsageDeclaration(
                bom_ref=SHARED_REF,
                role=ConsumerRole.DIRECT_CONSUMER,
                direction=FlowDirection.OUTBOUND,
                credential_name=CRED_API_KEY,
                bom_revision=REV_B,
            ),
        ]
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[
                ConfirmationReceipt(
                    bom_ref=SHARED_REF,
                    credential_name=CRED_API_KEY,
                    bom_revision=REV_A,
                ),
            ],
        )

        report = reconciler.reconcile(declarations)

        by_revision = {
            line.declaration.bom_revision: line for line in report.lines
        }
        self.assertEqual(
            'test-shared-service-alpha',
            by_revision[REV_A].service_name,
        )
        self.assertEqual(
            'test-shared-service-beta',
            by_revision[REV_B].service_name,
        )
        self.assertEqual(
            ReconciliationStatus.CONFIRMED,
            by_revision[REV_A].status,
        )
        self.assertEqual(
            ReconciliationStatus.PENDING_CONFIRMATION,
            by_revision[REV_B].status,
        )

    def test_unknown_credential_and_unknown_service(self) -> None:
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[],
        )
        declarations = [
            UsageDeclaration(
                bom_ref='consumer-ref',
                role=ConsumerRole.DIRECT_CONSUMER,
                direction=FlowDirection.OUTBOUND,
                credential_name='not-a-registered-credential',
                bom_revision=REV_A,
            ),
            UsageDeclaration(
                bom_ref='missing-service-ref',
                role=ConsumerRole.DIRECT_CONSUMER,
                direction=FlowDirection.OUTBOUND,
                credential_name=CRED_API_KEY,
                bom_revision=REV_A,
            ),
        ]

        report = reconciler.reconcile(declarations)
        statuses = {
            line.declaration.bom_ref: line for line in report.lines
        }
        self.assertEqual(
            ReconciliationStatus.UNKNOWN_CREDENTIAL,
            statuses['consumer-ref'].status,
        )
        self.assertEqual(
            ReconciliationStatus.UNKNOWN_SERVICE,
            statuses['missing-service-ref'].status,
        )
        self.assertEqual(
            'missing-service-ref',
            statuses['missing-service-ref'].service_name,
        )


class TestDutyTicket(TestCase):

    def _report(self) -> tuple[RetirementReconciler, list[UsageDeclaration]]:
        claims = [
            # forwarder: proxy, only outbound receipt -> inbound pending
            UsageClaim(
                bom_ref='forwarder-ref',
                credential_name=CRED_MTLS,
                bom_revision=REV_A,
                roles=(ConsumerRole.PROXY,),
            ),
            # direct consumer with receipt -> confirmed
            UsageClaim(
                bom_ref='consumer-ref',
                credential_name=CRED_API_KEY,
                bom_revision=REV_A,
                roles=(ConsumerRole.DIRECT_CONSUMER,),
            ),
        ]
        declarations = RetirementReconciler.expand_claims(claims)
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[
                ConfirmationReceipt(
                    bom_ref='forwarder-ref',
                    credential_name=CRED_MTLS,
                    bom_revision=REV_A,
                    direction=FlowDirection.OUTBOUND,
                ),
                ConfirmationReceipt(
                    bom_ref='consumer-ref',
                    credential_name=CRED_API_KEY,
                    bom_revision=REV_A,
                ),
            ],
        )
        return reconciler, declarations

    def test_last_section_lists_who_is_missing(self) -> None:
        reconciler, declarations = self._report()
        report = reconciler.reconcile(declarations)
        ticket = DutyTicket('test-legacy-order-api', report)

        rendered = ticket.render()
        rendered_lines = rendered.splitlines()

        self.assertEqual('Missing receipts:', rendered_lines[-2])
        last_line = rendered_lines[-1]
        self.assertIn('test-forwarder-alpha', last_line)
        self.assertIn('proxy/inbound', last_line)
        self.assertIn(CRED_MTLS, last_line)
        self.assertEqual(1, len(ticket.missing_receipts))
        self.assertFalse(ticket.is_complete)

    def test_ticket_reports_none_when_all_confirmed(self) -> None:
        claims = [
            UsageClaim(
                bom_ref='consumer-ref',
                credential_name=CRED_API_KEY,
                bom_revision=REV_A,
                roles=(ConsumerRole.DIRECT_CONSUMER,),
            ),
        ]
        declarations = RetirementReconciler.expand_claims(claims)
        reconciler = RetirementReconciler(
            boms=_revisions(),
            credentials=_credentials(),
            receipts=[
                ConfirmationReceipt(
                    bom_ref='consumer-ref',
                    credential_name=CRED_API_KEY,
                    bom_revision=REV_A,
                ),
            ],
        )
        ticket = DutyTicket('test-legacy-order-api', reconciler.reconcile(declarations))

        self.assertTrue(ticket.is_complete)
        self.assertEqual(0, len(ticket.missing_receipts))
        self.assertTrue(ticket.render().endswith(
            '- none, every consumer confirmed retirement',
        ))
        self.assertEqual(
            {'confirmed': 1}, ticket.status_summary,
        )

    def test_str_renders_ticket(self) -> None:
        reconciler, declarations = self._report()
        ticket = DutyTicket('test-legacy-order-api', reconciler.reconcile(declarations))
        self.assertEqual(ticket.render(), str(ticket))
