
from unittest import TestCase

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentScope
from cyclonedx.model.component_evidence import ComponentEvidence
from cyclonedx.model.license import (
    DisjunctiveLicense,
    LicenseAcknowledgement,
    LicenseExpression,
    LicensePolicy,
    decide_license_compliance,
    evaluate_license_policy,
)
from cyclonedx.model.license_decision import (
    LicenseConflictReason,
    LicenseDecisionStatus,
    LicenseEvidenceStatus,
    ReleaseScope,
)


class TestLicenseDecision(TestCase):
    def _bom(self) -> Bom:
        app = Component(
            bom_ref='app', name='app', scope=ComponentScope.REQUIRED,
            licenses=[LicenseExpression('MIT OR GPL-3.0-only', acknowledgement=LicenseAcknowledgement.DECLARED)],
        )
        devtool = Component(
            bom_ref='devtool', name='devtool', scope=ComponentScope.OPTIONAL,
            licenses=[LicenseExpression('GPL-3.0-only', acknowledgement=LicenseAcknowledgement.DECLARED)],
        )
        excluded = Component(
            bom_ref='excluded', name='excluded', scope=ComponentScope.EXCLUDED,
            licenses=[DisjunctiveLicense(name='Proprietary')],
        )
        bom = Bom()
        bom.components = [app, devtool, excluded]
        return bom

    def test_source_and_binary_scope_follow_channel(self) -> None:
        bom = self._bom()
        public = LicensePolicy(channel='public', allowed=['MIT', 'Apache-2.0'])

        binary = decide_license_compliance(bom, public, release_scope='binary')
        self.assertTrue(binary.allowed)
        self.assertEqual([ComponentScope.REQUIRED], [c.component.scope for c in binary.components])
        self.assertEqual(['MIT'], [s.atom for s in binary.selected])

        source = decide_license_compliance(bom, public, release_scope='source')
        self.assertFalse(source.allowed)
        self.assertEqual(['app', 'devtool'], [c.component.name for c in source.components])
        self.assertEqual(['devtool'], [c.component.name for c in source.denied_components])
        self.assertIn('GPL-3.0-only', source.conditions[0])

        internal = LicensePolicy(channel='internal', allowed=['MIT', 'GPL-3.0-only'])
        internal_source = internal.evaluate(bom, release_scope=ReleaseScope.SOURCE)
        self.assertTrue(internal_source.allowed)
        selected = {c.component.name: c.selected_expression for c in internal_source.components}
        self.assertEqual({'app': 'MIT', 'devtool': 'GPL-3.0-only'}, selected)

    def test_with_is_one_condition_and_and_or_keep_semantics(self) -> None:
        with_exception = Component(
            name='with-exception',
            licenses=[LicenseExpression('GPL-2.0-only WITH Classpath-exception-2.0')],
        )
        either = Component(name='either', licenses=[LicenseExpression('MIT OR Apache-2.0')])
        both = Component(name='both', licenses=[LicenseExpression('MIT AND Apache-2.0')])
        bom = Bom()
        bom.components = [with_exception, either, both]

        policy = LicensePolicy(
            channel='store',
            allowed=['MIT', 'GPL-2.0-only WITH Classpath-exception-2.0'],
            preferred_licenses=['MIT'],
        )
        decision = decide_license_compliance(bom, policy, release_scope='source')
        by_name = {c.component.name: c for c in decision.components}

        self.assertTrue(by_name['with-exception'].allowed)
        with_license = by_name['with-exception'].selected_licenses
        self.assertEqual(1, len(with_license))
        self.assertEqual('GPL-2.0-only', with_license[0].license_id)
        self.assertEqual('Classpath-exception-2.0', with_license[0].exception)
        self.assertEqual('GPL-2.0-only WITH Classpath-exception-2.0', with_license[0].atom)
        self.assertEqual(LicenseEvidenceStatus.UNSPECIFIED, with_license[0].evidence_status)

        self.assertTrue(by_name['either'].allowed)
        self.assertEqual('MIT', by_name['either'].selected_expression)
        self.assertFalse(by_name['both'].allowed)
        self.assertEqual('Apache-2.0', by_name['both'].conflicts[0].atom)
        self.assertEqual(LicenseConflictReason.LICENSE_NOT_ALLOWED, by_name['both'].conflicts[0].reason)

        other_channel = LicensePolicy(channel='other', allowed=['MIT', 'Apache-2.0'], preferred_licenses=['Apache-2.0'])
        other_decision = evaluate_license_policy(bom, other_channel, release_scope='source')
        either_other = next(c for c in other_decision.components if c.component.name == 'either')
        self.assertEqual('Apache-2.0', either_other.selected_expression)

    def test_unknown_license_and_evidence_reference_original_bom(self) -> None:
        unknown_license = DisjunctiveLicense(name='Acme-Proprietary')
        observed = ComponentEvidence(licenses=[unknown_license])
        package = Component(
            bom_ref='pkg-1', name='package',
            evidence=observed,
        )
        bom = Bom()
        bom.components = [package]
        policy = LicensePolicy(channel='public', allowed=['MIT'])
        decision = decide_license_compliance(bom, policy, release_scope='source')
        self.assertFalse(decision.allowed)
        self.assertIs(LicenseDecisionStatus.DENIED, decision.status)
        conflict = decision.conflicts[0]
        self.assertIs(package, conflict.component)
        self.assertIs(unknown_license, conflict.license)
        self.assertIs(LicenseEvidenceStatus.OBSERVED, conflict.evidence_status)
        self.assertTrue(conflict.is_unknown)
        self.assertEqual('pkg-1', decision.components[0].component.bom_ref.value)

    def test_conflicting_conditions_are_reported(self) -> None:
        bom = Bom()
        bom.components = [
            Component(name='a', licenses=[LicenseExpression('MIT AND Apache-2.0')]),
            Component(name='b', licenses=[LicenseExpression('GPL-3.0-only')]),
        ]
        policy = LicensePolicy(
            channel='public', allowed=['MIT'],
            incompatible_licenses=[('MIT', 'GPL-3.0-only')],
        )
        decision = decide_license_compliance(bom, policy, release_scope='source')
        self.assertFalse(decision.allowed)
        reasons = {conflict.reason for conflict in decision.conflicts}
        self.assertIn(LicenseConflictReason.LICENSE_NOT_ALLOWED, reasons)
        self.assertTrue(decision.conflict_groups)
        self.assertTrue(all(group.conditions for group in decision.conflict_groups))
        self.assertIn('Apache-2.0', decision.conditions[0] + decision.conditions[-1])

    def test_empty_or_unlicensed_component_is_denied(self) -> None:
        bom = Bom()
        bom.components = [Component(name='unlicensed')]
        decision = decide_license_compliance(bom, LicensePolicy(channel='x'), release_scope='source')
        self.assertFalse(decision.allowed)
        self.assertIs(LicenseConflictReason.MISSING_LICENSE, decision.conflicts[0].reason)
