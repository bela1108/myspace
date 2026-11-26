import hashlib
import os
import unittest

from elftools.elf.preservation import (
    ClaimSpec,
    LicenseView,
    NoteSelector,
    PreservationRequest,
    Provenance,
    pages_for_range,
    plan_preservation,
)


ARM = os.path.join('test', 'testfiles_for_unittests', 'arm_exidx_test.so.elf')
SAMPLE = os.path.join('examples', 'sample_exe64.elf')
SECTIONLESS = os.path.join('test', 'testfiles_for_unittests',
                           'x64_bad_sections.elf')


def arm_claims():
    return [
        ClaimSpec(
            'android-api-r21c',
            'artifact targets Android API 21 (NDK r21c)',
            NoteSelector(
                name='Android',
                type='NT_VERSION',
                desc_sha256=('95ba08e6d20e0d693961483e5bdc999b0bdd54adffc96f1'
                             '00e1e4712e8e8cad2')),
            Provenance(view='section', name='.note.android.ident')),
        ClaimSpec(
            'build-id-b02145ac',
            'delivered bytes carry build-id b02145ac',
            NoteSelector(
                name='GNU',
                type='NT_GNU_BUILD_ID',
                desc_sha256=('9c303c12bad3f4c058d9cf9527dc8ded15cd3e91df00d79f7'
                             'b1fb106332fd92b')),
            Provenance(view='section', name='.note.gnu.build-id')),
        ClaimSpec(
            'gold-linker-1.12',
            'artifact was linked by GNU gold 1.12',
            NoteSelector(
                name='GNU',
                type='NT_GNU_GOLD_VERSION',
                desc_sha256=('6d2648517bed8efb61161adf5e39f337dbf1d26cc4d1655999'
                             '4a808260dcb139')),
            Provenance(view='section', name='.note.gnu.gold-version')),
    ]


class TestPreservation(unittest.TestCase):
    def test_pages_for_range(self):
        self.assertEqual(pages_for_range(0, 1, 4096), (0,))
        self.assertEqual(pages_for_range(4095, 1, 4096), (0,))
        self.assertEqual(pages_for_range(4095, 2, 4096), (0, 1))
        self.assertEqual(pages_for_range(0, 4096, 4096), (0,))

    def test_three_claims_share_a_page_and_span_pages(self):
        plan = plan_preservation(ARM, arm_claims(), page_size=4096, budget=1)

        self.assertTrue(plan.optimal)
        self.assertTrue(plan.fully_satisfiable)
        self.assertEqual(plan.minimum_pages, (0, 597))
        self.assertEqual(plan.irreplaceable_pages, (0, 597))

        by_page = {slot.index: slot for slot in plan.page_slots}
        self.assertEqual(by_page[0].claims,
                         ('android-api-r21c', 'build-id-b02145ac'))
        self.assertEqual(by_page[597].claims, ('gold-linker-1.12',))

        self.assertEqual(plan.sole_provider[0],
                         ('android-api-r21c', 'build-id-b02145ac'))
        self.assertEqual(plan.sole_provider[597], ('gold-linker-1.12',))

        outcome = plan.budget_outcome
        self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertEqual(outcome.pages, (0,))
        self.assertEqual(outcome.kept_claims,
                         ('android-api-r21c', 'build-id-b02145ac'))
        self.assertEqual(outcome.lost_claims, ('gold-linker-1.12',))
        self.assertEqual([proof.claim_id for proof in outcome.lost_proofs],
                         ['gold-linker-1.12'])

    def test_cut_impact_reports_each_page(self):
        plan = plan_preservation(ARM, arm_claims(), page_size=4096)
        impacts = {cut.page: cut for cut in plan.cut_impacts}
        self.assertEqual(impacts[0].lost_claims,
                         ('android-api-r21c', 'build-id-b02145ac'))
        self.assertEqual(impacts[597].lost_claims, ('gold-linker-1.12',))
        self.assertEqual([proof.occurrence.offset
                          for proof in impacts[597].lost_proofs], [0x255098])

    def test_note_spanning_page_boundary_needs_every_page(self):
        claims = [
            ClaimSpec('abi', 'abi', NoteSelector(name='GNU',
                                                 type='NT_GNU_ABI_TAG'),
                      Provenance(view='section', name='.note.ABI-tag')),
            ClaimSpec('suse', 'suse', NoteSelector(name='SuSE'),
                      Provenance(view='section', name='.note.SuSE')),
            ClaimSpec('build-id', 'build-id',
                      NoteSelector(name='GNU', type='NT_GNU_BUILD_ID'),
                      Provenance(view='section', name='.note.gnu.build-id')),
        ]
        plan = plan_preservation(SAMPLE, claims, page_size=64)
        self.assertEqual(plan.minimum_pages, (9, 10))
        suse_proof = plan.proofs_by_claim['suse'][0]
        self.assertEqual(suse_proof.pages, (9, 10))
        impacts = {cut.page: cut for cut in plan.cut_impacts}
        self.assertEqual(impacts[9].lost_claims, ('abi', 'suse'))
        self.assertEqual(impacts[10].lost_claims, ('build-id', 'suse'))

    def test_identical_note_at_another_provenance_is_not_substituted(self):
        # This file has a PT_NOTE copy of the same GNU build-id note that
        # examples/sample_exe64.elf carries, but it has no section headers.
        section_claim = ClaimSpec(
            'via-section', 'must come from the section view',
            NoteSelector(name='GNU', type='NT_GNU_BUILD_ID', offset=0x28c),
            Provenance(view='section', name='.note.gnu.build-id'))
        segment_claim = ClaimSpec(
            'via-segment', 'must come from the program-header view',
            NoteSelector(name='GNU', type='NT_GNU_BUILD_ID', offset=0x28c),
            Provenance(view='segment'))
        plan = plan_preservation(SECTIONLESS, [section_claim, segment_claim],
                                 page_size=4096)
        self.assertIn('via-section', plan.unsatisfiable)
        self.assertNotIn('via-segment', plan.unsatisfiable)
        self.assertEqual(plan.minimum_pages, (0,))
        self.assertEqual(
            plan.proofs_by_claim['via-segment'][0].occurrence.view, 'segment')

    def test_license_view_can_block_a_required_page(self):
        claim = ClaimSpec(
            'gold', 'gold', NoteSelector(name='GNU',
                                         type='NT_GNU_GOLD_VERSION'),
            Provenance(view='section', name='.note.gnu.gold-version'))
        plan = plan_preservation(
            ARM, [claim], page_size=4096,
            license_view=LicenseView('page-0-only', ((0, 4096),)))
        self.assertIn('gold', plan.unsatisfiable)
        self.assertIn('project-licensed', plan.unsatisfiable['gold'])
        self.assertIsNone(plan.minimum_pages)

    def test_budget_zero_keeps_no_claim(self):
        plan = plan_preservation(ARM, arm_claims(), page_size=4096, budget=0)
        outcome = plan.budget_outcome
        self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertEqual(outcome.pages, ())
        self.assertEqual(outcome.kept_claims, ())
        self.assertEqual(len(outcome.lost_claims), 3)

    def test_plan_is_read_only(self):
        with open(ARM, 'rb') as source:
            before = hashlib.sha256(source.read()).hexdigest()
        plan_preservation(ARM, arm_claims(), page_size=4096)
        with open(ARM, 'rb') as source:
            after = hashlib.sha256(source.read()).hexdigest()
        self.assertEqual(before, after)

    def test_manifest_round_trip(self):
        request = PreservationRequest.from_json(
            os.path.join('examples', 'preservation_claims.json'))
        plan = request.plan(ARM)
        self.assertEqual([claim.id for claim in plan.claims],
                         [claim.id for claim in arm_claims()])
        self.assertEqual(plan.minimum_pages, (0, 597))

    def test_canonical_sample_has_three_claims_on_one_page(self):
        request = PreservationRequest.from_json(
            os.path.join('examples', 'preservation_claims_sample.json'))
        plan = request.plan(SAMPLE)
        self.assertEqual(plan.minimum_pages, (0,))
        self.assertEqual(plan.irreplaceable_pages, (0,))
        self.assertEqual(len(plan.page_slots), 1)
        self.assertEqual(plan.page_slots[0].claims,
                         ('build-id-8e50cda8', 'linux-abi-2.6.4',
                          'suse-note-1'))
        outcome = plan.budget_outcome
        self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertEqual(outcome.pages, ())
        self.assertEqual(len(outcome.lost_claims), 3)
        self.assertEqual(len(outcome.lost_proofs), 3)

    def test_both_section_and_segment_views_are_scanned(self):
        request = PreservationRequest.from_json(
            os.path.join('examples', 'preservation_claims_sample.json'))
        plan = request.plan(SAMPLE)
        section_occurrences = [occ for occ in plan.source.occurrences
                               if occ.view == 'section']
        segment_occurrences = [occ for occ in plan.source.occurrences
                               if occ.view == 'segment']
        self.assertEqual(len(section_occurrences), 3)
        self.assertEqual(len(segment_occurrences), 3)

        # The same build-id bytes can be proven through the program-header
        # view too; the claim decides which provenance is acceptable.
        segment_claim = ClaimSpec(
            'build-id-via-segment', 'program-header view',
            NoteSelector(name='GNU', type='NT_GNU_BUILD_ID'),
            Provenance(view='segment'))
        segment_plan = plan_preservation(SAMPLE, [segment_claim], page_size=4096)
        self.assertEqual(segment_plan.minimum_pages, (0,))
        self.assertEqual(
            segment_plan.proofs_by_claim['build-id-via-segment'][0].occurrence.view,
            'segment')

    def test_same_bytes_via_two_views_are_one_independent_proof(self):
        claim = ClaimSpec(
            'build-id-any-view', 'any view',
            NoteSelector(name='GNU', type='NT_GNU_BUILD_ID'),
            Provenance(view='any'))
        plan = plan_preservation(SAMPLE, [claim], page_size=4096, budget=0)
        candidates = plan.proofs_by_claim['build-id-any-view']
        self.assertEqual(len(candidates), 2)
        self.assertEqual(len({proof.occurrence.offset for proof in candidates}), 1)
        self.assertEqual(len(plan.page_slots[0].proofs), 1)
        outcome = plan.budget_outcome
        self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertEqual(len(outcome.lost_proofs), 1)


if __name__ == '__main__':
    unittest.main()
