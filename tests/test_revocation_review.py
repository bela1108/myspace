import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from asn1crypto import cms

from revocation_review.fixtures import build_fixtures
from revocation_review.review import (
    analyze_all,
    analyze_corpus_crl,
    analyze_manifest,
    write_report,
    verify_ledger,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RevocationReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.tempdir.name)
        cls.meta = build_fixtures(cls.fixtures)
        cls.analyses = analyze_all(cls.fixtures)
        cls.out = cls.fixtures / 'out'

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def test_fixture_is_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as other:
            other_path = Path(other)
            build_fixtures(other_path)
            for name in ['revocation.crl.der', 'archive-with-crl.der', 'archive-outer-only.der']:
                self.assertEqual(
                    sha256(self.fixtures / name),
                    sha256(other_path / name),
                    name,
                )

    def test_outer_signature_verifies_over_signed_attrs(self):
        verified = self.analyses['issuance-verified']
        self.assertEqual('VALID', verified['outer']['status'])
        self.assertEqual('ed25519', verified['outer']['algorithm'])
        self.assertEqual(
            hashlib.sha256(
                cms.ContentInfo.load(
                    (self.fixtures / 'archive-with-crl.der').read_bytes()
                )['content']['signer_infos'][0]['signed_attrs'].untag().dump()
            ).hexdigest(),
            verified['outer']['signed_sha256'],
        )
        self.assertTrue(verified['outer']['message_digest_match'])

    def test_inner_signature_covers_tbs_not_whole_crl(self):
        verified = self.analyses['issuance-verified']
        self.assertEqual('VALID', verified['inner']['status'])
        objects = {obj['id']: obj for obj in verified['coverage']}
        tbs = objects['crl_tbs_cert_list']
        crl_obj = objects['crl_certificate_list']
        sig = objects['crl_signature_value']
        self.assertTrue(tbs['inner_direct'])
        self.assertFalse(crl_obj['inner_direct'])
        self.assertFalse(sig['inner_direct'])
        self.assertGreater(tbs['length'], 0)
        self.assertGreater(crl_obj['length'], tbs['length'])
        self.assertGreaterEqual(tbs['archive_span'][0], crl_obj['archive_span'][0])
        self.assertLessEqual(tbs['archive_span'][1], crl_obj['archive_span'][1])
        self.assertGreaterEqual(sig['archive_span'][0], crl_obj['archive_span'][0])
        self.assertLessEqual(sig['archive_span'][1], crl_obj['archive_span'][1])
        self.assertFalse(
            sig['archive_span'][0] >= tbs['archive_span'][0]
            and sig['archive_span'][1] <= tbs['archive_span'][1]
        )

    def test_outer_seal_covers_embedded_crl_bytes(self):
        verified = self.analyses['issuance-verified']
        self.assertEqual('VALID', verified['outer']['status'])
        objects = {obj['id']: obj for obj in verified['coverage']}
        attrs = objects['outer_signed_attrs']
        crl_obj = objects['crl_certificate_list']
        archival = objects['archival_attribute']
        self.assertTrue(crl_obj['outer_direct'])
        self.assertTrue(archival['outer_direct'])
        self.assertGreaterEqual(archival['archive_span'][0], attrs['archive_span'][0])
        self.assertLessEqual(archival['archive_span'][1], attrs['archive_span'][1])
        self.assertGreaterEqual(crl_obj['archive_span'][0], attrs['archive_span'][0])
        self.assertLessEqual(crl_obj['archive_span'][1], attrs['archive_span'][1])

    def test_outer_only_and_missing_attachment_are_distinct(self):
        outer_only = self.analyses['outer-only']
        missing = self.analyses['missing-attachment']
        outer_entry = next(e for e in outer_only['entries'] if e['id'] == 'REV-001')
        missing_entry = next(e for e in missing['entries'] if e['id'] == 'REV-001')
        self.assertEqual('outer_receipt_only', outer_only['attachment']['state'])
        self.assertEqual('missing', missing['attachment']['state'])
        self.assertEqual('T1', outer_entry['tier'])
        self.assertEqual('T1', missing_entry['tier'])
        self.assertNotEqual(outer_entry['basis'], missing_entry['basis'])
        self.assertIn('缺失', missing_entry['basis'])
        self.assertEqual([], outer_only['attachment']['declared_refs'])
        self.assertEqual(1, len(missing['attachment']['declared_refs']))
        self.assertFalse(missing['attachment']['declared_refs'][0]['exists'])

    def test_attachment_unverified_reaches_t2_but_not_t3(self):
        analysis = self.analyses['attachment-unverified']
        entry = next(e for e in analysis['entries'] if e['id'] == 'REV-001')
        self.assertEqual('present', analysis['attachment']['state'])
        self.assertTrue(analysis['attachment']['digest_match'])
        self.assertEqual('MISSING_KEY', analysis['inner']['status'])
        self.assertEqual('T2', entry['tier'])
        self.assertNotEqual('T3', entry['tier'])

    def test_tampered_outer_seal_cannot_prove_issuance(self):
        analysis = self.analyses['tampered-attachment']
        entry = next(e for e in analysis['entries'] if e['id'] == 'REV-001')
        self.assertEqual('VALID', analysis['outer']['status'])
        self.assertEqual('INVALID', analysis['inner']['status'])
        self.assertFalse(analysis['attachment']['digest_match'])
        self.assertEqual('T1', entry['tier'])

    def test_only_target_entry_upgrades_with_issuance_proof(self):
        baseline = {e['id']: e for e in self.analyses['outer-only']['entries']}
        verified = {e['id']: e for e in self.analyses['issuance-verified']['entries']}
        self.assertEqual(['REV-001'], self.analyses['issuance-verified']['changed_ids'])
        self.assertEqual('T3', verified['REV-001']['tier'])
        for entry_id, before in baseline.items():
            if entry_id == 'REV-001':
                continue
            self.assertEqual(before['tier'], verified[entry_id]['tier'], entry_id)
            self.assertEqual(before['basis'], verified[entry_id]['basis'], entry_id)

    def test_citation_lines_are_verified_offline(self):
        audit = self.analyses['issuance-verified']['citation_audit']
        self.assertTrue(audit)
        self.assertTrue(all(item['status'] == 'OK' for item in audit.values()))
        absence = self.analyses['issuance-verified']['absence_audit']
        self.assertTrue(absence)
        self.assertTrue(all(item['status'] == 'OK' for item in absence.values()))
        code_entries = [e for e in self.analyses['issuance-verified']['entries'] if e['kind'] == 'code']
        self.assertTrue(code_entries)
        self.assertTrue(all(e['tier'] == 'S1' for e in code_entries))

    def test_ledger_recheck_and_no_absolute_paths(self):
        meta = dict(self.meta)
        meta['manifests'] = {name: Path(path).name for name, path in meta['manifests'].items()}
        md_path, json_path, ledger_path = write_report(self.analyses, meta, self.out)
        self.assertEqual([], verify_ledger(ledger_path, self.fixtures))
        for path in (md_path, json_path, ledger_path):
            text = path.read_text(encoding='utf-8')
            self.assertNotIn('/Users/', text, str(path))

    def test_existing_crl_corpus_stays_missing_key(self):
        corpus = analyze_corpus_crl()
        self.assertEqual('MISSING_KEY', corpus['status'])
        self.assertFalse(corpus['issuer_key_available'])
        self.assertGreater(corpus['revoked_count'], 0)
        self.assertEqual('sha256_rsa', corpus['signature_algorithm'])


if __name__ == '__main__':
    unittest.main()
