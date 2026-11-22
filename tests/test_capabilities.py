# -*- coding: utf-8 -*-

from __future__ import absolute_import

import unittest

try:
    from unittest import mock
except ImportError:  # Python 2
    import mock

import filetype
from filetype.types import Type


class StubOne(Type):
    MIME = 'application/x-stub-one'
    EXTENSION = 'stub1'
    VERSION = 1

    def __init__(self, **kwargs):
        super(StubOne, self).__init__(
            mime=StubOne.MIME,
            extension=StubOne.EXTENSION,
            **kwargs
        )

    def match(self, buf):
        return bytes(buf[:2]) == b'S1'


class StubTwo(Type):
    MIME = 'application/x-stub-two'
    EXTENSION = 'stub2'
    VERSION = 1

    def __init__(self, **kwargs):
        super(StubTwo, self).__init__(
            mime=StubTwo.MIME,
            extension=StubTwo.EXTENSION,
            **kwargs
        )

    def match(self, buf):
        return bytes(buf[:2]) == b'S2'


class SharedAlpha(Type):
    MIME = 'application/x-shared'
    EXTENSION = 'alpha'

    def __init__(self, **kwargs):
        super(SharedAlpha, self).__init__(
            mime=SharedAlpha.MIME,
            extension=SharedAlpha.EXTENSION,
            **kwargs
        )

    def match(self, buf):
        return bytes(buf[:2]) == b'A!'


class SharedBeta(Type):
    MIME = 'application/x-shared'
    EXTENSION = 'beta'

    def __init__(self, **kwargs):
        super(SharedBeta, self).__init__(
            mime=SharedBeta.MIME,
            extension=SharedBeta.EXTENSION,
            **kwargs
        )

    def match(self, buf):
        return bytes(buf[:2]) == b'B!'


class LegacyV1(Type):
    HANDLER = 'Legacy'
    VERSION = 1
    MIME = 'application/x-legacy'
    EXTENSION = 'legacy'

    def __init__(self, **kwargs):
        super(LegacyV1, self).__init__(
            mime=LegacyV1.MIME,
            extension=LegacyV1.EXTENSION,
            **kwargs
        )

    def match(self, buf):
        return bytes(buf[:2]) == b'LG'


class LegacyV2(Type):
    HANDLER = 'Legacy'
    VERSION = 2
    MIME = 'application/x-legacy'
    EXTENSION = 'legacy'

    def __init__(self, **kwargs):
        super(LegacyV2, self).__init__(
            mime=LegacyV2.MIME,
            extension=LegacyV2.EXTENSION,
            **kwargs
        )

    def match(self, buf):
        return bytes(buf[:2]) == b'LG'


class TestCapabilityManifest(unittest.TestCase):
    def test_manifest_is_keyed_by_handler_version(self):
        manifest = filetype.capabilities([StubOne()])
        capability = manifest['StubOne@1']
        self.assertEqual(capability.handler, 'StubOne')
        self.assertEqual(capability.version, 1)
        self.assertEqual(capability.mime, 'application/x-stub-one')
        self.assertEqual(capability.extension, 'stub1')
        self.assertTrue(capability.available)
        self.assertTrue(capability.checkable)

    def test_manifest_keeps_formats_with_shared_mime(self):
        manifest = filetype.capabilities([SharedAlpha(), SharedBeta()])
        shared = manifest.by_mime['application/x-shared']
        self.assertEqual(
            sorted(cap.extension for cap in shared),
            ['alpha', 'beta']
        )
        self.assertEqual(
            len(manifest.lookup(mime='application/x-shared')),
            2
        )
        self.assertEqual(
            manifest['SharedBeta@1'].extension,
            'beta'
        )

    def test_manifest_can_mark_handler_unavailable(self):
        manifest = filetype.capabilities(
            [StubOne()],
            overrides={
                'StubOne@1': {
                    'available': False,
                    'status': 'retired',
                },
            },
        )
        capability = manifest['StubOne@1']
        self.assertFalse(capability.available)
        self.assertFalse(capability.checkable)
        self.assertEqual(capability.status, 'retired')

    def test_manifest_describes_versions(self):
        manifest = filetype.capabilities([LegacyV1(), LegacyV2()])
        self.assertIn('Legacy@1', manifest)
        self.assertIn('Legacy@2', manifest)
        self.assertEqual(manifest['Legacy@1'].version, 1)
        self.assertEqual(manifest['Legacy@2'].version, 2)


class TestAudit(unittest.TestCase):
    def test_unchanged_record_from_stored_header(self):
        manifest = filetype.capabilities([StubOne()])
        report = filetype.audit(
            [{
                'handler': 'StubOne',
                'version': 1,
                'mime': 'application/x-stub-one',
                'extension': 'stub1',
                'header': b'S1rest-of-header',
            }],
            capabilities=manifest,
        )
        result = report[0]
        self.assertEqual(result.status, 'unchanged')
        self.assertTrue(result.checkable)
        self.assertTrue(result.verified)
        self.assertFalse(result.changed)

    def test_retired_handler_is_degraded_and_uncheckable(self):
        manifest = filetype.capabilities(
            [StubOne()],
            overrides={
                'StubOne@1': {
                    'available': False,
                    'status': 'retired',
                },
            },
        )
        report = filetype.audit(
            [{
                'handler': 'StubOne',
                'version': 1,
                'mime': 'application/x-stub-one',
                'extension': 'stub1',
                'header': b'S1rest-of-header',
            }],
            capabilities=manifest,
        )
        result = report[0]
        self.assertEqual(result.status, 'degraded')
        self.assertTrue(result.degraded)
        self.assertFalse(result.checkable)
        self.assertFalse(result.available)

    def test_stale_ledger_claim_is_visible_after_retirement(self):
        manifest = filetype.capabilities(
            [StubOne()],
            overrides={
                'StubOne@1': {
                    'available': False,
                    'status': 'retired',
                },
            },
        )
        report = filetype.audit(
            [{
                'handler': 'StubOne',
                'version': 1,
                'extension': 'stub1',
                'available': True,
            }],
            capabilities=manifest,
        )
        result = report[0]
        self.assertTrue(result.claimed_checkable)
        self.assertTrue(result.stale)
        self.assertFalse(result.checkable)
        self.assertEqual(report.summary()['stale'], 1)

    def test_version_change_is_reported_without_header(self):
        manifest = filetype.capabilities([LegacyV2()])
        report = filetype.audit(
            [{
                'handler': 'Legacy',
                'version': 1,
                'mime': 'application/x-legacy',
                'extension': 'legacy',
            }],
            capabilities=manifest,
        )
        result = report[0]
        self.assertEqual(result.status, 'changed')
        self.assertTrue(result.checkable)
        self.assertFalse(result.verified)

    def test_disagreeing_generations_keep_both_evidence(self):
        manifest = filetype.capabilities([StubOne(), StubTwo()])
        report = filetype.audit(
            [{
                'handler': 'StubOne',
                'version': 1,
                'mime': 'application/x-stub-one',
                'extension': 'stub1',
                'header': b'S2rest-of-header',
                'evidence': {
                    'handler': 'StubOne',
                    'header_hex': '5332',
                },
            }],
            capabilities=manifest,
        )
        result = report[0]
        self.assertEqual(result.status, 'changed')
        self.assertEqual(result.previous['extension'], 'stub1')
        self.assertEqual(result.current['extension'], 'stub2')
        self.assertEqual(
            result.previous_evidence['handler'],
            'StubOne'
        )
        self.assertEqual(
            result.current_evidence['handler'],
            'StubTwo'
        )
        self.assertIsNotNone(result.evidence['previous'])
        self.assertIsNotNone(result.evidence['current'])

    def test_shared_mime_without_dispatch_is_ambiguous(self):
        manifest = filetype.capabilities([SharedAlpha(), SharedBeta()])
        report = filetype.audit(
            [{'mime': 'application/x-shared'}],
            capabilities=manifest,
        )
        result = report[0]
        self.assertEqual(result.status, 'ambiguous')
        self.assertTrue(result.ambiguous)
        self.assertEqual(len(result.candidates), 2)
        self.assertTrue(result.checkable)

    def test_shared_mime_with_extension_selects_one_format(self):
        manifest = filetype.capabilities([SharedAlpha(), SharedBeta()])
        report = filetype.audit(
            [{
                'mime': 'application/x-shared',
                'extension': 'beta',
            }],
            capabilities=manifest,
        )
        result = report[0]
        self.assertEqual(result.status, 'unchanged')
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].extension, 'beta')

    def test_duplicate_determination_is_not_ambiguous(self):
        class DicomA(Type):
            MIME = 'application/dicom'
            EXTENSION = 'dcm'

            def __init__(self):
                super(DicomA, self).__init__(
                    mime=DicomA.MIME,
                    extension=DicomA.EXTENSION,
                )

            def match(self, buf):
                return False

        class DicomB(DicomA):
            pass

        manifest = filetype.capabilities([DicomA(), DicomB()])
        result = filetype.audit(
            [{'extension': 'dcm'}],
            capabilities=manifest,
        )[0]
        self.assertEqual(result.status, 'unchanged')
        self.assertFalse(result.ambiguous)
        self.assertEqual(len(result.candidates), 2)

    def test_tuple_record_is_a_single_determination(self):
        manifest = filetype.capabilities([StubOne()])
        report = filetype.audit(
            ('application/x-stub-one', 'stub1'),
            capabilities=manifest,
        )
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0].status, 'unchanged')

    def test_header_may_be_a_stored_hex_sample(self):
        manifest = filetype.capabilities([StubOne()])
        result = filetype.audit(
            [{
                'mime': 'application/x-stub-one',
                'extension': 'stub1',
                'header_hex': '533172657374',
            }],
            capabilities=manifest,
        )[0]
        self.assertEqual(result.status, 'unchanged')
        self.assertTrue(result.verified)

    def test_stored_previous_and_current_keep_both_evidence(self):
        manifest = filetype.capabilities([StubOne(), StubTwo()])
        result = filetype.audit(
            [{
                'previous': {
                    'handler': 'StubOne',
                    'version': 1,
                    'mime': 'application/x-stub-one',
                    'extension': 'stub1',
                    'evidence': {
                        'handler': 'StubOne',
                        'header_hex': '5332',
                    },
                },
                'current': {
                    'handler': 'StubTwo',
                    'version': 1,
                    'mime': 'application/x-stub-two',
                    'extension': 'stub2',
                    'evidence': {
                        'handler': 'StubTwo',
                        'header_hex': '5332',
                    },
                },
            }],
            capabilities=manifest,
        )[0]
        self.assertEqual(result.status, 'changed')
        self.assertTrue(result.checkable)
        self.assertEqual(result.previous['extension'], 'stub1')
        self.assertEqual(result.current['extension'], 'stub2')
        self.assertEqual(
            result.previous_evidence['handler'], 'StubOne')
        self.assertEqual(
            result.current_evidence['handler'], 'StubTwo')

    def test_stored_current_with_retired_handler_is_degraded(self):
        manifest = filetype.capabilities(
            [StubOne(), StubTwo()],
            overrides={
                'StubTwo@1': {
                    'available': False,
                    'status': 'retired',
                },
            },
        )
        result = filetype.audit(
            [{
                'previous': {
                    'handler': 'StubOne',
                    'version': 1,
                    'mime': 'application/x-stub-one',
                    'extension': 'stub1',
                },
                'current': {
                    'handler': 'StubTwo',
                    'version': 1,
                    'mime': 'application/x-stub-two',
                    'extension': 'stub2',
                },
            }],
            capabilities=manifest,
        )[0]
        self.assertEqual(result.status, 'degraded')
        self.assertFalse(result.checkable)
        self.assertEqual(result.current['extension'], 'stub2')

    def test_incomplete_record_with_unique_mime_is_still_checkable(self):
        manifest = filetype.capabilities([StubOne()])
        report = filetype.audit(
            [{'mime': 'application/x-stub-one'}],
            capabilities=manifest,
        )
        result = report[0]
        self.assertEqual(result.status, 'unchanged')
        self.assertTrue(result.checkable)
        self.assertFalse(result.verified)

    def test_empty_record_is_invalid(self):
        report = filetype.audit([{}], capabilities=filetype.capabilities([]))
        result = report[0]
        self.assertEqual(result.status, 'invalid')
        self.assertFalse(result.checkable)

    def test_audit_never_opens_attachment_paths(self):
        manifest = filetype.capabilities([StubOne()])
        records = [{
            'handler': 'StubOne',
            'version': 1,
            'mime': 'application/x-stub-one',
            'extension': 'stub1',
            'header': '/quarantine/do-not-read.bin',
        }]
        with mock.patch(
            'builtins.open',
            side_effect=AssertionError('audit must not read attachments'),
        ):
            result = filetype.audit(
                records, capabilities=manifest)[0]
        self.assertFalse(result.verified)
        self.assertEqual(result.status, 'unchanged')

    def test_plain_mapping_manifest_supports_versions(self):
        supplied = {
            'Jpeg@2': {
                'mime': 'image/jpeg',
                'extension': 'jpg',
                'available': True,
            },
        }
        report = filetype.audit(
            [{
                'handler': 'Jpeg',
                'version': 1,
                'mime': 'image/jpeg',
                'extension': 'jpg',
            }],
            capabilities=supplied,
        )
        result = report[0]
        self.assertEqual(result.status, 'changed')
        self.assertEqual(result.candidates[0].version, 2)

    def test_report_summary_and_aliases(self):
        manifest = filetype.capabilities([StubOne()])
        report = filetype.audit(
            [
                {
                    'handler': 'StubOne',
                    'version': 1,
                    'extension': 'stub1',
                },
                {'mime': 'application/unknown'},
            ],
            capabilities=manifest,
        )
        summary = report.summary()
        self.assertEqual(summary['total'], 2)
        self.assertEqual(summary['unchanged'], 1)
        self.assertEqual(summary['unavailable'], 1)
        self.assertIs(filetype.check_impact, filetype.audit)
        self.assertIs(filetype.change_impact, filetype.audit)


if __name__ == '__main__':
    unittest.main()
