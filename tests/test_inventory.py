# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest

from asn1crypto import inventory
from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def _fixture(name):
    with open(os.path.join(fixtures_dir, name), 'rb') as f:
        return f.read()


class InventoryTests(unittest.TestCase):

    def test_pkcs12_classification_and_opaque_layer(self):
        data = _fixture('test-tripledes.p12')
        result = inventory.inventory(data)

        self.assertTrue(result.complete)
        self.assertEqual(None, result.stop_reason)
        self.assertEqual(['0'], result.roots)

        root = result.entries[0]
        self.assertEqual('pkcs12.Pfx', root.kind)
        self.assertEqual('known', root.classification)
        self.assertFalse(root.opaque)
        self.assertEqual(0, root.offset)
        self.assertEqual(len(data), root.end_offset)
        self.assertEqual(len(data), root.total_length)

        kinds = [entry.kind for entry in result.entries]
        self.assertIn('pkcs12.AuthenticatedSafe', kinds)
        self.assertIn('pkcs12.SafeContents', kinds)
        self.assertIn('pkcs12.SafeBag', kinds)
        self.assertIn('keys.EncryptedPrivateKeyInfo', kinds)
        self.assertIn('cms.EncryptedData', kinds)

        opaque = [entry for entry in result.entries if entry.opaque]
        self.assertEqual(2, len(opaque))
        self.assertEqual(set(['encrypted']), set(entry.reason for entry in opaque))
        self.assertEqual(set([False]), set(entry.openable for entry in opaque))

        # Every child points at a real parent and at a byte range inside it.
        for entry in result.entries:
            if entry.parent is None:
                continue
            parent = result.by_path[entry.parent]
            self.assertEqual(parent.path, entry.source['parent'])
            self.assertGreaterEqual(entry.offset, parent.content_offset)
            self.assertLessEqual(entry.end_offset, parent.end_offset)

    def test_cms_opaque_layers(self):
        enveloped = inventory.inventory(_fixture('cms-enveloped.der'))
        encrypted = [entry for entry in enveloped.entries if entry.opaque]
        self.assertEqual(1, len(encrypted))
        self.assertEqual('cms.encrypted_content', encrypted[0].kind)
        self.assertEqual('encrypted', encrypted[0].reason)
        self.assertTrue(encrypted[0].boundary)
        self.assertTrue(encrypted[0].sibling_continuation['possible'])

        compressed = inventory.inventory(_fixture('cms-compressed.der'))
        opaque = [entry for entry in compressed.entries if entry.opaque]
        self.assertEqual(1, len(opaque))
        self.assertEqual('cms.compressed_content', opaque[0].kind)
        self.assertEqual('compressed', opaque[0].reason)

    def test_indefinite_length_with_trailing_whitespace(self):
        result = inventory.inventory(_fixture('cms-signed-indefinite-length.der'))
        self.assertTrue(result.complete)
        self.assertEqual([], result.errors)
        self.assertEqual('cms.ContentInfo', result.entries[0].kind)
        self.assertIn('cms.SignedData', [entry.kind for entry in result.entries])

    def test_cert_bag_is_classified(self):
        result = inventory.inventory(_fixture('certbag.der'))
        kinds = [entry.kind for entry in result.entries]
        self.assertIn('pkcs12.CertBag', kinds)
        self.assertIn('x509.Certificate', kinds)
        self.assertFalse(any(entry.opaque for entry in result.entries))

    def test_mixed_cms_and_pkcs12_bundle(self):
        pfx = _fixture('test-tripledes.p12')
        cms = _fixture('cms-signed.der')
        result = inventory.inventory(pfx + cms)

        self.assertEqual(['0', '1'], result.roots)
        self.assertEqual('pkcs12.Pfx', result.by_path['0'].kind)
        self.assertEqual('cms.ContentInfo', result.by_path['1'].kind)
        self.assertEqual(len(pfx), result.by_path['1'].offset)
        self.assertEqual(len(pfx) + len(cms), result.by_path['1'].end_offset)
        self.assertTrue(result.complete)

    def test_node_budget_keeps_confirmed_parent(self):
        data = _fixture('test-tripledes.p12')
        result = inventory.inventory(data, max_nodes=1)

        self.assertEqual(1, len(result.entries))
        root = result.entries[0]
        self.assertEqual('pkcs12.Pfx', root.kind)
        self.assertEqual(0, root.offset)
        self.assertEqual(len(data), root.end_offset)
        self.assertFalse(root.complete)
        self.assertTrue(root.unvisited_children)
        self.assertTrue(root.has_unvisited_children)
        self.assertTrue(root.pending_children)
        self.assertEqual(0, root.next_child_index)
        self.assertEqual('node_budget', result.stop_reason)
        self.assertTrue(result.truncated)
        self.assertFalse(result.complete)
        self.assertIn('unvisited child items', result.stop_detail)

    def test_byte_budget_keeps_confirmed_parent(self):
        data = _fixture('test-tripledes.p12')
        result = inventory.inventory(data, max_bytes=4)

        self.assertEqual(1, len(result.entries))
        root = result.entries[0]
        self.assertEqual('pkcs12.Pfx', root.kind)
        self.assertEqual(4, result.bytes_read)
        self.assertEqual(4, root.reviewed_bytes)
        self.assertFalse(root.complete)
        self.assertTrue(root.unvisited_children)
        self.assertEqual('byte_budget', result.stop_reason)
        self.assertIn('unvisited child items', result.stop_detail)

    def test_budget_reports_independent_siblings(self):
        # SEQUENCE { INTEGER 1, INTEGER 2, INTEGER 3 }
        data = b'\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03'
        result = inventory.inventory(data, max_nodes=2)

        self.assertEqual(2, len(result.entries))
        self.assertEqual('asn1.Sequence', result.by_path['0'].kind)
        self.assertEqual('asn1.Integer', result.by_path['0.0'].kind)
        self.assertFalse(result.by_path['0'].complete)
        self.assertTrue(result.by_path['0'].has_unvisited_children)
        self.assertTrue(result.siblings_remaining)
        self.assertEqual(1, len(result.independent_siblings))
        self.assertEqual('0', result.independent_siblings[0]['parent'])
        self.assertEqual(1, result.independent_siblings[0]['next_index'])

        # A remaining top-level item is an independent sibling of the reviewed
        # root, even when the cutoff happens below the root.
        pfx = _fixture('test-tripledes.p12')
        cms = _fixture('cms-signed.der')
        mixed = inventory.inventory(pfx + cms, max_nodes=1)
        self.assertEqual(['0'], mixed.roots)
        root_siblings = [p for p in mixed.pending if p['kind'] == 'roots']
        self.assertEqual(1, len(root_siblings))
        self.assertEqual(1, root_siblings[0]['next_index'])

    def test_unreadable_child_does_not_hide_independent_sibling(self):
        # SEQUENCE { SEQUENCE { FF FF }, INTEGER 5 }
        data = b'\x30\x07\x30\x02\xff\xff\x02\x01\x05'
        result = inventory.inventory(data)

        self.assertIn('0.1', result.by_path)
        self.assertEqual('asn1.Integer', result.by_path['0.1'].kind)
        self.assertTrue(result.by_path['0.1'].complete)
        self.assertFalse(result.by_path['0.0'].complete)
        self.assertFalse(result.by_path['0'].complete)
        self.assertEqual('unreadable_child', result.by_path['0'].error)
        self.assertEqual(1, len(result.errors))
        self.assertEqual('0', result.errors[0].parent)

    def test_read_only(self):
        data = _fixture('test-tripledes.p12')
        original = bytes(data)
        inventory.inventory(data)
        inventory.inventory(data, max_nodes=1)
        self.assertEqual(original, data)

    def test_complete_inventory_has_no_unvisited_children(self):
        result = inventory.inventory(_fixture('cms-signed.der'))
        self.assertTrue(result.complete)
        self.assertFalse(result.has_unvisited_children)
        self.assertEqual([], result.incomplete)
        for entry in result.entries:
            self.assertTrue(entry.complete)
            self.assertFalse(entry.has_unvisited_children)


if __name__ == '__main__':
    unittest.main()
