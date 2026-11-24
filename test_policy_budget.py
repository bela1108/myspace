import unittest

from xml.sax.handler import ContentHandler

from defusedxml import ElementTree, pulldom, sax
from defusedxml.expatreader import create_parser
from defusedxml.policy import (
    BudgetPolicy,
    PolicyRejected,
    RejectionReason,
)
from defusedxml.service import XMLSegmentService, parse_segments


SYNTHETIC_DTD_XML = """<?xml version='1.0' encoding='ascii'?>
<!DOCTYPE root [
  <!ENTITY small 'abc'>
  <!ENTITY nested '&small;&small;&small;'>
  <!ENTITY picture SYSTEM 'picture.gif' NDATA gif>
]>
<root><a><b><c>&nested;</c></b></a><u unparsed='picture'/></root>
"""


def chunks(size=7):
    return [
        SYNTHETIC_DTD_XML[index : index + size]
        for index in range(0, len(SYNTHETIC_DTD_XML), size)
    ]


class BudgetPolicyTests(unittest.TestCase):
    def test_byte_and_reference_counts_survive_tiny_chunks(self):
        policy = BudgetPolicy(max_expansions=100, max_bytes=10000)
        for chunk in chunks(1):
            policy.observe_data(chunk)
        self.assertEqual(policy.bytes, len(SYNTHETIC_DTD_XML.encode("utf-8")))
        self.assertEqual(policy.entity_references, 1)

    def test_dtd_references_are_not_document_expansions(self):
        policy = BudgetPolicy()
        for chunk in chunks(3):
            policy.observe_data(chunk)
        policy.record_entity_declaration("small", 0, "abc")
        policy.record_entity_declaration("nested", 0, "&small;&small;&small;")
        self.assertEqual(policy.expansion_weight("nested"), 4)
        self.assertEqual(policy.entity_references, 1)

    def test_sax_parser_reset_keeps_document_policy(self):
        policy = BudgetPolicy(max_bytes=10)
        parser = create_parser(policy=policy, forbid_entities=False)
        self.assertIs(parser.policy, policy)
        policy.bytes = 7
        policy.expansions = 3
        parser.reset()
        self.assertIs(parser.policy, policy)
        self.assertEqual(policy.bytes, 7)
        self.assertEqual(policy.expansions, 3)


class SharedBudgetBackendTests(unittest.TestCase):
    backends = ("ElementTree", "SAX", "pulldom")

    def assertRejected(self, backend, **limits):
        policy = BudgetPolicy(**limits)
        with self.assertRaises(PolicyRejected) as context:
            parse_segments(
                SYNTHETIC_DTD_XML,
                backend=backend,
                chunk_size=5,
                policy=policy,
                forbid_entities=False,
            )
        rejection = context.exception
        self.assertEqual(rejection.backend, backend)
        return rejection

    def test_expansion_limit_is_common(self):
        for backend in self.backends:
            with self.subTest(backend=backend):
                rejection = self.assertRejected(backend, max_expansions=3)
                self.assertEqual(rejection.reason, RejectionReason.EXPANSION)
                self.assertGreaterEqual(rejection.used, 4)

    def test_depth_limit_is_common(self):
        for backend in self.backends:
            with self.subTest(backend=backend):
                rejection = self.assertRejected(backend, max_depth=3)
                self.assertEqual(rejection.reason, RejectionReason.DEPTH)
                self.assertGreaterEqual(rejection.used, 4)

    def test_byte_limit_accumulates_across_chunks(self):
        for backend in self.backends:
            with self.subTest(backend=backend):
                rejection = self.assertRejected(backend, max_bytes=20)
                self.assertEqual(rejection.reason, RejectionReason.BYTES)
                self.assertGreater(rejection.used, rejection.limit)

    def test_unparsed_entity_limit_is_common(self):
        for backend in self.backends:
            with self.subTest(backend=backend):
                rejection = self.assertRejected(backend, max_unparsed_entities=0)
                self.assertEqual(rejection.reason, RejectionReason.UNPARSED_ENTITY)
                self.assertEqual(rejection.used, 1)

    def test_backend_native_difference_is_recorded(self):
        xml = "<root>&does-not-exist;</root>"
        native_types = set()
        for backend in self.backends:
            policy = BudgetPolicy()
            with self.assertRaises(PolicyRejected) as context:
                parse_segments(
                    xml,
                    backend=backend,
                    chunk_size=3,
                    policy=policy,
                    forbid_entities=False,
                )
            rejection = context.exception
            self.assertEqual(rejection.reason, RejectionReason.BACKEND)
            self.assertTrue(rejection.native_type)
            self.assertIn(backend, rejection.controlled_reason)
            native_types.add(rejection.native_type)
        self.assertTrue(native_types)


class DirectFacadeTests(unittest.TestCase):
    def test_elementtree_fromstringlist_uses_policy(self):
        policy = BudgetPolicy(max_depth=1)
        with self.assertRaises(PolicyRejected):
            ElementTree.fromstringlist(chunks(4), policy=policy, forbid_entities=False)

    def test_sax_parse_string_uses_policy(self):
        policy = BudgetPolicy(max_unparsed_entities=0)
        with self.assertRaises(PolicyRejected):
            sax.parseString(
                SYNTHETIC_DTD_XML.encode(),
                ContentHandler(),
                policy=policy,
                forbid_entities=False,
            )

    def test_pulldom_parse_string_uses_policy(self):
        policy = BudgetPolicy(max_expansions=1)
        with self.assertRaises(PolicyRejected) as context:
            events = pulldom.parseString(
                SYNTHETIC_DTD_XML,
                policy=policy,
                forbid_entities=False,
            )
            list(events)
        self.assertEqual(context.exception.backend, "pulldom")

    def test_service_parse_all_returns_independent_fresh_policies(self):
        service = XMLSegmentService(max_depth=1)
        for backend in ("ElementTree", "SAX", "pulldom"):
            with self.assertRaises(PolicyRejected):
                service.parse(SYNTHETIC_DTD_XML, backend=backend, chunk_size=9)


if __name__ == "__main__":
    unittest.main()
