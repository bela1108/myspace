from unittest import TestCase
from unittest.mock import patch

import lxml.html

from .audit import Category, ChangeDecision, ChangeLedger, Reason, Status
from .sanitizer import Sanitizer


class LedgerBasicsTestCase(TestCase):
    def test_ledger_is_optional_and_does_not_change_output(self):
        sanitizer = Sanitizer()
        fragment = '<p>Title <b>bold</b></p><script>a()</script>'
        plain = sanitizer.sanitize(fragment)
        audited, ledger = sanitizer.sanitize_with_ledger(fragment)
        self.assertEqual(plain, audited)
        self.assertIsInstance(ledger, ChangeLedger)

    def test_decisions_cover_three_categories(self):
        sanitizer = Sanitizer()
        fragment = (
            '<!-- note --><script>a()</script>'
            '<p class="x">a <b>b</b> <span></span></p>'
            '<a href="javascript:alert(1)">l</a>'
        )
        _, ledger = sanitizer.sanitize_with_ledger(fragment)
        categories = {decision.category for decision in ledger.decisions()}
        self.assertEqual(
            categories, {Category.PARSE, Category.STRUCTURE, Category.POLICY}
        )
    def test_public_view_only_exposes_alias_and_reason(self):
        sanitizer = Sanitizer()
        fragment = '<p>Secret <b>word</b></p><script>token()</script>'
        _, ledger = sanitizer.sanitize_with_ledger(fragment)
        entries = ledger.public_entries()
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual(
                set(entry), {"alias", "category", "reason"}
            )
            self.assertTrue(entry["alias"].startswith("/"))
        serialized = repr(entries)
        self.assertNotIn("Secret", serialized)
        self.assertNotIn("word", serialized)
        self.assertNotIn("token", serialized)

    def test_internal_view_resolves_alias_to_original_node(self):
        sanitizer = Sanitizer()
        _, ledger = sanitizer.sanitize_with_ledger(
            '<p>a <b>b</b></p>'
        )
        decision = next(
            d for d in ledger.decisions() if d.reason is Reason.TAG_REWRITTEN
        )
        original = ledger.original_for(decision.alias)
        self.assertIsNotNone(original)
        self.assertEqual(
            lxml.html.tostring(original, encoding="unicode"),
            "<strong>b</strong>",
        )

    def test_aliases_are_stable_structural_paths(self):
        sanitizer = Sanitizer()
        _, ledger = sanitizer.sanitize_with_ledger(
            '<p>a <b>b</b></p><p>c</p>'
        )
        aliases = {d.alias for d in ledger.decisions()}
        self.assertIn("/p[0]/b[0]", aliases)
        # no memory addresses / non-string labels leak into aliases
        for alias in aliases:
            self.assertNotIn("0x", alias)
            self.assertNotIn("cyfunction", alias)

class AuditReasonTestCase(TestCase):
    def _reasons(self, ledger):
        return {d.reason for d in ledger.decisions()}

    def test_parse_decisions(self):
        sanitizer = Sanitizer()
        _, ledger = sanitizer.sanitize_with_ledger(
            '<!-- c --><style>x</style><script>a()</script><p>x</p>'
        )
        reasons = self._reasons(ledger)
        self.assertIn(Reason.COMMENT_REMOVED, reasons)
        self.assertIn(Reason.SCRIPT_TAG_REMOVED, reasons)
        self.assertIn(Reason.STYLE_TAG_REMOVED, reasons)

    def test_parser_fallback_is_recorded(self):
        sanitizer = Sanitizer()
        with patch("lxml.html.fromstring", side_effect=ValueError("boom")):
            _, ledger = sanitizer.sanitize_with_ledger("<p>x</p>")
        self.assertIn(Reason.PARSER_FALLBACK, self._reasons(ledger))

    def test_structure_decisions(self):
        sanitizer = Sanitizer()
        _, ledger = sanitizer.sanitize_with_ledger(
            '<p><b>bold</b></p><p></p><p>a<br><br>b</p>'
        )
        reasons = self._reasons(ledger)
        self.assertIn(Reason.TAG_REWRITTEN, reasons)
        self.assertIn(Reason.EMPTY_ELEMENT_REMOVED, reasons)

    def test_policy_decisions(self):
        sanitizer = Sanitizer()
        _, ledger = sanitizer.sanitize_with_ledger(
            '<p class="x">a</p><a href="javascript:x()">l</a>'
        )
        reasons = self._reasons(ledger)
        self.assertIn(Reason.DISALLOWED_ATTRIBUTE_REMOVED, reasons)
        self.assertIn(Reason.HREF_SANITIZED, reasons)

    def test_disallowed_tag_and_embedded_host(self):
        sanitizer = Sanitizer(
            {
                "tags": {"p", "iframe"},
                "empty": {"iframe"},
                "separate": {"p", "iframe"},
                "attributes": {"iframe": {"src"}},
                "embedded_hosts": {"www.youtube.com"},
            }
        )
        _, ledger = sanitizer.sanitize_with_ledger(
            '<iframe src="https://evil.example.com/"></iframe>'
        )
        self.assertIn(Reason.EMBEDDED_HOST_NOT_ALLOWED, self._reasons(ledger))
        self.assertEqual(ledger.pending(), [])

class RepeatedTighteningTestCase(TestCase):
    DOCUMENT = (
        '<p class="secret">Keep <b>bold</b> <i>italic</i> <u>under</u>'
        ' and <strong>strong</strong></p>'
    )

    def _sanitizer(self, tags):
        return Sanitizer(
            {
                "tags": set(tags),
                "attributes": {},
                "empty": set(),
                "separate": {"p"},
            }
        )

    def test_first_pass_removals_are_not_new_decisions_in_second_pass(self):
        first = self._sanitizer({"p", "strong", "em", "b", "i"})
        output_one, ledger_one = first.sanitize_with_ledger(self.DOCUMENT)

        # Tighten the rules: strong is no longer allowed. Feed the first
        # ledger so earlier decisions are carried forward.
        second = self._sanitizer({"p", "em"})
        _, ledger_two = second.sanitize_with_ledger(
            output_one, previous=ledger_one
        )

        new_reasons = {
            d.reason for d in ledger_two.decisions(include_repeated=False)
        }
        carried = {
            d.reason
            for d in ledger_two.decisions()
            if d.status is Status.REPEATED
        }
        # The <u> removal was decided in pass one; it must not reappear as
        # a fresh decision, even though rules were tightened.
        self.assertIn(Reason.DISALLOWED_TAG_UNWRAPPED, carried)
        self.assertIn(Reason.TAG_REWRITTEN, carried)
        # Every genuinely new decision only concerns newly forbidden tags.
        self.assertTrue(
            new_reasons <= {Reason.DISALLOWED_TAG_UNWRAPPED}
        )

    def test_reprocessing_same_document_records_nothing_new(self):
        sanitizer = self._sanitizer({"p", "strong"})
        _, ledger_one = sanitizer.sanitize_with_ledger(self.DOCUMENT)
        _, ledger_two = sanitizer.sanitize_with_ledger(
            self.DOCUMENT, previous=ledger_one
        )
        self.assertEqual(
            ledger_two.decisions(include_repeated=False), []
        )
        self.assertTrue(
            all(d.status is Status.REPEATED for d in ledger_two.decisions())
        )

class PendingAndPersistenceTestCase(TestCase):
    def test_unalignable_nodes_remain_pending(self):
        # An element removed by the first cleaner for a reason the ledger
        # cannot attribute (an unknown embedded element) is kept open.
        sanitizer = Sanitizer(
            {
                "tags": {"p"},
                "attributes": {},
                "empty": set(),
                "separate": {"p"},
            }
        )
        _, ledger = sanitizer.sanitize_with_ledger(
            '<p>a<applet code="x">b</applet>c</p>'
        )
        pending = ledger.pending()
        self.assertTrue(pending)
        self.assertTrue(
            all(d.status is Status.PENDING for d in pending)
        )
        self.assertTrue(all(d.reason is Reason.UNALIGNED_NODE for d in pending))

    def test_pending_decisions_survive_into_next_ledger(self):
        sanitizer = Sanitizer(
            {
                "tags": {"p"},
                "attributes": {},
                "empty": set(),
                "separate": {"p"},
            }
        )
        _, ledger_one = sanitizer.sanitize_with_ledger(
            '<p>a<applet code="x">b</applet>c</p>'
        )
        one_pending = {d.alias for d in ledger_one.pending()}
        ledger_two = ChangeLedger(previous=ledger_one)
        # Pending items are not treated as known decisions and stay open.
        self.assertEqual(
            {d.alias for d in ledger_two.pending()}, one_pending
        )

    def test_public_export_roundtrip_suppresses_duplicates(self):
        sanitizer = Sanitizer()
        document = '<p>a <b>b</b></p><script>t()</script>'
        _, ledger = sanitizer.sanitize_with_ledger(document)
        fragments = {
            d.alias: lxml.html.tostring(d.original, encoding="unicode")
            for d in ledger.decisions()
            if d.original is not None
        }
        restored = ChangeLedger.from_public_entries(
            ledger.public_entries(), fragments=fragments
        )
        _, ledger_two = sanitizer.sanitize_with_ledger(
            document, previous=restored
        )
        self.assertEqual(
            ledger_two.decisions(include_repeated=False), []
        )

    def test_decision_is_immutable_value(self):
        decision = ChangeDecision(
            alias="/p[0]",
            category=Category.POLICY,
            reason=Reason.HREF_SANITIZED,
            fingerprint="abc",
        )
        with self.assertRaises(Exception):
            decision.alias = "/other"
