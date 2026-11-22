from unittest import TestCase

from .ledger import STATUS_PENDING
from .sanitizer import ChangeLedger, Sanitizer, sanitize_with_ledger


def policy_settings(tags):
    return {
        "tags": set(tags),
        "attributes": {},
        "empty": set(),
        "separate": {"p"},
    }


class ChangeLedgerTestCase(TestCase):
    def test_public_view_only_contains_alias_and_reason(self):
        ledger = ChangeLedger()
        sanitizer = Sanitizer(policy_settings({"p"}))
        sanitizer.sanitize(
            "<p>public <span>private note</span></p><p> </p>",
            ledger=ledger,
            policy="public-v1",
        )

        public = ledger.public_dicts()
        self.assertTrue(public)
        for record in public:
            self.assertEqual(set(record), {"alias", "reason"})
            self.assertNotIn("private note", record["reason"])
            self.assertNotIn("/html/body", record["reason"])

        internal = ledger.internal()
        self.assertTrue(internal)
        span = next(entry for entry in internal if entry.tag == "span")
        self.assertEqual(span.source_xpath, "/html/body/div/p[1]/span")
        self.assertIn("private note", span.fragment)
        self.assertIn("valid HTML", span.reason)
        self.assertIn("not approved for public output", span.reason)
        self.assertEqual(ledger.original_node(span.alias).text, "private note")

    def test_three_stages_and_pending_parse_decision(self):
        ledger = ChangeLedger()
        sanitizer = Sanitizer(policy_settings({"p", "strong"}))
        sanitizer.sanitize(
            "<p><strong>note</p><p> </p><span>legal but not public</span>",
            ledger=ledger,
        )

        stages = {entry.stage for entry in ledger.internal()}
        self.assertEqual(stages, {"parse", "structure", "policy"})

        parse_entries = [entry for entry in ledger.internal() if entry.stage == "parse"]
        self.assertTrue(parse_entries)
        self.assertTrue(all(entry.status == STATUS_PENDING for entry in parse_entries))
        self.assertIn("pending confirmation", parse_entries[0].reason)
        self.assertIn("<p><strong>note", parse_entries[0].fragment)
        self.assertTrue(ledger.pending())
        self.assertIn(
            "<p><strong>note",
            ledger.original_document(parse_entries[0].document_id),
        )

        structure_entries = [
            entry for entry in ledger.internal() if entry.stage == "structure"
        ]
        self.assertTrue(any("empty <p>" in entry.reason for entry in structure_entries))

        policy_entries = [
            entry for entry in ledger.internal() if entry.stage == "policy"
        ]
        self.assertTrue(any("tag <span>" in entry.reason for entry in policy_entries))

    def test_two_successive_policy_tightenings_do_not_repeat_a_removal(self):
        source = (
            "<p>keep <span>private note</span></p><p> </p><p><strong>bold</strong></p>"
        )
        ledger = ChangeLedger()
        first = Sanitizer(policy_settings({"p", "span", "strong"}))
        second = Sanitizer(policy_settings({"p", "strong"}))
        third = Sanitizer(policy_settings({"p"}))

        first.sanitize(source, ledger=ledger, policy="v1")
        second.sanitize(source, ledger=ledger, policy="v2")
        third.sanitize(source, ledger=ledger, policy="v3")

        removals = [
            entry for entry in ledger.internal() if entry.operation == "node-removal"
        ]
        by_alias = {entry.alias: entry for entry in removals}

        self.assertEqual(by_alias["#fragment/p[2]"].round, 1)
        self.assertEqual(by_alias["#fragment/p[1]/span[1]"].round, 2)
        self.assertEqual(by_alias["#fragment/p[3]/strong[1]"].round, 3)
        self.assertEqual(len(removals), 3)

        # Replaying the stricter passes against the same source must not create
        # a second decision for content which was already removed.
        second.sanitize(source, ledger=ledger, policy="v2")
        third.sanitize(source, ledger=ledger, policy="v3")
        self.assertEqual(len(ledger.internal()), 3)

    def test_sequential_outputs_do_not_repeat_removed_content(self):
        source = (
            "<p>keep <span>private note</span></p><p> </p><p><strong>bold</strong></p>"
        )
        ledger = ChangeLedger()
        first = Sanitizer(policy_settings({"p", "span", "strong"}))
        second = Sanitizer(policy_settings({"p", "strong"}))
        third = Sanitizer(policy_settings({"p"}))

        out = first.sanitize(source, ledger=ledger, policy="v1")
        out = second.sanitize(out, ledger=ledger, policy="v2")
        out = third.sanitize(out, ledger=ledger, policy="v3")

        self.assertEqual(out.strip(), "<p>keep private note</p> <p>bold</p>")
        removals = [
            entry for entry in ledger.internal() if entry.operation == "node-removal"
        ]
        self.assertEqual(len(removals), 3)
        self.assertEqual(
            [entry.round for entry in removals],
            [1, 2, 3],
        )

    def test_unaligned_removal_is_kept_pending(self):
        def drop_span(element):
            if element.tag == "span":
                element.drop_tree()
            return element

        ledger = ChangeLedger()
        sanitizer = Sanitizer({"element_preprocessors": [drop_span]})
        sanitizer.sanitize("<p>a<span>hidden note</span>b</p>", ledger=ledger)

        pending = ledger.pending()
        self.assertEqual(len(pending), 1)
        entry = pending[0]
        self.assertEqual(entry.status, STATUS_PENDING)
        self.assertEqual(entry.alias, "#fragment/p[1]/span[1]")
        self.assertEqual(entry.source_xpath, "/html/body/div/p/span")
        self.assertIn("hidden note", entry.fragment)
        self.assertIn("could not be aligned", entry.reason)
        self.assertIn("pending confirmation", entry.reason)

    def test_policy_reasons_do_not_leak_values_or_text(self):
        ledger = ChangeLedger()
        Sanitizer().sanitize(
            '<p class="private-class" onclick="alert(1)">'
            '<a href="javascript:alert(2)">link</a></p>',
            ledger=ledger,
        )

        public_reasons = " ".join(record["reason"] for record in ledger.public_dicts())
        self.assertNotIn("private-class", public_reasons)
        self.assertNotIn("javascript:alert", public_reasons)
        self.assertIn("attribute 'class'", public_reasons)
        self.assertIn("attribute 'onclick'", public_reasons)
        self.assertIn("link target is valid markup", public_reasons)

        internal_details = [
            entry.details for entry in ledger.internal() if entry.details
        ]
        self.assertTrue(
            any(
                details.get("old_value") == "javascript:alert(2)"
                for details in internal_details
            )
        )

    def test_change_ledger_keyword_alias(self):
        ledger = ChangeLedger()
        Sanitizer(policy_settings({"p"})).sanitize(
            "<p><span>x</span></p>", change_ledger=ledger
        )
        self.assertEqual(len(ledger), 1)
        self.assertIn("not approved", ledger.public_dicts()[0]["reason"])

    def test_sanitize_with_ledger_helper_and_json_views(self):
        result = sanitize_with_ledger(
            "<p><span>legal but not public</span></p>",
            settings=policy_settings({"p"}),
        )
        self.assertEqual(result.html, "<p>legal but not public</p>")
        self.assertEqual(result.sanitized, result.html)
        self.assertIsInstance(result.ledger, ChangeLedger)

        public_html, ledger = result
        self.assertEqual(public_html, result.html)
        self.assertEqual(len(ledger), 1)

        public_json = ledger.to_json()
        internal_json = ledger.to_json(internal=True)
        self.assertIn('"alias"', public_json)
        self.assertNotIn("source_xpath", public_json)
        self.assertIn("source_xpath", internal_json)
