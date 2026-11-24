"""Transactional callback chain regression tests.

The scenario mirrors protected, system generated compliance/course clauses
living next to ordinary body cleaning extensions.  A body extension must not
rewrite those clauses, and a failed chain must never expose a half cleaned
tree to its owner.
"""

import unittest

import lxml.html

from .sanitizer import Sanitizer
from .transactions import (
    CallbackChain,
    CallbackExecutionError,
    CallbackTransaction,
    CapabilityViolation,
    NodeScope,
    ScopedCallback,
    ScopeViolation,
    Snapshot,
    TransactionViolation,
    run_callback_chain,
    scoped,
)


DOCUMENT = """
<article data-doc="course-agreement">
  <section class="compliance" data-part="compliance">
    <p class="system-note" data-system="formatter">
      系统生成段落，只能由指定格式化器维护
    </p>
    <p class="clause" data-role="course-clause">
      课程条款：开课后七日内可退
    </p>
  </section>
  <section class="lesson-body" data-part="body">
    <p class="lesson" data-role="lesson">正文第一段</p>
  </section>
</article>
"""


def parse_document():
    return lxml.html.fromstring("<div>%s</div>" % DOCUMENT)


def clause_node(root):
    return root.xpath('//*[@data-role="course-clause"]')[0]


def lesson_node(root):
    return root.xpath('//*[@data-role="lesson"]')[0]


def body_section(root):
    return root.xpath('//*[@data-part="body"]')[0]


body_scope = lambda node: (  # noqa: E731
    node.get("data-part") == "body" or node.get("data-role") == "lesson"
)


class CallbackTransactionRegressionTest(unittest.TestCase):
    def test_middle_extension_touching_unscoped_clause_leaves_no_half_tree(self):
        root = parse_document()
        original_html = lxml.html.tostring(root, encoding="unicode")
        seen_by_external_reader = []
        ran = []

        def first_extension(element, context):
            ran.append("first")
            lesson_node(context.root).text = "第一段已清洗"
            # The composition is not committed yet, so the committed/external
            # view must still be the pristine tree.
            seen_by_external_reader.append(context.read_committed())

        def middle_extension(element, context):
            ran.append("middle")
            clause_node(context.root).text = "正文扩展顺手改掉了课程条款"

        def last_extension(element, context):
            ran.append("last")

        transaction = CallbackTransaction(
            root,
            [
                ScopedCallback(first_extension, scope=body_scope, name="first_body"),
                ScopedCallback(middle_extension, scope=body_scope, name="bad_middle"),
                ScopedCallback(last_extension, scope=body_scope, name="last_body"),
            ],
        )

        with self.assertRaises(ScopeViolation) as caught:
            transaction.run()

        error = caught.exception
        self.assertIsInstance(error, TransactionViolation)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(["first", "middle"], ran)

        self.assertTrue(error.violations)
        self.assertEqual(
            ["scope_violation"], [violation.code for violation in error.violations]
        )
        violation = error.violations[0]
        self.assertEqual("bad_middle", violation.callback_name)
        self.assertEqual("course-clause", violation.node.get("data-role"))
        self.assertEqual("text", violation.change.kind)

        self.assertIsNotNone(error.report)
        self.assertTrue(error.report.scope_violations)
        self.assertIn("bad_middle", error.report.summary())

        # The caller owned tree was never published a half composition.
        self.assertEqual(original_html, lxml.html.tostring(root, encoding="unicode"))
        self.assertNotIn("第一段已清洗", original_html)
        self.assertNotIn("第一段已清洗", lxml.html.tostring(root, encoding="unicode"))

        # The external committed view is still the original snapshot.
        self.assertEqual(original_html, transaction.read_html())
        self.assertEqual(original_html, seen_by_external_reader[0])
        self.assertEqual(CallbackTransaction.STATUS_ROLLED_BACK, transaction.status)

    def test_successful_chain_commits_everything_together(self):
        root = parse_document()

        def first_extension(element, context):
            lesson_node(context.root).set("data-clean", "yes")

        def second_extension(element, context):
            lesson_node(context.root).text = "正文已清洗"

        transaction = CallbackTransaction(
            root,
            [
                ScopedCallback(
                    first_extension,
                    scope=body_scope,
                    capabilities={"attributes"},
                    name="attr_ext",
                ),
                ScopedCallback(
                    second_extension,
                    scope=body_scope,
                    capabilities={"text"},
                    name="text_ext",
                ),
            ],
        )
        transaction.run()
        self.assertEqual(CallbackTransaction.STATUS_COMPOSED, transaction.status)

        # Nothing visible to the owner before commit.
        self.assertIsNone(lesson_node(root).get("data-clean"))

        committed_root = transaction.commit()
        self.assertIs(committed_root, root)
        self.assertEqual("yes", lesson_node(root).get("data-clean"))
        self.assertEqual("正文已清洗", lesson_node(root).text)
        self.assertEqual(CallbackTransaction.STATUS_COMMITTED, transaction.status)
        self.assertIn("正文已清洗", transaction.read_html())

    def test_context_snapshot_is_explicit_and_isolated(self):
        root = parse_document()
        snapshots = []

        def extension(element, context):
            snapshots.append(context.snapshot)
            self.assertIsInstance(context.snapshot, Snapshot)
            self.assertIn("正文第一段", context.snapshot.html)
            lesson_node(context.root).text = "working change"
            # The handed out snapshot is a frozen deep copy.
            self.assertIn("正文第一段", context.snapshot.html)
            context.snapshot.root.set("data-mutated-snapshot", "1")

        CallbackTransaction(root, [ScopedCallback(extension, scope=body_scope)]).run(
            commit=True
        )

        self.assertNotIn("data-mutated-snapshot", root.attrib)
        self.assertNotIn("working change", snapshots[0].html)
        self.assertIn("working change", lxml.html.tostring(root, encoding="unicode"))

    def test_moving_unscoped_node_is_rejected(self):
        root = parse_document()

        def move_clause(element, context):
            target = body_section(context.root)
            target.append(clause_node(context.root))

        transaction = CallbackTransaction(
            root, [ScopedCallback(move_clause, scope=body_scope, name="mover")]
        )
        with self.assertRaises(ScopeViolation) as caught:
            transaction.run()
        self.assertEqual("move", caught.exception.violations[0].change.kind)
        self.assertEqual(
            parse_document()
            .xpath("//*[@data-role='course-clause']/..")[0]
            .get("data-part"),
            "compliance",
        )
        self.assertEqual(
            lxml.html.tostring(parse_document(), encoding="unicode"),
            transaction.read_html(),
        )

    def test_moving_scoped_node_outside_scope_is_rejected(self):
        root = parse_document()

        def move_lesson_into_compliance(element, context):
            compliance = context.root.xpath('//*[@data-part="compliance"]')[0]
            compliance.append(lesson_node(context.root))

        transaction = CallbackTransaction(
            root,
            [
                ScopedCallback(
                    move_lesson_into_compliance, scope=body_scope, name="boundary"
                )
            ],
        )
        with self.assertRaises(ScopeViolation) as caught:
            transaction.run()
        self.assertIn("destination allowed=False", str(caught.exception))

    def test_move_without_capability_is_rejected_but_declared_move_passes(self):
        html = (
            '<section data-part="body">'
            '<p data-role="one">one</p>'
            '<p data-role="two">two</p>'
            "</section>"
        )

        def reorder(element, context):
            body = body_section(context.root)
            first = body.xpath('*[@data-role="one"]')[0]
            body.append(first)

        with self.assertRaises(CapabilityViolation) as caught:
            CallbackTransaction(
                lxml.html.fromstring("<div>%s</div>" % html),
                [ScopedCallback(reorder, capabilities={"text"})],
            ).run()
        self.assertEqual("move", caught.exception.violations[0].required_capability)

        root = lxml.html.fromstring("<div>%s</div>" % html)
        CallbackTransaction(
            root,
            [ScopedCallback(reorder, capabilities={"move"})],
        ).run(commit=True)
        roles = [node.get("data-role") for node in root.xpath("//p")]
        self.assertEqual(["two", "one"], roles)

    def test_replacing_ancestor_is_precisely_reported(self):
        def replace_body_ancestor(element, context):
            lesson = lesson_node(context.root)
            body = body_section(context.root)
            replacement = lxml.html.Element("div")
            replacement.set("data-replacement", "body")
            body.getparent().replace(body, replacement)
            replacement.append(lesson)

        transaction = CallbackTransaction(
            parse_document(),
            [
                ScopedCallback(
                    replace_body_ancestor,
                    scope=lambda node: node.get("data-role") == "lesson",
                    name="ancestor_swap",
                )
            ],
        )
        with self.assertRaises(ScopeViolation) as caught:
            transaction.run()

        kinds = [violation.change.kind for violation in caught.exception.violations]
        self.assertEqual(["replace_ancestor"], kinds)
        self.assertIn("ancestor", str(caught.exception.violations[0]))

    def test_replacing_ancestor_requires_capability(self):
        def replace_body_ancestor(element, context):
            lesson = lesson_node(context.root)
            body = body_section(context.root)
            replacement = lxml.html.Element("div")
            body.getparent().replace(body, replacement)
            replacement.append(lesson)

        with self.assertRaises(CapabilityViolation) as caught:
            CallbackTransaction(
                parse_document(),
                [
                    ScopedCallback(
                        replace_body_ancestor,
                        capabilities={"text"},
                    )
                ],
            ).run()
        self.assertEqual(
            "replace_ancestor",
            caught.exception.violations[0].required_capability,
        )

        # Declaring the precise capability absorbs the constituent
        # remove/insert/move checks and the replacement commits.
        root = parse_document()
        CallbackTransaction(
            root,
            [
                ScopedCallback(
                    replace_body_ancestor,
                    capabilities={"replace_ancestor"},
                )
            ],
        ).run(commit=True)
        self.assertTrue(root.xpath("//div[p[@data-role='lesson']]"))

    def test_callback_failure_rolls_back_and_keeps_impact_report(self):
        root = parse_document()
        original_html = lxml.html.tostring(root, encoding="unicode")
        ran = []

        def exploding_extension(element, context):
            ran.append("boom")
            lesson_node(context.root).text = "half cleaned"
            raise RuntimeError("extension failed halfway")

        def never_runs(element, context):
            ran.append("after")

        transaction = CallbackTransaction(
            root,
            [
                ScopedCallback(exploding_extension, scope=body_scope, name="boom"),
                ScopedCallback(never_runs, scope=body_scope),
            ],
        )
        with self.assertRaises(CallbackExecutionError) as caught:
            transaction.run()

        error = caught.exception
        self.assertIsInstance(error.original, RuntimeError)
        self.assertIsInstance(error.__cause__, RuntimeError)
        self.assertEqual(["boom"], ran)
        self.assertTrue(any(change.kind == "text" for change in error.report.changes))
        self.assertEqual(original_html, lxml.html.tostring(root, encoding="unicode"))
        self.assertEqual(CallbackTransaction.STATUS_ROLLED_BACK, transaction.status)

    def test_callback_failure_after_scope_breach_reports_breach_too(self):
        def bad_and_broken(element, context):
            clause_node(context.root).text = "tampered then failed"
            raise ValueError("nope")

        with self.assertRaises(CallbackExecutionError) as caught:
            CallbackTransaction(
                parse_document(),
                [ScopedCallback(bad_and_broken, scope=body_scope, name="bad")],
            ).run()
        self.assertTrue(caught.exception.scope_violations)
        self.assertIsInstance(caught.exception.original, ValueError)

    def test_legacy_plain_callback_runs_unrestricted(self):
        root = parse_document()

        def legacy_processor(element):
            clause = element.xpath('//*[@data-role="course-clause"]')[0]
            clause.text = "legacy may still touch everything"
            return element

        CallbackTransaction(root, [legacy_processor]).run(commit=True)
        self.assertEqual("legacy may still touch everything", clause_node(root).text)

    def test_declaration_forms_are_recognized(self):
        seen = []

        def plain(element, context=None):
            seen.append("plain")

        decorated = scoped(scope="p", capabilities=["text"])(plain)
        self.assertIsInstance(decorated, ScopedCallback)

        def fn(element, context):
            seen.append("fn")

        fn.scope = body_scope
        fn.capabilities = ("text",)

        def dict_fn(element, context):
            seen.append("dict")

        def tuple_fn(element, context):
            seen.append("tuple")

        root = parse_document()
        CallbackTransaction(
            root,
            [
                decorated,
                fn,
                {"callback": dict_fn, "scope": body_scope, "capabilities": {"text"}},
                (tuple_fn, body_scope, {"text"}),
            ],
        ).run()
        self.assertEqual(["plain", "fn", "dict", "tuple"], seen)

    def test_run_callback_chain_tolerates_argument_order(self):
        first_root = parse_document()

        def edit(element, context):
            lesson_node(context.root).text = "via convenience"

        committed = run_callback_chain(
            [ScopedCallback(edit, scope=body_scope)], first_root
        )
        self.assertEqual("via convenience", lesson_node(committed).text)

        second_root = parse_document()
        committed = run_callback_chain(
            second_root, [ScopedCallback(edit, scope=body_scope)]
        )
        self.assertEqual("via convenience", lesson_node(committed).text)

        transaction = run_callback_chain(
            parse_document(),
            [ScopedCallback(edit, scope=body_scope)],
            return_transaction=True,
        )
        self.assertIsInstance(transaction, CallbackTransaction)
        self.assertEqual(CallbackTransaction.STATUS_COMMITTED, transaction.status)


class SanitizerCallbackIntegrationTest(unittest.TestCase):
    def settings(self, processors):
        return {
            "tags": {"article", "section", "p", "div"},
            "empty": set(),
            "separate": set(),
            "whitespace": set(),
            "attributes": {
                "section": {"data-part", "class"},
                "p": {"data-role", "data-clean", "class", "data-replacement"},
                "div": {"data-replacement"},
            },
            "element_preprocessors": processors,
        }

    def test_declared_processor_is_enforced_by_sanitize(self):
        def tamper(element):
            root = element.getroottree().getroot()
            clauses = root.xpath('//*[@data-role="course-clause"]')
            if clauses:
                clauses[0].text = "sanitizer extension tampers clause"
            return element

        sanitizer = Sanitizer(
            self.settings([ScopedCallback(tamper, scope=body_scope, name="tamper")])
        )
        with self.assertRaises(ScopeViolation):
            sanitizer.sanitize(DOCUMENT)

        # The sanitizer instance keeps no half tree and stays usable.
        self.assertEqual("<p>ok</p>", sanitizer.sanitize("<p>ok</p>"))

    def test_good_declared_processor_still_sanitizes(self):
        def polish(element):
            if element.tag == "p" and element.get("data-role") == "lesson":
                element.text = "正文已整理"
            return element

        sanitizer = Sanitizer(
            self.settings(
                [
                    ScopedCallback(
                        polish,
                        scope=lambda node: node.get("data-role") == "lesson",
                        capabilities={"text"},
                    )
                ]
            )
        )
        result = sanitizer.sanitize(DOCUMENT)
        self.assertIn("正文已整理", result)
        self.assertIn("课程条款", result)

    def test_legacy_processors_keep_working(self):
        def shout(element):
            if element.text:
                element.text = element.text.replace("正文第一段", "正文第一段！")
            return element

        sanitizer = Sanitizer(self.settings([shout]))
        result = sanitizer.sanitize("<p data-role='lesson'>正文第一段</p>")
        self.assertIn("正文第一段！", result)

    def test_sanitizer_run_callback_chain_helper(self):
        sanitizer = Sanitizer()
        root = parse_document()

        def legacy(element):
            lesson_node(element).text = "helper"
            return element

        committed = sanitizer.run_callback_chain(
            root, [ScopedCallback(legacy, scope=body_scope, capabilities={"text"})]
        )
        self.assertIs(committed, root)
        self.assertEqual("helper", lesson_node(root).text)
        self.assertEqual("helper", lesson_node(committed).text)


class CompatibilityApiTest(unittest.TestCase):
    def test_deferred_chain_style_process(self):
        seen = []

        def extension(element, context):
            seen.append("ran")
            lesson_node(context.root).text = "deferred"

        chain = CallbackChain([ScopedCallback(extension, scope=body_scope)])
        root = parse_document()
        returned = chain.process(root)
        self.assertIs(root, returned)
        self.assertEqual(["ran"], seen)
        self.assertEqual("deferred", lesson_node(root).text)

    def test_context_manager_commit_and_rollback(self):
        root = parse_document()

        def good(element, context):
            lesson_node(context.root).text = "with-block"

        with CallbackTransaction(
            root, [ScopedCallback(good, scope=body_scope)]
        ) as transaction:
            transaction.run()
        self.assertEqual(CallbackTransaction.STATUS_COMMITTED, transaction.status)
        self.assertEqual("with-block", lesson_node(root).text)

        other = parse_document()
        before = lxml.html.tostring(other, encoding="unicode")

        def bad(element, context):
            clause_node(context.root).text = "context manager breach"

        with (
            self.assertRaises(ScopeViolation),
            CallbackTransaction(
                other, [ScopedCallback(bad, scope=body_scope)]
            ) as failed_transaction,
        ):
            failed_transaction.run()
        self.assertEqual(before, lxml.html.tostring(other, encoding="unicode"))

    def test_scope_forms(self):
        self.assertTrue(NodeScope("p").contains(lxml.html.fromstring("<p>")))
        self.assertFalse(NodeScope("p").contains(lxml.html.fromstring("<div>")))
        self.assertTrue(
            NodeScope("[data-part='body']").contains(body_section(parse_document()))
        )
        self.assertTrue(
            NodeScope({"data-part": "body"}).contains(body_section(parse_document()))
        )
        self.assertTrue(
            NodeScope(lambda node: node.tag == "section").contains(
                body_section(parse_document())
            )
        )
        referenced = body_section(parse_document())
        self.assertTrue(NodeScope(referenced).contains(referenced[0]))

    def test_sanitizer_context_aware_processor_gets_root(self):
        seen = {}

        def processor(element, context):
            if element.tag == "p" and element.get("data-role") == "lesson":
                seen["root_tag"] = context.root.tag
                context.root.xpath('//*[@data-role="lesson"]')[
                    0
                ].text = "ctx root works"
            return element

        sanitizer = Sanitizer(
            {
                "tags": {"article", "section", "p"},
                "empty": set(),
                "separate": set(),
                "attributes": {
                    "section": {"data-part"},
                    "p": {"data-role"},
                },
                "element_preprocessors": [
                    ScopedCallback(
                        processor,
                        scope=lambda node: node.get("data-role") == "lesson",
                    )
                ],
            }
        )
        result = sanitizer.sanitize(DOCUMENT)
        self.assertEqual("div", seen["root_tag"])
        self.assertIn("ctx root works", result)


if __name__ == "__main__":
    unittest.main()
