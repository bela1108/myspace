from unittest import TestCase

from html_sanitizer import Sanitizer
from html_sanitizer.offline_compare import (
    OfflineComparisonError,
    canonical_visible_text,
    compare_outputs,
    compare_views,
)


PREVIEW_TAGS = frozenset({"p", "mark"})
PRINT_TAGS = PREVIEW_TAGS | {"aside"}


def make_sanitizer(*extra_tags):
    tags = {"p", "mark", *extra_tags}
    attributes = {}
    if "mark" in tags:
        attributes["mark"] = {"class"}
    if "aside" in tags:
        attributes["aside"] = {"class"}

    separate = {"p"}
    if "aside" in tags:
        separate.add("aside")

    return Sanitizer(
        {
            "tags": tags,
            "attributes": attributes,
            "empty": set(),
            "separate": separate,
        }
    )


class OfflineCompareExamplesTestCase(TestCase):
    def setUp(self):
        self.preview_sanitizer = make_sanitizer()
        self.print_sanitizer = make_sanitizer("aside")

    def test_01_plain_text_example(self):
        text = "档案正文 无需标签"
        report = compare_outputs(
            PREVIEW_TAGS,
            self.preview_sanitizer.sanitize(text),
            PRINT_TAGS,
            self.print_sanitizer.sanitize(text),
        )

        self.assertTrue(report.ok, [item.message for item in report.errors])
        self.assertEqual(report.shared_visible_text, text)
        self.assertEqual(report.shared_text_blocks, [text])
        self.assertEqual(report.marker_decisions, [])
        self.assertTrue(report.provenance_notes)

    def test_02_legal_tags_and_layout_shift_example(self):
        preview_source = (
            '\n  <p>档案正文 卷一</p>\n\n  <mark class="page-number">第 7 页</mark>\n'
        )
        print_source = (
            "<p>档案正文 卷一</p>"
            '<aside class="note-label">备注 核对引文</aside>'
            '<mark class="page-number">第 7 页</mark>'
        )

        report = compare_outputs(
            PREVIEW_TAGS,
            self.preview_sanitizer.sanitize(preview_source),
            PRINT_TAGS,
            self.print_sanitizer.sanitize(print_source),
        )

        self.assertTrue(report.ok, [item.message for item in report.errors])
        self.assertEqual(
            report.shared_text_blocks,
            ["档案正文 卷一", "第 7 页"],
        )
        self.assertEqual(
            report.shared_visible_text,
            "档案正文 卷一 第 7 页",
        )
        self.assertIn("备注 核对引文", report.print_only_text)

        scopes = {
            (marker.view, marker.tag): marker.policy_scope
            for marker in report.marker_decisions
        }
        self.assertEqual(scopes[("public_preview", "mark")], "shared_allowed")
        self.assertEqual(scopes[("print", "mark")], "shared_allowed")
        self.assertEqual(scopes[("print", "aside")], "print_only_allowed")

        note_sources = [
            item for item in report.source_decisions if "备注 核对引文" in item.text
        ]
        self.assertEqual(len(note_sources), 1)
        self.assertEqual(
            note_sources[0].classification,
            "optional_permission_bound_marker_text",
        )

    def test_layout_shift_does_not_change_visible_text(self):
        compact = '<p>档案正文 卷三</p><mark class="page-number">第 9 页</mark>'
        shifted = (
            '\n\t<p>档案正文 卷三</p>\n\n\t<mark class="page-number">第 9 页</mark>\n'
        )

        self.assertEqual(
            canonical_visible_text(shifted),
            canonical_visible_text(compact),
        )

    def test_03_note_in_disallowed_view_is_diagnosed(self):
        source = (
            "<p>档案正文 卷二</p>"
            '<aside class="note-label">备注 不应公开</aside>'
            '<mark class="page-number">第 8 页</mark>'
        )

        report = compare_outputs(
            PREVIEW_TAGS,
            source,
            PRINT_TAGS,
            self.print_sanitizer.sanitize(source),
        )

        self.assertFalse(report.ok)
        self.assertEqual(len(report.errors), 1)
        diagnostic = report.errors[0]
        self.assertEqual(diagnostic.code, "disallowed_marker")
        self.assertEqual(diagnostic.view, "public_preview")
        self.assertEqual(diagnostic.tag, "aside")
        self.assertIn("备注 不应公开", diagnostic.excerpt)
        self.assertNotIn("备注 不应公开", report.shared_visible_text)

        forbidden_sources = [
            item
            for item in report.source_decisions
            if item.classification == "disallowed_marker_text"
        ]
        self.assertEqual(len(forbidden_sources), 1)
        self.assertIn("aside", forbidden_sources[0].tags)

        with self.assertRaisesRegex(OfflineComparisonError, "aside"):
            report.raise_for_violations()

    def test_compare_views_four_arguments(self):
        report = compare_views(PREVIEW_TAGS, "纯文本", PRINT_TAGS, "纯文本")
        self.assertEqual(report.shared_visible_text, "纯文本")
        self.assertTrue(report.ok)

    def test_unexplained_extra_text_is_unverified_origin(self):
        report = compare_outputs(
            PREVIEW_TAGS,
            "<p>共享正文</p>",
            PRINT_TAGS,
            "<p>共享正文</p><p>来源不明的附加段</p>",
        )

        self.assertTrue(report.ok)
        self.assertEqual(report.shared_text_blocks, ["共享正文"])
        self.assertEqual(len(report.unverifiable_sources), 1)
        self.assertIn("来源不明的附加段", report.unverifiable_sources[0])
