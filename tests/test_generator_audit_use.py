#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import dlint


class TestGeneratorAuditUse(dlint.test.base.BaseTest):
    def lint(self, source):
        python_node = self.get_ast_node(source)
        linter = dlint.linters.GeneratorAuditUseLinter()
        linter.visit(python_node)
        return linter.get_results()

    def result(self, lineno, col_offset, message):
        return dlint.linters.base.Flake8Result(
            lineno=lineno,
            col_offset=col_offset,
            message=message
        )

    def test_never_consumed_pinned_on_producer(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                yield 2
                audit_end()
            """
        )

        assert results == [
            self.result(
                2,
                0,
                dlint.linters.GeneratorAuditUseLinter._error_tmpl.format(
                    name="export_rows"
                )
            )
        ]

    def test_missing_end_audit_pinned_on_exhausting_consumer(self):
        results = self.lint(
            """
            def export_rows():
                yield 1
                yield 2

            def consume():
                rows = list(export_rows())
            """
        )

        assert results == [
            self.result(
                7,
                16,
                dlint.linters.GeneratorAuditUseLinter.missing_end_tmpl.format(
                    stage="full exhaustion", name="export_rows"
                )
            )
        ]

    def test_first_consumption_stage_via_next(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                audit_end()

            def consume():
                gen = export_rows()
                next(gen)
            """
        )

        assert results == [
            self.result(
                9,
                9,
                dlint.linters.GeneratorAuditUseLinter.missing_end_tmpl.format(
                    stage="first consumption", name="export_rows"
                )
            )
        ]

    def test_early_break_stage(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                yield 2
                audit_end()

            def consume():
                for row in export_rows():
                    if row == 1:
                        break
            """
        )

        assert results == [
            self.result(
                9,
                15,
                dlint.linters.GeneratorAuditUseLinter.missing_end_tmpl.format(
                    stage="early break", name="export_rows"
                )
            )
        ]

    def test_explicit_close_stage_without_end_audit(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                yield 2

            def consume():
                gen = export_rows()
                gen.close()
            """
        )

        assert results == [
            self.result(
                9,
                4,
                dlint.linters.GeneratorAuditUseLinter.missing_end_tmpl.format(
                    stage="explicit close", name="export_rows"
                )
            )
        ]

    def test_full_exhaustion_confirms_present_end_audit(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                yield 2
                audit_end()

            def consume():
                rows = list(export_rows())
            """
        )

        assert results == []

    def test_explicit_close_confirms_present_end_audit(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                audit_end()

            def consume():
                gen = export_rows()
                gen.close()
            """
        )

        assert results == []

    def test_unknown_consumer_contract_prompts_review(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                audit_end()

            def consume():
                pipe(export_rows())
            """
        )

        assert results == [
            self.result(
                8,
                9,
                dlint.linters.GeneratorAuditUseLinter.review_tmpl.format(
                    name="export_rows"
                )
            )
        ]

    def test_finally_end_audit_covers_all_stages(self):
        results = self.lint(
            """
            def export_rows():
                try:
                    audit_start()
                    yield 1
                    yield 2
                finally:
                    audit_end()

            def break_consumer():
                for row in export_rows():
                    break

            def close_consumer():
                gen = export_rows()
                gen.close()

            def unknown_consumer():
                pipe(export_rows())
            """
        )

        assert results == []

    def test_single_layer_wrapper_is_followed(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                audit_end()

            def get_rows():
                return export_rows()

            def consume():
                rows = list(get_rows())
            """
        )

        assert results == []

    def test_double_layer_wrapper_is_not_followed(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                audit_end()

            def get_rows():
                return export_rows()

            def get_rows2():
                return get_rows()

            def consume():
                rows = list(get_rows2())
            """
        )

        assert results == [
            self.result(
                14,
                16,
                dlint.linters.GeneratorAuditUseLinter.review_tmpl.format(
                    name="get_rows2"
                )
            ),
            self.result(
                2,
                0,
                dlint.linters.GeneratorAuditUseLinter._error_tmpl.format(
                    name="export_rows"
                )
            ),
        ]

    def test_local_binding_is_not_consumption(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                audit_end()

            def hold():
                gen = export_rows()
                return gen
            """
        )

        assert results == [
            self.result(
                2,
                0,
                dlint.linters.GeneratorAuditUseLinter._error_tmpl.format(
                    name="export_rows"
                )
            )
        ]

    def test_non_generator_functions_are_ignored(self):
        results = self.lint(
            """
            def plain():
                audit_start()
                audit_end()
                return 1

            def consume():
                value = plain()
            """
        )

        assert results == []

    def test_attribute_form_audit_calls_are_recognized(self):
        results = self.lint(
            """
            def export_rows():
                audit.start()
                yield 1
                yield 2
                audit.end()

            def consume():
                for row in export_rows():
                    break
            """
        )

        assert results == [
            self.result(
                9,
                15,
                dlint.linters.GeneratorAuditUseLinter.missing_end_tmpl.format(
                    stage="early break", name="export_rows"
                )
            )
        ]

    def test_consumer_inside_nested_function_is_followed(self):
        results = self.lint(
            """
            def export_rows():
                audit_start()
                yield 1
                audit_end()

            def outer():
                def inner():
                    return list(export_rows())
                return inner
            """
        )

        assert results == []
