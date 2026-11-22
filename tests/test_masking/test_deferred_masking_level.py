#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import sys
import textwrap
import unittest

import dlint


IS_PYTHON_3 = sys.version_info >= (3,)


class TestDeferredMaskingLevel(dlint.test.base.BaseTest):

    def _lint(self, source):
        python_node = self.get_ast_node(textwrap.dedent(source))

        linter = dlint.linters.DeferredMaskingLevelLinter()
        linter.visit(python_node)

        return linter.get_results()

    def _result(self, lineno, col_offset, message):
        return dlint.linters.base.Flake8Result(
            lineno=lineno,
            col_offset=col_offset,
            message=message
        )

    def test_empty(self):
        results = self._lint(
            """
            """
        )

        assert results == []

    def test_plain_list_callbacks_are_skipped(self):
        results = self._lint(
            """
            handlers = [lambda item: item.clean() for item in range(3)]
            cleaned = [mask(item, level="secret") for item in items]
            mapped = list(map(lambda item: item.clean(), items))
            """
        )

        assert results == []

    def test_callback_without_masking_call_is_skipped(self):
        results = self._lint(
            """
            def callback(data):
                data.clean()

            queue.submit(callback)
            """
        )

        assert results == []

    def test_lambda_closure_read_of_loop_variable(self):
        results = self._lint(
            """
            for level in ["low", "high"]:
                queue.submit(lambda data: masking.mask(data, level=level))
            """
        )

        expected = [
            self._result(
                3,
                30,
                'DUO139 deferred masking callback "<lambda>" at scheduling '
                'call line 3: closure-read at masking call line 3 '
                '(no provable level)'
            )
        ]

        assert results == expected

    def test_function_closure_read_of_loop_variable(self):
        results = self._lint(
            """
            def schedule_cleanup(records):
                for level in ["low", "high"]:
                    def closure_callback(data):
                        masking.mask(data, level=level)
                    queue.submit(closure_callback)
            """
        )

        expected = [
            self._result(
                5,
                12,
                'DUO139 deferred masking callback "closure_callback" at '
                'scheduling call line 6: closure-read at masking call line 5 '
                '(no provable level)'
            )
        ]

        assert results == expected

    def test_while_loop_closure_read(self):
        results = self._lint(
            """
            def schedule_cleanup(records):
                while records:
                    level = records.pop()
                    def closure_callback(data):
                        masking.mask(data, level=level)
                    queue.submit(closure_callback)
            """
        )

        expected = [
            self._result(
                6,
                12,
                'DUO139 deferred masking callback "closure_callback" at '
                'scheduling call line 7: closure-read at masking call line 6 '
                '(no provable level)'
            )
        ]

        assert results == expected

    def test_default_value_capture_is_provable(self):
        results = self._lint(
            """
            def schedule_sweep(batch, default_level="secret"):
                def default_callback(data):
                    masking.mask(data, level=default_level)
                queue.submit(default_callback)
            """
        )

        expected = [
            self._result(
                4,
                8,
                'DUO139 deferred masking callback "default_callback" at '
                'scheduling call line 5: default-capture at masking call '
                'line 4 (provable level secret)'
            )
        ]

        assert results == expected

    def test_default_value_capture_with_positional_level(self):
        results = self._lint(
            """
            def schedule_sweep(batch, default_level="pci"):
                def default_callback(data):
                    masking.mask(data, default_level)
                queue.submit(default_callback)
            """
        )

        expected = [
            self._result(
                4,
                8,
                'DUO139 deferred masking callback "default_callback" at '
                'scheduling call line 5: default-capture at masking call '
                'line 4 (provable level pci)'
            )
        ]

        assert results == expected

    def test_default_value_invalidated_by_reassignment(self):
        results = self._lint(
            """
            def schedule_sweep(batch, default_level="secret"):
                def default_callback(data):
                    default_level = "public"
                    masking.mask(data, level=default_level)
                queue.submit(default_callback)
            """
        )

        expected = [
            self._result(
                5,
                8,
                'DUO139 deferred masking callback "default_callback" at '
                'scheduling call line 6: dynamic at masking call line 5 '
                '(no provable level)'
            )
        ]

        assert results == expected

    @unittest.skipUnless(IS_PYTHON_3, "nonlocal is Python 3-only syntax")
    def test_nonlocal_reassignment(self):
        results = self._lint(
            """
            def schedule_rotation(items):
                current = "internal"

                def rebind_callback(data):
                    nonlocal current
                    current = "public"
                    masking.mask(data, level=current)

                queue.submit(rebind_callback)
            """
        )

        expected = [
            self._result(
                8,
                8,
                'DUO139 deferred masking callback "rebind_callback" at '
                'scheduling call line 10: nonlocal-reassignment at masking '
                'call line 8 (no provable level)'
            )
        ]

        assert results == expected

    def test_constant_literal_level_is_provable(self):
        results = self._lint(
            """
            def constant_callback(data):
                masking.mask(data, level="public")

            queue.submit(constant_callback)
            """
        )

        expected = [
            self._result(
                3,
                4,
                'DUO139 deferred masking callback "constant_callback" at '
                'scheduling call line 5: constant at masking call line 3 '
                '(provable level public)'
            )
        ]

        assert results == expected

    def test_single_outer_constant_binding_is_provable(self):
        results = self._lint(
            """
            def schedule_batch(records):
                level = "confidential"

                def constant_callback(data):
                    masking.mask(data, level=level)

                queue.submit(constant_callback)
            """
        )

        expected = [
            self._result(
                6,
                8,
                'DUO139 deferred masking callback "constant_callback" at '
                'scheduling call line 8: constant at masking call line 6 '
                '(provable level confidential)'
            )
        ]

        assert results == expected

    def test_module_level_constant_is_provable(self):
        results = self._lint(
            """
            LEVEL = "secret"

            def constant_callback(data):
                masking.mask(data, level=LEVEL)

            queue.submit(constant_callback)
            """
        )

        expected = [
            self._result(
                5,
                4,
                'DUO139 deferred masking callback "constant_callback" at '
                'scheduling call line 7: constant at masking call line 5 '
                '(provable level secret)'
            )
        ]

        assert results == expected

    def test_module_level_dynamic_binding_is_not_provable(self):
        results = self._lint(
            """
            LEVEL = compute_level()

            def dynamic_callback(data):
                masking.mask(data, level=LEVEL)

            queue.submit(dynamic_callback)
            """
        )

        expected = [
            self._result(
                5,
                4,
                'DUO139 deferred masking callback "dynamic_callback" at '
                'scheduling call line 7: dynamic at masking call line 5 '
                '(no provable level)'
            )
        ]

        assert results == expected

    def test_unknown_higher_order_wrapper_requires_manual_review(self):
        results = self._lint(
            """
            queue.submit(build_cleaner())
            """
        )

        expected = [
            self._result(
                2,
                0,
                'DUO139 deferred masking callback "submit" at scheduling '
                'call line 2: manual review required - callback originates '
                'from an unknown higher-order wrapper'
            )
        ]

        assert results == expected

    def test_attribute_and_subscript_callbacks_require_manual_review(self):
        results = self._lint(
            """
            queue.submit(holder.cleaner)
            queue.submit(cleaners[0])
            """
        )

        expected = [
            self._result(
                2,
                0,
                'DUO139 deferred masking callback "submit" at scheduling '
                'call line 2: manual review required - callback originates '
                'from an unknown higher-order wrapper'
            ),
            self._result(
                3,
                0,
                'DUO139 deferred masking callback "submit" at scheduling '
                'call line 3: manual review required - callback originates '
                'from an unknown higher-order wrapper'
            )
        ]

        assert results == expected

    def test_rebound_callback_name_requires_manual_review(self):
        results = self._lint(
            """
            def schedule_batch():
                callback = build_cleaner()
                queue.submit(callback)
            """
        )

        expected = [
            self._result(
                4,
                4,
                'DUO139 deferred masking callback "submit" at scheduling '
                'call line 4: manual review required - callback originates '
                'from an unknown higher-order wrapper'
            )
        ]

        assert results == expected

    def test_separate_queue_batches_are_not_merged(self):
        results = self._lint(
            """
            queue_a = masking.Queue()
            queue_b = masking.Queue()

            def batch_one():
                level = "low"

                def callback(data):
                    masking.mask(data, level=level)

                queue_a.submit(callback)

            def batch_two():
                level = "high"

                def callback(data):
                    masking.mask(data, level=level)

                queue_b.submit(callback)
            """
        )

        expected = [
            self._result(
                9,
                8,
                'DUO139 deferred masking callback "callback" at scheduling '
                'call line 11: constant at masking call line 9 '
                '(provable level low)'
            ),
            self._result(
                17,
                8,
                'DUO139 deferred masking callback "callback" at scheduling '
                'call line 19: constant at masking call line 17 '
                '(provable level high)'
            )
        ]

        assert results == expected

    def test_multiple_masking_calls_are_reported_independently(self):
        results = self._lint(
            """
            def schedule_batch(default_level="a"):
                def callback(data):
                    masking.mask(data, level=default_level)
                    masking.mask(data, level="fixed")
                queue.submit(callback)
            """
        )

        expected = [
            self._result(
                4,
                8,
                'DUO139 deferred masking callback "callback" at scheduling '
                'call line 6: default-capture at masking call line 4 '
                '(provable level a)'
            ),
            self._result(
                5,
                8,
                'DUO139 deferred masking callback "callback" at scheduling '
                'call line 6: constant at masking call line 5 '
                '(provable level fixed)'
            )
        ]

        assert results == expected

    def test_module_level_scheduling_function(self):
        results = self._lint(
            """
            def callback(data):
                masking.mask(data, level="secret")

            submit_masking_job(callback)
            """
        )

        expected = [
            self._result(
                3,
                4,
                'DUO139 deferred masking callback "callback" at scheduling '
                'call line 5: constant at masking call line 3 '
                '(provable level secret)'
            )
        ]

        assert results == expected

    def test_two_deferred_cleanup_jobs_and_plain_list_callback(self):
        results = self._lint(
            """
            import masking

            queue = masking.Queue()


            def schedule_cleanups(batches):
                for level in ("public", "confidential"):
                    def loop_cleanup(data):
                        masking.mask(data, level=level)

                    queue.submit(loop_cleanup)

                def default_cleanup(data, default_level="internal"):
                    masking.mask(data, level=default_level)

                queue.submit(default_cleanup)


            plain_handlers = [
                lambda record: record.clean() for record in records
            ]
            """
        )

        expected = [
            self._result(
                10,
                12,
                'DUO139 deferred masking callback "loop_cleanup" at '
                'scheduling call line 12: closure-read at masking call '
                'line 10 (no provable level)'
            ),
            self._result(
                15,
                8,
                'DUO139 deferred masking callback "default_cleanup" at '
                'scheduling call line 17: default-capture at masking call '
                'line 15 (provable level internal)'
            )
        ]

        assert results == expected

    def test_inline_lambda_constant_level(self):
        results = self._lint(
            """
            queue.submit(lambda data: masking.mask(data, level="internal"))
            """
        )

        expected = [
            self._result(
                2,
                26,
                'DUO139 deferred masking callback "<lambda>" at scheduling '
                'call line 2: constant at masking call line 2 '
                '(provable level internal)'
            )
        ]

        assert results == expected


if __name__ == "__main__":
    unittest.main()
