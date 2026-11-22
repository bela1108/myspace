#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint
from dlint.linters.transaction.audit_config import AuditTransactionConfig


LINTER = dlint.linters.AuditBeforeCommitLinter
UNSAFE_MSG = LINTER._error_tmpl
UNKNOWN_MSG = LINTER._unknown_tmpl


class TestAuditBeforeCommit(dlint.test.base.BaseTest):

    def _run(self, source, config=None):
        python_node = self.get_ast_node(source)
        linter = LINTER(config=config)
        linter.visit(python_node)
        return linter.get_results()

    def _messages(self, results):
        return sorted(result.message for result in results)


    def test_empty_module(self):
        assert self._run(
            """
            """
        ) == []

    def test_unrelated_calls_are_silent(self):
        results = self._run(
            """
            def handler():
                total = compute()
                logger.debug(total)
            """
        )
        assert results == []

    def test_direct_write_then_rollback_is_unsafe(self):
        results = self._run(
            """
            def handler():
                log_security_event("blocked user")
                transaction.rollback()
            """
        )
        assert len(results) == 1
        assert results[0].lineno == 3
        assert results[0].message == UNSAFE_MSG

    def test_direct_write_then_commit_is_safe(self):
        results = self._run(
            """
            def handler():
                log_security_event("blocked user")
                transaction.commit()
            """
        )
        assert results == []

    def test_inner_success_outer_rollback_folded_at_call_site(self):
        # The inner wrapper succeeds on its own, but the outer transaction
        # rolls back after the call. Only the outer call site is reported;
        # the wrapper body is not reported a second time.
        results = self._run(
            """
            def log_disposition():
                log_security_event("blocked user")

            def handler():
                log_disposition()
                transaction.rollback()
            """
        )
        assert len(results) == 1
        assert results[0].lineno == 6
        assert results[0].message == UNSAFE_MSG

    def test_inner_success_outer_commit_is_safe(self):
        results = self._run(
            """
            def log_disposition():
                log_security_event("blocked user")

            def handler():
                log_disposition()
                transaction.commit()
            """
        )
        assert results == []

    def test_chained_local_wrappers_are_followed(self):
        results = self._run(
            """
            def write_audit():
                log_security_event("blocked user")

            def log_disposition():
                write_audit()

            def handler():
                log_disposition()
                transaction.rollback()
            """
        )
        assert len(results) == 1
        assert results[0].lineno == 9
        assert results[0].message == UNSAFE_MSG

    def test_empty_stub_wrapper_runs_without_false_positive(self):
        # An empty implementation is enough to exercise the wrapper chain;
        # a stub with no audit write contributes no ordering fact.
        results = self._run(
            """
            def log_disposition():
                pass

            def handler():
                log_disposition()
                transaction.rollback()
            """
        )
        assert results == []

    def test_post_commit_callback_function_is_safe(self):
        # The callback body writes the audit record, but it only runs after
        # the outer transaction commits, so neither the body nor the
        # registrar is reported.
        results = self._run(
            """
            def handler():
                def after_commit():
                    log_security_event("blocked user")

                transaction.on_commit(after_commit)
                transaction.commit()
            """
        )
        assert results == []

    def test_post_commit_callback_lambda_is_safe(self):
        results = self._run(
            """
            def handler():
                transaction.on_commit(
                    lambda: log_security_event("blocked user")
                )
                transaction.commit()
            """
        )
        assert results == []

    def test_post_commit_lambda_body_not_reported_standalone(self):
        # The lambda is a scope boundary: its inner write must only be
        # explained through the safe registrar, never as a standalone entry.
        results = self._run(
            """
            def handler():
                transaction.on_commit(
                    lambda: log_security_event("blocked user")
                )
            """
        )
        assert results == []

    def test_post_commit_dynamic_callback_is_unknown(self):
        results = self._run(
            """
            def handler():
                callbacks = load_callbacks()
                transaction.on_commit(callbacks[0])
                transaction.commit()
            """
        )
        assert len(results) == 1
        assert results[0].lineno == 4
        assert results[0].message == UNKNOWN_MSG

    def test_two_same_named_wrappers_each_get_an_explanation(self):
        # Two wrappers share a name in different scopes. The lexical binding
        # is not unique, so every same-named call is unknown rather than
        # guessed, and the ambiguous bodies are not reported a second time.
        results = self._run(
            """
            def log_disposition():
                log_security_event("outer")

            def other_scope():
                def log_disposition():
                    log_security_event("inner")

                log_disposition()

            def handler():
                log_disposition()
                transaction.rollback()
            """
        )
        assert len(results) == 2
        assert self._messages(results) == [UNKNOWN_MSG, UNKNOWN_MSG]
        unknown_lines = sorted(result.lineno for result in results)
        assert unknown_lines == [9, 12]

    def test_ambiguous_and_unique_wrapper_coexist(self):
        # Same-named helpers stay unknown, while a uniquely named wrapper on
        # the rollback path still yields a confident unsafe verdict.
        results = self._run(
            """
            def helper():
                log_security_event("shared")

            def other_scope():
                def helper():
                    log_security_event("shadow")

                helper()

            def record_disposition():
                log_security_event("unique")

            def handler():
                record_disposition()
                transaction.rollback()
            """
        )
        messages = self._messages(results)
        assert messages.count(UNKNOWN_MSG) == 1
        assert messages.count(UNSAFE_MSG) == 1

    def test_single_named_wrapper_resolves_confidently(self):
        results = self._run(
            """
            def log_disposition():
                log_security_event("only one")

            def handler():
                log_disposition()
            """
        )
        assert len(results) == 1
        assert results[0].message == UNSAFE_MSG

    def test_dynamic_attribute_chain_is_unknown(self):
        # get_logger().emit(...) cannot be bound to a static configured name.
        results = self._run(
            """
            def handler():
                logger = get_logger()
                logger.emit("blocked user")
            """
        )
        assert len(results) == 1
        assert results[0].lineno == 4
        assert results[0].message == UNKNOWN_MSG

    def test_rebound_wrapper_name_is_unknown(self):
        results = self._run(
            """
            def log_disposition():
                log_security_event("static")

            def handler():
                log_disposition = imported_logger
                log_disposition()
            """
        )
        messages = self._messages(results)
        assert UNKNOWN_MSG in messages

    def test_dynamic_call_without_sink_name_is_silent(self):
        results = self._run(
            """
            def handler():
                router = get_router()
                router.dispatch("anything")
            """
        )
        assert results == []

    def test_outside_transaction_adapter_safe_when_no_transaction(self):
        results = self._run(
            """
            def handler():
                emit_audit_event("blocked user")
            """
        )
        assert results == []

    def test_outside_transaction_adapter_unsafe_inside_transaction(self):
        results = self._run(
            """
            def handler():
                log_security_event("blocked user")
                emit_audit_event("duplicate")
                transaction.rollback()
            """
        )
        messages = self._messages(results)
        assert messages == [UNSAFE_MSG, UNSAFE_MSG]

    def test_nested_scope_does_not_leak_transaction_state(self):
        # The nested function opens and commits its own transaction. When it
        # exits, the outer scope still has an open write that is rolled back.
        results = self._run(
            """
            def handler():
                log_security_event("outer")

                def nested():
                    log_security_event("inner")
                    transaction.commit()

                nested()
                transaction.rollback()
            """
        )
        messages = self._messages(results)
        assert messages.count(UNSAFE_MSG) == 1

    def test_explicit_project_config_drives_detection(self):
        config = AuditTransactionConfig.from_mapping({
            "audit_write_functions": ["sec.record"],
            "post_commit_callbacks": ["db.after_commit"],
            "outside_transaction_adapters": ["sink.send"],
            "commit_functions": ["db.commit"],
            "rollback_functions": ["db.abort"],
        })
        results = self._run(
            """
            def handler():
                sec.record("blocked user")
                db.abort()
            """
            ,
            config=config,
        )
        assert len(results) == 1
        assert results[0].message == UNSAFE_MSG

        safe_results = self._run(
            """
            def handler():
                db.after_commit(lambda: sec.record("blocked user"))
                db.commit()
            """
            ,
            config=config,
        )
        assert safe_results == []


if __name__ == "__main__":
    unittest.main()
