#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from .. import base
from ... import namespace
from ... import tree
from .audit_config import (
    AuditTransactionConfig,
    AuditVerdict,
    DYNAMIC,
    SAFE,
    UNKNOWN,
    UNSAFE,
    PENDING,
)


def _call_name(node):
    """Return the dotted name of a direct call, e.g.
    ``audit.log_security_event`` for ``audit.log_security_event(...)``,
    or ``None`` when the call target is not a static name/attribute chain.
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        path = tree.module_path_str(func)
        return path or None
    return None


def _name_matches(call_name, configured_name):
    """A configured dotted name matches a bare or qualified call sharing
    the same trailing path, e.g. ``on_commit`` matches both
    ``on_commit(...)`` and ``transaction.on_commit(...)``.
    """
    if not call_name:
        return False
    if call_name == configured_name:
        return True
    return call_name.endswith("." + configured_name)


def _any_match(call_name, configured_names):
    return any(
        _name_matches(call_name, configured_name)
        for configured_name in configured_names
    )


def _is_docstring(node):
    if not isinstance(node, ast.Expr):
        return False
    if hasattr(ast, "Constant"):
        return isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, str
        )
    return isinstance(node.value, ast.Str)



class AuditBeforeCommitLinter(base.BaseLinter):
    """This linter looks for security audit records written while the
    surrounding database transaction may still be rolled back. An audit
    entry written before the transaction boundary is a confirmed action
    even when the transaction later undoes the underlying security change.

    The project explicitly declares, via AuditTransactionConfig:
      * the functions that write a security record,
      * registrars that only run their callback after commit,
      * adapters that are only valid outside of a transaction, and
      * the commit / rollback boundary calls.

    Local wrapper functions are followed when their body resolves to a
    confident ordering. Dynamic binding (or any wrapper that cannot be
    resolved statically) yields an unknown result instead of a guess.
    Nested functions are analyzed in their own scope; once a nested scope
    exits the outer transaction state decides whether its writes are safe.
    """

    off_by_default = False

    _code = "DUO139"
    _error_tmpl = (
        "DUO139 audit record written before transaction boundary, "
        "a rollback would leave a confirmed entry for an undone action"
    )
    _unknown_tmpl = (
        "DUO139 audit ordering cannot be determined statically, "
        "dynamic binding or an unresolvable wrapper is in use"
    )

    def __init__(self, config=None, *args, **kwargs):
        self.config = config or AuditTransactionConfig.default()
        self._functions = []
        self._summaries = {}
        self._resolving = set()
        self._dynamic_names = set()

        super(AuditBeforeCommitLinter, self).__init__(*args, **kwargs)

    def visit_Module(self, node):
        if not self.namespace:
            self.namespace = namespace.Namespace.from_module_node(node)
        self._functions = self._collect_functions(node)
        self._dynamic_names = self._collect_dynamic_names(node)
        self._summaries = {}

        for function in self._functions:
            self._summarize(function)

        # A function reports its own findings only when it is neither a
        # post-commit callback nor a local wrapper reached from another
        # function. Wrapper call sites report through the folded verdict at
        # the call itself, so the wrapper body is not reported a second time.
        wrapper_nodes = self._collect_wrapper_nodes()
        ambiguous_nodes = self._collect_ambiguous_nodes()
        for function in self._functions:
            if self._is_post_commit_callback(function):
                continue
            if function in wrapper_nodes or function in ambiguous_nodes:
                continue
            for finding in self._summaries.get(function, []):
                self._emit(finding)

    def _collect_functions(self, module_node):
        functions = []

        def collect(inner_node):
            if isinstance(
                inner_node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                functions.append(inner_node)

        tree.walk_callback(module_node, collect)
        return functions

    def _collect_dynamic_names(self, module_node):
        """Names assigned or imported rather than uniquely bound to a local
        def are dynamically bound and cannot be trusted as static wrappers.
        """
        dynamic = set()

        def collect(inner_node):
            if isinstance(inner_node, ast.Assign):
                for target in inner_node.targets:
                    if isinstance(target, ast.Name):
                        dynamic.add(target.id)
            elif isinstance(inner_node, ast.AnnAssign) and isinstance(
                inner_node.target, ast.Name
            ):
                dynamic.add(inner_node.target.id)
            elif isinstance(inner_node, (ast.Import, ast.ImportFrom)):
                for alias in inner_node.names:
                    dynamic.add(alias.asname or alias.name.split(".")[0])

        tree.walk_callback(module_node, collect)
        # A name that is both defined and later assigned/imported is kept:
        # the rebinding makes the static wrapper target untrustworthy.
        return dynamic

    def _is_post_commit_callback(self, function):
        for other in self._functions:
            for call in self._calls_in_scope(other):
                name = _call_name(call)
                if not name or not _any_match(
                    name, self.config.post_commit_callbacks
                ):
                    continue
                for argument in call.args:
                    if argument is function:
                        return True
                    if isinstance(argument, ast.Name) and self._refers_to(
                        argument.id, function
                    ):
                        return True
        return False

    def _refers_to(self, name, function):
        if function.name != name:
            return False
        candidates = [
            inner for inner in self._functions if inner.name == name
        ]
        return len(candidates) == 1 and candidates[0] is function

    def _summarize(self, function):
        """Compute one verdict per audit-relevant call reachable from this
        function's own scope; nested functions and local wrappers are
        summarized separately and referenced through their resolved verdict
        rather than inlined.
        """
        if function in self._summaries:
            return self._summaries[function]
        if function in self._resolving:
            # A recursive wrapper adds no ordering fact about itself.
            return []

        self._resolving.add(function)
        findings = []
        pending = []
        transaction_open = False

        def flush_pending(verdict_state, reason):
            while pending:
                queued = pending.pop(0)
                state = queued.state if verdict_state is None else verdict_state
                findings.append(
                    AuditVerdict(state, reason, queued.call)
                )

        for statement in function.body:
            if _is_docstring(statement):
                continue
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                # A nested scope keeps its own transaction state; analyze it
                # independently so its state never leaks into the outer one.
                self._summarize(statement)
                continue

            for call in self._calls_in_scope(statement):
                name = _call_name(call)
                if name is None:
                    verdict = self._dynamic_call_verdict(call)
                    if verdict is not None:
                        findings.append(verdict)
                    continue

                if _any_match(name, self.config.post_commit_callbacks):
                    self._classify_post_commit(call, findings)
                    continue

                if _any_match(name, self.config.rollback_functions):
                    # Everything written before a rollback stays confirmed
                    # even though the underlying action is being undone.
                    flush_pending(
                        UNSAFE,
                        "write precedes a rollback boundary, the confirmed "
                        "audit entry outlives the undone action",
                    )
                    transaction_open = False
                    continue

                if _any_match(name, self.config.commit_functions):
                    flush_pending(
                        SAFE,
                        "write is followed by a commit boundary before the "
                        "scope exits",
                    )
                    transaction_open = False
                    continue

                if _any_match(name, self.config.audit_write_functions):
                    pending.append(AuditVerdict(
                        PENDING,
                        "audit write awaits the transaction boundary",
                        call,
                    ))
                    transaction_open = True
                    continue

                if self._is_dynamic_sink_call(call, name):
                    findings.append(AuditVerdict(
                        UNKNOWN,
                        "call target is a dynamic expression, not a static "
                        "qualified name",
                        call,
                    ))
                    continue

                if _any_match(
                    name, self.config.outside_transaction_adapters
                ):
                    if transaction_open:
                        findings.append(AuditVerdict(
                            UNSAFE,
                            "outside-transaction adapter reached while a "
                            "transaction is open",
                            call,
                        ))
                    else:
                        findings.append(AuditVerdict(
                            SAFE,
                            "adapter used outside of any transaction",
                            call,
                        ))
                    continue

                wrapper = self._resolve_wrapper(name)
                if wrapper is None:
                    continue
                if wrapper == DYNAMIC:
                    findings.append(AuditVerdict(
                        UNKNOWN,
                        "wrapper is dynamically bound or shadowed",
                        call,
                    ))
                    continue

                wrapper_findings = self._summarize(wrapper)
                self._fold_wrapper(
                    call, name, wrapper_findings, findings, pending
                )

        # No boundary was reached before the scope exited. Keep the writes
        # neutral (PENDING): a wrapper lets its caller decide, while an entry
        # function treats a leftover PENDING write as vulnerable at emission.
        flush_pending(
            None,
            "no transaction boundary reached before the scope exited",
        )

        self._resolving.discard(function)
        self._summaries[function] = findings
        return findings

    def _classify_post_commit(self, call, findings):
        """A post-commit registrar is safe when its callback is a static
        local function or lambda. A dynamic callback cannot be followed and
        is reported as unknown. The callback body itself is never reported
        directly because it only runs after the transaction commits.
        """
        for argument in call.args:
            if isinstance(
                argument,
                (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                findings.append(AuditVerdict(
                    SAFE,
                    "callback is only invoked after the transaction commits",
                    call,
                ))
                continue

            if isinstance(argument, ast.Name):
                wrapper = self._resolve_wrapper(argument.id)
                if wrapper is None or wrapper == DYNAMIC:
                    findings.append(AuditVerdict(
                        UNKNOWN,
                        "post-commit callback is not a statically "
                        "resolvable function",
                        call,
                    ))
                else:
                    findings.append(AuditVerdict(
                        SAFE,
                        "callback is only invoked after the transaction "
                        "commits",
                        call,
                    ))
                continue

            findings.append(AuditVerdict(
                UNKNOWN,
                "post-commit callback is a dynamic expression",
                call,
            ))

    def _fold_wrapper(self, call, name, wrapper_findings, findings, pending):
        """Map a resolved wrapper internal findings onto the call site.

        Explicit UNSAFE / SAFE / UNKNOWN findings carry through. A neutral
        PENDING write inherits the caller transaction state by joining the
        local pending queue, so the surrounding boundary makes the final call.
        """
        if not wrapper_findings:
            # Empty stub wrapper (pass / docstring): no ordering fact yet.
            return
        if any(finding.state == UNKNOWN for finding in wrapper_findings):
            findings.append(AuditVerdict(
                UNKNOWN,
                "wrapper contains an unresolvable call",
                call,
            ))
            return
        if any(finding.state == UNSAFE for finding in wrapper_findings):
            pending.append(AuditVerdict(
                UNSAFE,
                "wrapper writes before the transaction boundary",
                call,
            ))
            return
        if any(finding.state == PENDING for finding in wrapper_findings):
            pending.append(AuditVerdict(
                PENDING,
                "wrapper write inherits the caller transaction state",
                call,
            ))
            return
        findings.append(AuditVerdict(
            SAFE,
            "wrapper only writes after commit",
            call,
        ))

    def _dynamic_call_verdict(self, call):
        """Resolve calls whose target is not a static name/attribute chain.

        A dynamic attribute call whose terminal name matches a configured
        sink is unknown. Unrelated dynamic calls stay silent. Bare name
        calls are handled through wrapper resolution instead.
        """
        func = call.func
        if not isinstance(func, ast.Attribute):
            return None

        terminal = func.attr
        configured = (
            self.config.audit_write_functions
            + self.config.outside_transaction_adapters
        )
        if any(
            configured_name.split(".")[-1] == terminal
            for configured_name in configured
        ):
            return AuditVerdict(
                UNKNOWN,
                "call target is a dynamic expression, not a static name",
                call,
            )
        return None

    def _collect_wrapper_nodes(self):
        """Local function definitions reached via a bare call from another
        function. Their findings are folded into the call site instead of
        being emitted independently.
        """
        nodes = set()
        for function in self._functions:
            for call in self._calls_in_scope(function):
                name = _call_name(call)
                if not name or "." in name:
                    continue
                wrapper = self._resolve_wrapper(name)
                if wrapper not in (None, DYNAMIC):
                    nodes.add(wrapper)
        return nodes

    def _collect_ambiguous_nodes(self):
        """Local definitions whose name is shared by more than one def.
        Calls to them resolve to DYNAMIC and are explained at the call site,
        so the ambiguous bodies are not emitted independently.
        """
        counts = {}
        for function in self._functions:
            counts[function.name] = counts.get(function.name, 0) + 1
        return set(
            function for function in self._functions
            if counts[function.name] > 1
        )

    def _is_dynamic_sink_call(self, call, name):
        """A qualified call is only trustworthy when it exactly matches a
        configured dotted name. A shorter dynamic chain ending on a sink
        attribute, e.g. get_logger().emit(...), cannot be bound statically.
        """
        func = call.func
        if not isinstance(func, ast.Attribute):
            return False

        configured = (
            self.config.audit_write_functions
            + self.config.outside_transaction_adapters
        )
        exact_match = any(
            _name_matches(name, configured_name)
            for configured_name in configured
        )
        if exact_match:
            return False

        terminal = name.split(".")[-1]
        return any(
            configured_name.split(".")[-1] == terminal
            for configured_name in configured
        )

    def _resolve_wrapper(self, name):
        """Resolve a bare local call to its unique function definition.

        Returns the function node when exactly one local definition binds
        the name, DYNAMIC when the name is rebound/imported or more than one
        same-named wrapper exists, and None when the name does not refer to
        a local wrapper.
        """
        if "." in name:
            # Attribute calls are external bindings we cannot follow.
            return None

        short_name = name.split(".")[-1]
        if short_name in self._dynamic_names:
            return DYNAMIC

        candidates = [
            function for function in self._functions
            if function.name == short_name
        ]
        if not candidates:
            return None
        if len(candidates) > 1:
            # Same-named wrappers in different scopes: without a confident
            # lexical binding we refuse to guess.
            return DYNAMIC
        return candidates[0]

    def _calls_in_scope(self, node):
        """Yield call nodes in statement order without crossing a nested
        function or class scope boundary.
        """
        calls = []
        scopes = (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.Lambda,
            ast.ClassDef,
        )

        def walk(inner_node):
            for child in ast.iter_child_nodes(inner_node):
                if isinstance(child, scopes):
                    continue
                if isinstance(child, ast.Call):
                    calls.append(child)
                walk(child)

        walk(node)
        return calls

    def _emit(self, finding):
        if finding.state == SAFE:
            return
        # A leftover PENDING write belongs to an entry function whose scope
        # exited without any boundary; conservatively treat it as vulnerable
        # to a rollback the linter cannot see in the same scope.
        message = (
            self._unknown_tmpl
            if finding.state == UNKNOWN
            else self._error_tmpl
        )
        self.results.append(
            base.Flake8Result(
                lineno=finding.call.lineno,
                col_offset=finding.call.col_offset,
                message=message,
            )
        )
