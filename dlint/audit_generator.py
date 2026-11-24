from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections
import textwrap


STATE_NOT_STARTED = 'not_started'
STATE_EARLY_CLOSE = 'early_close'
STATE_EARLY_BREAK = 'early_break'
STATE_EXHAUSTED = 'exhausted'
STATE_FINALLY_SUPPRESSED = 'finally_suppressed'
STATE_UNKNOWN_CONSUMER = 'unknown_consumer'

STATE_ORDER = (
    STATE_NOT_STARTED,
    STATE_EARLY_CLOSE,
    STATE_EARLY_BREAK,
    STATE_EXHAUSTED,
    STATE_FINALLY_SUPPRESSED,
    STATE_UNKNOWN_CONSUMER,
)

AuditGeneratorFinding = collections.namedtuple(
    'AuditGeneratorFinding',
    [
        'lineno',
        'col_offset',
        'state',
        'factory_name',
        'confirmation_lineno',
        'consumer_lineno',
        'suppression_lineno',
        'wrapper_name',
    ],
)


def _full_name(node):
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return '.'.join(reversed(parts))


def _call_name(call):
    if not isinstance(call, ast.Call):
        return ''
    return _full_name(call.func)


def is_audit_confirmation_call(node):
    if not isinstance(node, ast.Call):
        return False

    name = _call_name(node).lower()
    leaf = name.rsplit('.', 1)[-1]
    tokens = set(leaf.split('_'))
    confirmation_tokens = {
        'confirm', 'confirmation', 'commit', 'complete', 'finish',
        'ack', 'acknowledge', 'record', 'report', 'save', 'send', 'flush',
    }
    exact_names = {
        'audit_ok', 'audit_done', 'audit_success', 'audit_finished',
        'audit_complete', 'audit_confirmed',
    }

    if leaf in exact_names:
        return True
    if 'audit' in name and tokens & confirmation_tokens:
        return True

    func = node.func
    if isinstance(func, ast.Attribute):
        owner = _full_name(func.value).lower()
        if 'audit' in owner and (
            func.attr.lower() in confirmation_tokens
            or set(func.attr.lower().split('_')) & confirmation_tokens
        ):
            return True

    return False


def _has_yield(node):
    return any(
        isinstance(child, (ast.Yield, ast.YieldFrom))
        for child in ast.walk(node)
    )


def _last_confirmation(func):
    calls = [
        child for child in ast.walk(func)
        if is_audit_confirmation_call(child)
    ]
    if not calls:
        return None
    return max(calls, key=lambda item: (item.lineno, item.col_offset))


def _matches_audit_decorator(node):
    name = _full_name(node.func if isinstance(node, ast.Call) else node)
    leaf = name.rsplit('.', 1)[-1].lower()
    return 'audit' in leaf or leaf in {'audited', 'audit_generator'}


def _find_finally_suppression(func):
    for node in ast.walk(func):
        if not isinstance(node, ast.Try) or not node.finalbody:
            continue
        for statement in node.finalbody:
            for child in ast.walk(statement):
                if isinstance(child, ast.Return):
                    nested = False
                    for scope in ast.walk(statement):
                        if isinstance(
                            scope,
                            (ast.FunctionDef, ast.AsyncFunctionDef),
                        ) and scope is not child and child in ast.walk(scope):
                            nested = True
                    if not nested:
                        return child
    return None


def analyze_source(source):
    return AuditGeneratorAnalyzer().analyze(
        ast.parse(textwrap.dedent(source))
    )


class _GeneratorInstance(object):
    __slots__ = (
        'factory_name', 'call_node', 'wrapper_name', 'started',
        'last_node', 'state',
    )

    def __init__(self, factory_name, call_node, wrapper_name):
        self.factory_name = factory_name
        self.call_node = call_node
        self.wrapper_name = wrapper_name
        self.started = False
        self.last_node = call_node
        self.state = None


class AuditGeneratorAnalyzer(object):
    def __init__(self):
        self.factories = {}
        self.wrappers = {}
        self.confirmation_lines = {}
        self.suppression_nodes = {}

    def analyze(self, tree):
        if isinstance(tree, str):
            tree = ast.parse(textwrap.dedent(tree))

        functions = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        for func in functions:
            if not _has_yield(func):
                continue
            confirmation = _last_confirmation(func)
            audit_named = 'audit' in func.name.lower()
            audited = any(
                _matches_audit_decorator(decorator)
                for decorator in func.decorator_list
            )
            if confirmation is None and not audit_named and not audited:
                continue

            self.factories[func.name] = func
            if confirmation is not None:
                self.confirmation_lines[func.name] = confirmation.lineno
            suppression = _find_finally_suppression(func)
            if suppression is not None:
                self.suppression_nodes[func.name] = suppression

        for func in functions:
            if func.name in self.factories:
                continue
            target = self._wrapper_target(func)
            if target is not None:
                self.wrappers[func.name] = target

        scopes = [tree]
        scopes.extend(
            func for func in functions
            if func.name not in self.factories
            and func.name not in self.wrappers
        )

        findings = []
        for scope in scopes:
            findings.extend(_ScopeAnalyzer(self, scope).run())

        return sorted(
            findings,
            key=lambda finding: (
                finding.lineno,
                finding.col_offset,
                finding.state,
            ),
        )

    def _call_factory_name(self, call):
        function = call.func
        if isinstance(function, ast.Name):
            name = function.id
        elif isinstance(function, ast.Attribute):
            name = function.attr
        else:
            return None
        return name if name in self.factories else None

    def _wrapper_target(self, func):
        for node in ast.walk(func):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
                target = self._call_factory_name(node.value)
                if target is not None:
                    return target
            if isinstance(node, ast.YieldFrom) and isinstance(node.value, ast.Call):
                target = self._call_factory_name(node.value)
                if target is not None:
                    return target
        return None


_EAGER_CONSUMER_NAMES = frozenset((
    'list', 'tuple', 'set', 'frozenset', 'dict', 'sum', 'min', 'max',
    'any', 'all', 'sorted',
))
_LAZY_ADAPTER_NAMES = frozenset((
    'iter', 'enumerate', 'zip', 'map', 'filter', 'reversed',
))


def _first_direct_break(statements):
    for statement in statements:
        found = _search_direct_break(statement)
        if found is not None:
            return found
    return None


def _search_direct_break(node):
    if isinstance(node, ast.Break):
        return node
    if isinstance(
        node,
        (
            ast.For, ast.AsyncFor, ast.While,
            ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
        ),
    ):
        return None

    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.AST):
            found = _search_direct_break(child)
            if found is not None:
                return found
    return None


class _ScopeAnalyzer(object):
    def __init__(self, owner, scope):
        self.owner = owner
        self.scope = scope
        self.bindings = {}
        self.local_callables = {}
        self.instances = []
        self.findings = []
        self.active_iterators = []

    def run(self):
        for statement in self.scope.body:
            self.statement(statement)

        for instance in self.instances:
            if instance.state is not None:
                continue
            if instance.started:
                self.finish(
                    instance,
                    STATE_UNKNOWN_CONSUMER,
                    instance.last_node or instance.call_node,
                    instance.last_node or instance.call_node,
                )
            else:
                self.finish(
                    instance,
                    STATE_NOT_STARTED,
                    instance.call_node,
                    instance.call_node,
                )

        return self.findings

    def statement(self, node):
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            return

        if isinstance(node, ast.Assign):
            self.handle_assignment(node)
        elif isinstance(node, ast.AnnAssign):
            self.handle_ann_assignment(node)
        elif isinstance(node, ast.Expr):
            self.expression(node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.handle_for(node)
        elif isinstance(node, ast.While):
            self.handle_while(node)
        elif isinstance(node, ast.If):
            self.expression(node.test)
            self.statements(node.body)
            self.statements(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            self.handle_with(node)
        elif isinstance(node, ast.Try):
            self.handle_try(node)
        elif isinstance(node, ast.Return):
            self.handle_return(node)
        elif isinstance(node, (ast.Raise, ast.Delete)):
            self.handle_escape_statement(node)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.stmt):
                    self.statement(child)

    def statements(self, nodes):
        for node in nodes:
            self.statement(node)

    def handle_assignment(self, node):
        instances = self.expression(node.value)
        if not instances and isinstance(node.value, ast.Name):
            resolved = self.resolve_named_callable(node.value.id)
            if resolved is not None:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.local_callables[target.id] = resolved

        if instances:
            instance = instances[0]
            for target in node.targets:
                self.bind_target(target, instance)

    def handle_ann_assignment(self, node):
        if node.value is None:
            return
        instances = self.expression(node.value)
        if instances and isinstance(node.target, ast.Name):
            self.bindings[node.target.id] = instances[0]

    def bind_target(self, target, instance):
        if isinstance(target, ast.Name):
            self.bindings[target.id] = instance
        elif isinstance(target, ast.Starred):
            self.bind_target(target.value, instance)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind_target(element, instance)
        else:
            self.finish(instance, STATE_UNKNOWN_CONSUMER, target, target)

    def handle_for(self, node):
        instances = self.expression(node.iter)
        break_node = _first_direct_break(node.body)

        for instance in instances:
            instance.started = True
            instance.last_node = node
            if break_node is not None:
                self.finish(
                    instance,
                    STATE_EARLY_BREAK,
                    break_node,
                    break_node,
                )

        self.active_iterators.append(instances)
        self.statements(node.body)
        self.active_iterators.pop()

        if break_node is None:
            for instance in instances:
                self.finish(instance, STATE_EXHAUSTED, node, node)

        self.statements(node.orelse)

    def handle_while(self, node):
        self.expression(node.test)
        self.statements(node.body)
        self.statements(node.orelse)

    def handle_with(self, node):
        for item in node.items:
            instances = self.expression(item.context_expr)
            if item.optional_vars is not None and instances:
                self.bind_target(item.optional_vars, instances[0])
        self.statements(node.body)

    def handle_try(self, node):
        self.statements(node.body)
        for handler in node.handlers:
            if handler.type is not None:
                self.expression(handler.type)
            self.statements(handler.body)
        self.statements(node.orelse)
        self.statements(node.finalbody)

    def handle_return(self, node):
        for instance in self.expression(node.value):
            self.finish(instance, STATE_UNKNOWN_CONSUMER, node, node)
        self.escape_active_iterators(node)

    def handle_escape_statement(self, node):
        if isinstance(node, ast.Delete):
            for target in node.targets:
                for instance in self.expression(target):
                    self.finish(instance, STATE_UNKNOWN_CONSUMER, node, node)
        self.escape_active_iterators(node)

    def escape_active_iterators(self, node):
        for instances in reversed(self.active_iterators):
            for instance in instances:
                self.finish(instance, STATE_UNKNOWN_CONSUMER, node, node)

    def resolve_named_callable(self, name):
        if name in self.local_callables:
            return self.local_callables[name]
        if name in self.owner.wrappers:
            return self.owner.wrappers[name], name
        if name in self.owner.factories:
            return name, None
        return None

    def resolve_factory(self, call):
        function = call.func
        if isinstance(function, ast.Name):
            return self.resolve_named_callable(function.id)
        if isinstance(function, ast.Attribute):
            if function.attr in self.owner.wrappers:
                return self.owner.wrappers[function.attr], function.attr
            if function.attr in self.owner.factories:
                return function.attr, None
        return None

    def expression(self, node):
        if node is None:
            return []
        if isinstance(node, ast.Name):
            instance = self.bindings.get(node.id)
            return [instance] if instance is not None else []
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.Starred):
            return self.expression(node.value)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            instances = []
            for element in node.elts:
                instances.extend(self.expression(element))
            return instances
        if isinstance(node, ast.Dict):
            instances = []
            for value in node.values:
                instances.extend(self.expression(value))
            return instances
        if isinstance(node, (ast.Attribute, ast.Lambda)):
            return []

        instances = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                instances.extend(self.expression(child))
        return instances

    def call(self, node):
        factory = self.resolve_factory(node)
        if factory is not None:
            factory_name, wrapper_name = factory
            instance = _GeneratorInstance(
                factory_name,
                node,
                wrapper_name,
            )
            self.instances.append(instance)
            return [instance]

        function = node.func
        owner_instances = []
        if isinstance(function, ast.Attribute):
            owner_instances = self.expression(function.value)
            if function.attr == 'close':
                for instance in self.unique(owner_instances):
                    self.close_instance(instance, node)
                return []
            if function.attr in {'send', '__next__'}:
                for instance in self.unique(owner_instances):
                    instance.started = True
                    instance.last_node = node
                return []

        name = ''
        if isinstance(function, ast.Name):
            name = function.id
        elif isinstance(function, ast.Attribute):
            name = function.attr
            owner_instances = []

        argument_instances = list(owner_instances)
        if isinstance(function, ast.Name):
            argument_instances.extend(self.expression(function))
        for argument in node.args:
            argument_instances.extend(self.expression(argument))
        for keyword in node.keywords:
            argument_instances.extend(self.expression(keyword.value))
        instances = self.unique(argument_instances)

        if name in {'next', 'anext'} and node.args:
            for instance in self.unique(self.expression(node.args[0])):
                instance.started = True
                instance.last_node = node
            return []

        eager_consumers = {
            'list', 'tuple', 'set', 'frozenset', 'dict', 'sum', 'min',
            'max', 'any', 'all', 'sorted',
        }
        lazy_adapters = {
            'iter', 'enumerate', 'zip', 'map', 'filter', 'reversed',
        }

        if name in eager_consumers:
            for instance in instances:
                self.finish(instance, STATE_EXHAUSTED, node, node)
            return []
        if name in lazy_adapters:
            return instances

        for instance in instances:
            self.finish(instance, STATE_UNKNOWN_CONSUMER, node, node)
        return []

    def unique(self, instances):
        result = []
        for instance in instances:
            if not isinstance(instance, _GeneratorInstance):
                continue
            if instance not in result:
                result.append(instance)
        return result

    def close_instance(self, instance, node):
        if instance.state is not None:
            return
        instance.last_node = node
        if not instance.started:
            self.finish(instance, STATE_NOT_STARTED, instance.call_node, node)
        else:
            self.finish(instance, STATE_EARLY_CLOSE, node, node)

    def finish(self, instance, state, line_node, consumer_node):
        if instance.state is not None:
            return

        suppression_node = self.owner.suppression_nodes.get(
            instance.factory_name
        )
        primary_node = line_node
        if state in {STATE_EARLY_CLOSE, STATE_EARLY_BREAK} and suppression_node:
            state = STATE_FINALLY_SUPPRESSED
            primary_node = suppression_node

        instance.state = state
        finding = AuditGeneratorFinding(
            lineno=primary_node.lineno,
            col_offset=primary_node.col_offset,
            state=state,
            factory_name=instance.factory_name,
            confirmation_lineno=self.owner.confirmation_lines.get(
                instance.factory_name
            ),
            consumer_lineno=getattr(consumer_node, 'lineno', None),
            suppression_lineno=(
                suppression_node.lineno
                if state == STATE_FINALLY_SUPPRESSED and suppression_node
                else None
            ),
            wrapper_name=instance.wrapper_name,
        )
        self.findings.append(finding)
