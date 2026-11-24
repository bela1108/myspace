# TOCTOU descriptor-flow tracing support.

from __future__ import absolute_import, division, print_function, unicode_literals

import ast
import contextlib
import os
import shutil
import tempfile
from collections import namedtuple

from . import tree

SAFE = 'safe'
PROVEN = SAFE
RACE = 'race'
RACY = RACE
UNKNOWN = 'unknown'
UNDECIDABLE = UNKNOWN

_DESC = 'desc'
_PATH = 'path'

Location = namedtuple('Location', ('line', 'column'))


def _location(node):
    if node is None:
        return Location(0, 0)
    return Location(node.lineno, node.col_offset)


def open_safe(path, flags=os.O_RDONLY, mode=0o600):
    closed_flags = flags | getattr(os, 'O_CLOEXEC', 0)
    return os.open(os.fspath(path), closed_flags, mode)


class Diagnostic(object):
    def __init__(self, status, message, check_node, use_node,
                 rename_node=None, path_key=None, descriptor_id=None):
        self.status = status
        self.verdict = status
        self.kind = status
        self.state = status
        self.message = message
        self.check_node = check_node
        self.use_node = use_node
        self.rename_node = rename_node
        self.check_location = _location(check_node)
        self.use_location = _location(use_node)
        self.rename_location = _location(rename_node)
        self.path_key = path_key
        self.descriptor_id = descriptor_id

    @property
    def check_line(self):
        return self.check_location.line

    @property
    def check_column(self):
        return self.check_location.column

    @property
    def use_line(self):
        return self.use_location.line

    @property
    def use_column(self):
        return self.use_location.column

    @property
    def lineno(self):
        return self.use_location.line

    @property
    def col_offset(self):
        return self.use_location.column

    def __iter__(self):
        yield self.status
        yield self.check_location
        yield self.use_location

    def __repr__(self):
        return 'Diagnostic({}, check={}, use={})'.format(
            self.status, self.check_location, self.use_location)


class AnalysisReport(object):
    def __init__(self, diagnostics):
        self.diagnostics = diagnostics
        self.findings = diagnostics
        self.flows = diagnostics

    def _with_status(self, status):
        return [item for item in self.diagnostics if item.status == status]

    @property
    def safe(self):
        return self._with_status(SAFE)

    @property
    def proven(self):
        return self.safe

    @property
    def races(self):
        return self._with_status(RACE)

    @property
    def unknown(self):
        return self._with_status(UNKNOWN)

    @property
    def undecidable(self):
        return self.unknown

    def by_status(self, status):
        return self._with_status(status)

    def __iter__(self):
        return iter(self.diagnostics)

    def __len__(self):
        return len(self.diagnostics)


class TOCTOUAnalyzer(object):
    check_bases = frozenset((
        'exists', 'lexists', 'isfile', 'is_file', 'isdir', 'is_dir',
        'islink', 'is_symlink', 'access', 'stat', 'lstat',
    ))
    check_names = frozenset((
        'check_path', 'check_file', 'is_safe_path', 'validate_path',
        'verify_path', 'authorize_path', 'allowed_path', 'security_check',
    ))
    open_names = frozenset(('open_safe', 'safe_open'))
    read_methods = frozenset(('read', 'read1', 'readline', 'readlines', 'readinto'))
    path_read_methods = frozenset(('read_text', 'read_bytes'))
    known_bases = frozenset((
        'print', 'len', 'range', 'repr', 'str', 'bytes', 'int', 'float',
        'bool', 'list', 'tuple', 'set', 'dict', 'isinstance', 'issubclass',
        'getattr', 'setattr', 'hasattr', 'open', 'fdopen', 'close', 'fstat',
        'lseek', 'seek', 'tell', 'dup', 'dup2', 'fileno', 'fcntl', 'flock',
    ))

    def analyze(self, source):
        node = ast.parse(source) if isinstance(source, str) else source
        self.diagnostics = []
        self._seen = set()
        self._order = 0
        self._checks = {}
        self._renames = {}
        self._descriptors = {}
        self._exec_block(node.body, {})
        self._finalize()
        return AnalysisReport(self.diagnostics)

    analyze_source = analyze

    def _next_order(self):
        self._order += 1
        return self._order

    def _add(self, diagnostic, key):
        if key in self._seen:
            return
        self._seen.add(key)
        self.diagnostics.append(diagnostic)

    def _call_name(self, node):
        try:
            return tree.module_path_str(node.func)
        except Exception:
            if isinstance(node.func, ast.Name):
                return node.func.id
            if isinstance(node.func, ast.Attribute):
                return node.func.attr
            return ''

    def _base_name(self, full_name, node):
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return full_name.split('.')[-1]

    def _path_key(self, node, env):
        if node is None:
            return None
        tokens = self._eval(node, env)
        for kind, value in tokens:
            if kind == _PATH:
                return value
        if isinstance(node, ast.Name):
            return 'name:' + node.id
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return 'literal:str:' + node.value
            if isinstance(node.value, bytes):
                return 'literal:bytes:' + repr(node.value)
        if isinstance(node, ast.Call) and node.args:
            return self._path_key(node.args[0], env)
        return 'expr:' + ast.dump(node)

    def _eval(self, node, env):
        if node is None:
            return frozenset()
        if isinstance(node, ast.Name):
            return frozenset(env.get(node.id, ()))
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, bytes)):
                return frozenset(((_PATH, 'literal:' + type(node.value).__name__ + ':' + repr(node.value)),))
            return frozenset()
        if isinstance(node, ast.Attribute):
            key = 'storage:' + ast.dump(node)
            if key in env:
                return frozenset(env[key])
            self._eval(node.value, env)
            return frozenset()
        if isinstance(node, ast.Subscript):
            key = 'storage:' + ast.dump(node)
            return frozenset(env.get(key, ()))
        if isinstance(node, ast.Call):
            return frozenset(self._eval_call(node, env))
        if isinstance(node, ast.NamedExpr):
            values = self._eval(node.value, env)
            self._bind_name(node.target, values, env)
            return frozenset(values)
        if isinstance(node, ast.Await):
            return self._eval(node.value, env)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            result = set()
            for child in node.elts:
                result.update(self._eval(child, env))
            return frozenset(result)
        if isinstance(node, ast.Dict):
            result = set()
            for child in list(node.keys) + list(node.values):
                result.update(self._eval(child, env))
            return frozenset(result)
        if isinstance(node, ast.IfExp):
            result = set(self._eval(node.body, env))
            result.update(self._eval(node.orelse, env))
            self._eval(node.test, env)
            return frozenset(result)
        if isinstance(node, ast.BoolOp):
            result = set()
            for child in node.values:
                result.update(self._eval(child, env))
            return frozenset(result)
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, env)
        if isinstance(node, ast.BinOp):
            result = set(self._eval(node.left, env))
            result.update(self._eval(node.right, env))
            return frozenset(result)
        for child in ast.iter_child_nodes(node):
            self._eval(child, env)
        return frozenset()

    def _eval_call(self, call, env):
        full_name = self._call_name(call)
        base = self._base_name(full_name, call)
        receiver_tokens = set()
        if isinstance(call.func, ast.Attribute):
            receiver_tokens.update(self._eval(call.func.value, env))
        elif not isinstance(call.func, ast.Name):
            self._eval(call.func, env)

        arg_tokens = []
        for arg in call.args:
            arg_tokens.append(set(self._eval(arg, env)))
        keyword_tokens = {}
        for keyword in call.keywords:
            keyword_tokens[keyword.arg] = set(self._eval(keyword.value, env))

        path_node = self._path_argument(call)
        path_key = self._path_key(path_node, env) if path_node is not None else None

        if self._is_check_call(full_name, base):
            self._record_check(call, path_node, path_key)
            return set()

        if full_name in ('os.rename', 'os.replace', 'shutil.move') or base == 'rename':
            self._record_rename(call, path_node, path_key)
            return set()

        if base in self.open_names or full_name.split('.')[-1] in self.open_names:
            descriptor_id = self._create_open_safe(call, path_node, path_key)
            return {(_DESC, descriptor_id)}

        read_tokens = self._read(call, base, full_name, receiver_tokens, arg_tokens, path_node, path_key, env)
        if read_tokens is not None:
            return read_tokens

        open_tokens = self._open_like(call, base, full_name, receiver_tokens, arg_tokens, path_node, path_key)
        if open_tokens is not None:
            return open_tokens

        self._external_helper(call, base, full_name, arg_tokens, keyword_tokens, path_key)
        return set()

    def _path_argument(self, call):
        if call.args:
            return call.args[0]
        for keyword in call.keywords:
            if keyword.arg in ('path', 'filename', 'file', 'name'):
                return keyword.value
        if isinstance(call.func, ast.Attribute):
            return call.func.value
        return None

    def _is_check_call(self, full_name, base):
        return base in self.check_bases or full_name in self.check_names or base in self.check_names

    def _record_check(self, call, path_node, path_key):
        if path_key is None:
            return
        check = {'node': call, 'order': self._next_order(), 'path_key': path_key}
        self._checks.setdefault(path_key, []).append(check)

    def _record_rename(self, call, path_node, path_key):
        if path_key is None:
            return
        rename = {'node': call, 'order': self._next_order(), 'path_key': path_key}
        self._renames.setdefault(path_key, []).append(rename)

    def _latest_check(self, path_key, before_order):
        checks = [item for item in self._checks.get(path_key, []) if item['order'] < before_order]
        return checks[-1] if checks else None

    def _verdict(self, path_key, use_order):
        check = self._latest_check(path_key, use_order)
        if check is None:
            return None, None, None
        rename = None
        for item in self._renames.get(path_key, []):
            if check['order'] < item['order'] < use_order:
                rename = item
        if rename is not None:
            return check, rename, RACE
        return check, None, UNKNOWN

    def _create_open_safe(self, call, path_node, path_key):
        descriptor_id = len(self._descriptors) + 1
        order = self._next_order()
        check = self._latest_check(path_key, order) if path_key else None
        self._descriptors[descriptor_id] = {
            'kind': 'open_safe', 'node': call, 'order': order,
            'path_key': path_key, 'check': check, 'proven': False,
            'terminal': False, 'helper': False,
        }
        return descriptor_id

    def _descriptor_ids(self, tokens):
        return [value for kind, value in tokens if kind == _DESC]

    def _copy_env(self, env):
        return dict((key, set(values)) for key, values in env.items())

    def _merge_env(self, target, source):
        for key, values in source.items():
            target.setdefault(key, set()).update(values)

    def _storage_key(self, node):
        return 'storage:' + ast.dump(node)

    def _exec_block(self, statements, env, handlers=None):
        for statement in statements:
            if handlers:
                for handler in handlers:
                    handler_env = self._copy_env(env)
                    if handler.name:
                        handler_env[handler.name] = set()
                    self._exec_block(handler.body, handler_env)
            self._exec_statement(statement, env)

    def _bind_name(self, target, tokens, env):
        if isinstance(target, ast.Name):
            env[target.id] = set(tokens)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            env[self._storage_key(target)] = set(tokens)
        elif isinstance(target, ast.Starred):
            self._bind_name(target.value, tokens, env)

    def _bind_target(self, target, value_node, tokens, env):
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value_node, (ast.Tuple, ast.List)) and len(value_node.elts) == len(target.elts):
                for sub_target, sub_value in zip(target.elts, value_node.elts):
                    sub_tokens = self._eval(sub_value, env)
                    self._bind_target(sub_target, sub_value, sub_tokens, env)
                return
            for sub_target in target.elts:
                self._bind_target(sub_target, None, tokens, env)
            return
        self._bind_name(target, tokens, env)

    def _exec_statement(self, statement, env):
        if isinstance(statement, ast.Assign):
            tokens = self._eval(statement.value, env)
            for target in statement.targets:
                self._bind_target(target, statement.value, tokens, env)
            return

        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                tokens = self._eval(statement.value, env)
                self._bind_target(statement.target, statement.value, tokens, env)
            return

        if isinstance(statement, ast.AugAssign):
            values = set(self._eval(statement.value, env))
            values.update(self._eval(statement.target, env))
            self._bind_target(statement.target, statement.value, values, env)
            return

        if isinstance(statement, ast.Expr):
            self._eval(statement.value, env)
            return

        if isinstance(statement, ast.Return):
            tokens = self._eval(statement.value, env) if statement.value is not None else set()
            self._return_boundary(statement, tokens)
            return

        if isinstance(statement, ast.Raise):
            if statement.exc is not None:
                self._eval(statement.exc, env)
            if statement.cause is not None:
                self._eval(statement.cause, env)
            return

        if isinstance(statement, ast.Assert):
            self._eval(statement.test, env)
            if statement.msg is not None:
                self._eval(statement.msg, env)
            return

        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in env:
                    del env[target.id]
            return

        if isinstance(statement, (ast.Pass, ast.Break, ast.Continue,
                                  ast.Import, ast.ImportFrom, ast.Global,
                                  ast.Nonlocal)):
            return

        if isinstance(statement, ast.If):
            self._eval(statement.test, env)
            body_env = self._copy_env(env)
            else_env = self._copy_env(env)
            self._exec_block(statement.body, body_env)
            self._exec_block(statement.orelse, else_env)
            merged = self._copy_env(env)
            self._merge_env(merged, body_env)
            self._merge_env(merged, else_env)
            env.clear()
            self._merge_env(env, merged)
            return

        if isinstance(statement, (ast.While,)):
            self._eval(statement.test, env)
            self._exec_block(statement.body, env)
            self._exec_block(statement.body, env)
            self._exec_block(statement.orelse, env)
            return

        if isinstance(statement, (ast.For, getattr(ast, 'AsyncFor', ()))):
            tokens = self._eval(statement.iter, env)
            self._bind_target(statement.target, None, tokens, env)
            self._exec_block(statement.body, env)
            self._exec_block(statement.body, env)
            self._exec_block(statement.orelse, env)
            return

        if isinstance(statement, (ast.With, getattr(ast, 'AsyncWith', ()))):
            for item in statement.items:
                tokens = self._eval(item.context_expr, env)
                if item.optional_vars is not None:
                    self._bind_target(item.optional_vars, item.context_expr, tokens, env)
            self._exec_block(statement.body, env)
            return

        if isinstance(statement, ast.Try):
            before = self._copy_env(env)
            self._exec_block(statement.body, env, statement.handlers)
            self._exec_block(statement.orelse, env)
            final_env = self._copy_env(before)
            self._merge_env(final_env, env)
            self._exec_block(statement.finalbody, final_env)
            env.clear()
            self._merge_env(env, final_env)
            return

        if isinstance(statement, (ast.FunctionDef, getattr(ast, 'AsyncFunctionDef', ()))):
            for default in statement.args.defaults:
                self._eval(default, env)
            for decorator in statement.decorator_list:
                self._eval(decorator, env)
            local_env = {}
            arguments = statement.args
            for arg in list(getattr(arguments, 'posonlyargs', ())) + list(arguments.args) + list(arguments.kwonlyargs):
                local_env[arg.arg] = set()
            if arguments.vararg is not None:
                local_env[arguments.vararg.arg] = set()
            if arguments.kwarg is not None:
                local_env[arguments.kwarg.arg] = set()
            self._exec_block(statement.body, local_env)
            return

        if isinstance(statement, ast.ClassDef):
            for base in statement.bases:
                self._eval(base, env)
            self._exec_block(statement.body, self._copy_env(env))
            return

        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.stmt):
                self._exec_statement(child, env)
            else:
                self._eval(child, env)

    def _return_boundary(self, node, tokens):
        for kind, value in tokens:
            if kind != _DESC:
                continue
            descriptor = self._descriptors[value]
            if descriptor['kind'] != 'open_safe' or descriptor['proven'] or descriptor['terminal']:
                continue
            descriptor['terminal'] = True
            check = descriptor['check']
            check_node = check['node'] if check else descriptor['node']
            diagnostic = Diagnostic(
                UNKNOWN,
                'descriptor leaves the function before a same-descriptor read',
                check_node, node, path_key=descriptor['path_key'],
                descriptor_id=value,
            )
            self._add(diagnostic, ('return', value, id(node)))

    def _read(self, call, base, full_name, receiver_tokens, arg_tokens,
              path_node, path_key, env):
        target_tokens = None

        if full_name in ('os.read', 'os.pread', 'os.readv'):
            target_tokens = arg_tokens[0] if arg_tokens else set()
        elif isinstance(call.func, ast.Attribute) and base in self.read_methods:
            target_tokens = receiver_tokens
        elif base == 'read' and not isinstance(call.func, ast.Attribute):
            target_tokens = arg_tokens[0] if arg_tokens else set()
        elif isinstance(call.func, ast.Attribute) and base in self.path_read_methods:
            key = path_key
            if key is None:
                key = self._path_key(call.func.value, env)
            order = self._next_order()
            check, rename, status = self._verdict(key, order)
            if check is not None:
                self._emit_path_use(status, check, rename, call, call, key)
            return frozenset()
        else:
            return None

        descriptor_ids = self._descriptor_ids(target_tokens or ())
        if not descriptor_ids:
            return frozenset()

        for descriptor_id in descriptor_ids:
            descriptor = self._descriptors[descriptor_id]
            if descriptor['kind'] == 'open_safe':
                if not descriptor['proven']:
                    descriptor['proven'] = True
                    self._emit_proven(descriptor, call)
            elif not descriptor['terminal']:
                descriptor['terminal'] = True
                self._emit_descriptor_verdict(descriptor, call)

        return frozenset()

    def _open_like(self, call, base, full_name, receiver_tokens, arg_tokens,
                   path_node, path_key):
        is_open = (
            base in ('open', 'fdopen')
            or full_name in ('io.open', 'codecs.open')
            or (isinstance(call.func, ast.Attribute) and base == 'open')
        )
        if not is_open:
            return None

        first_tokens = arg_tokens[0] if arg_tokens else receiver_tokens
        descriptor_ids = self._descriptor_ids(first_tokens)
        if descriptor_ids:
            return set(first_tokens)

        if path_key is None and path_node is not None:
            path_key = self._path_key(path_node, {})
        order = self._next_order()
        check, rename, status = self._verdict(path_key, order)
        descriptor_id = len(self._descriptors) + 1
        self._descriptors[descriptor_id] = {
            'kind': 'string_open', 'node': call, 'order': order,
            'path_key': path_key, 'check': check, 'rename': rename,
            'status': status, 'resolution': call, 'proven': False,
            'terminal': False, 'helper': False,
        }
        return {(_DESC, descriptor_id)}

    def _external_helper(self, call, base, full_name, arg_tokens,
                         keyword_tokens, path_key):
        if base in self.known_bases or base in self.read_methods:
            return
        if full_name.startswith((
                'os.', 'io.', 'stat.', 'pathlib.', 'tempfile.', 'shutil.',
                'errno.', 'fcntl.', 'codecs.', 'builtins.')):
            return

        order = self._next_order()
        tokens = []
        for values in arg_tokens:
            tokens.extend(values)
        for values in keyword_tokens.values():
            tokens.extend(values)

        reported = False
        for kind, value in tokens:
            if kind == _DESC:
                descriptor = self._descriptors[value]
                if descriptor['kind'] != 'open_safe' or descriptor['terminal']:
                    continue
                descriptor['terminal'] = True
                descriptor['helper'] = True
                check = descriptor['check']
                if check is None and descriptor['path_key']:
                    check = self._latest_check(descriptor['path_key'], order)
                if check is None:
                    continue
                check_node = check['node'] if check else descriptor['node']
                diagnostic = Diagnostic(
                    UNKNOWN,
                    'descriptor passed to external helper; same-descriptor read is unproven',
                    check_node, call, path_key=descriptor['path_key'],
                    descriptor_id=value,
                )
                self._add(diagnostic, ('helper', value, id(call)))
                reported = True
            elif kind == _PATH:
                check = self._latest_check(value, order)
                if check is None:
                    continue
                diagnostic = Diagnostic(
                    UNKNOWN,
                    'path passed to external helper; path may be re-resolved',
                    check['node'], call, path_key=value,
                )
                self._add(diagnostic, ('path-helper', value, id(call)))
                reported = True

        if not reported and path_key is not None:
            check = self._latest_check(path_key, order)
            if check is not None:
                diagnostic = Diagnostic(
                    UNKNOWN,
                    'external helper prevents same-descriptor proof',
                    check['node'], call, path_key=path_key,
                )
                self._add(diagnostic, ('helper-path-key', path_key, id(call)))

    def _emit_proven(self, descriptor, read_node):
        check = descriptor['check']
        check_node = check['node'] if check else descriptor['node']
        diagnostic = Diagnostic(
            SAFE,
            'path check flows through open_safe to one descriptor read',
            check_node, read_node, path_key=descriptor['path_key'],
            descriptor_id=descriptor['id'] if 'id' in descriptor else None,
        )
        self._add(diagnostic, ('safe', descriptor['order'], id(read_node)))

    def _emit_descriptor_verdict(self, descriptor, use_node):
        check = descriptor.get('check')
        rename = descriptor.get('rename')
        status = descriptor.get('status') or UNKNOWN
        check_node = check['node'] if check else descriptor['node']
        message = (
            'rename occurred between path check and string re-resolution'
            if status == RACE else
            'string path was re-resolved instead of reading the original descriptor'
        )
        diagnostic = Diagnostic(
            status, message, check_node, use_node,
            rename_node=rename['node'] if rename else None,
            path_key=descriptor['path_key'],
        )
        self._add(diagnostic, (status, 'reopen', descriptor['order'], id(use_node)))

    def _emit_path_use(self, status, check, rename, resolution_node,
                       use_node, path_key, descriptor_id):
        message = (
            'rename occurred between path check and path read'
            if status == RACE else
            'path string was re-resolved instead of reading one descriptor'
        )
        diagnostic = Diagnostic(
            status, message, check['node'], use_node,
            rename_node=rename['node'] if rename else None,
            path_key=path_key, descriptor_id=descriptor_id,
        )
        self._add(diagnostic, (status, 'path-use', path_key, id(use_node)))

    def _finalize(self):
        for descriptor_id, descriptor in self._descriptors.items():
            if descriptor['kind'] == 'string_open' and not descriptor['terminal']:
                descriptor['terminal'] = True
                self._emit_descriptor_verdict(descriptor, descriptor['node'])
            elif (descriptor['kind'] == 'open_safe'
                  and not descriptor['proven']
                  and not descriptor['terminal']):
                check = descriptor['check']
                if check is None:
                    continue
                check_node = check['node']
                diagnostic = Diagnostic(
                    UNKNOWN,
                    'open_safe descriptor was not read; same-descriptor proof is absent',
                    check_node, descriptor['node'],
                    path_key=descriptor['path_key'],
                    descriptor_id=descriptor_id,
                )
                self._add(diagnostic, ('final-open-safe', descriptor_id))


def analyze(source):
    return TOCTOUAnalyzer().analyze(source)


def analyze_source(source):
    return analyze(source)


def find_toctou(source):
    return analyze(source).diagnostics


def trace_open_safe(source):
    return analyze(source)


OpenSafeTracker = TOCTOUAnalyzer
TOCTOUTracer = TOCTOUAnalyzer
OpenSafeAnalyzer = TOCTOUAnalyzer


def trace_toctou(source):
    return analyze(source)


def analyze_toctou(source):
    return analyze(source)


SimulationResult = namedtuple('SimulationResult', ('status', 'observed', 'path'))


def external_read_descriptor(descriptor, size=4096):
    return os.read(descriptor, size)


def _simulation_directory(directory):
    if directory is not None:
        if not os.path.isdir(directory):
            os.makedirs(directory)
        return directory, False
    path = tempfile.mkdtemp(prefix='dlint-toctou-')
    return path, True


def _write_bytes(path, data):
    with open(path, 'wb') as handle:
        handle.write(data)


def simulate_safe_flow(directory=None):
    root, cleanup = _simulation_directory(directory)
    path = os.path.join(root, 'safe.txt')
    payload = b'checked-content'
    try:
        _write_bytes(path, payload)
        if not os.path.exists(path):
            raise AssertionError('path check did not see fixture file')
        descriptor = open_safe(path)
        alias = descriptor
        try:
            observed = os.read(alias, 4096)
        finally:
            os.close(descriptor)
        return SimulationResult(SAFE, observed, path)
    finally:
        if cleanup:
            shutil.rmtree(root, ignore_errors=True)


def simulate_race_flow(directory=None):
    root, cleanup = _simulation_directory(directory)
    path = os.path.join(root, 'flow.txt')
    replacement = os.path.join(root, 'attacker.txt')
    payload = b'checked-content'
    attacker_payload = b'attacker-content'
    try:
        _write_bytes(path, payload)
        _write_bytes(replacement, attacker_payload)
        if not os.path.exists(path):
            raise AssertionError('path check did not see fixture file')
        os.rename(path, path + '.checked')
        os.rename(replacement, path)
        with open(path, 'rb') as handle:
            observed = handle.read()
        return SimulationResult(RACE, observed, path)
    finally:
        if cleanup:
            shutil.rmtree(root, ignore_errors=True)


def simulate_unknown_flow(directory=None):
    root, cleanup = _simulation_directory(directory)
    path = os.path.join(root, 'unknown.txt')
    payload = b'checked-content'
    try:
        _write_bytes(path, payload)
        if not os.path.exists(path):
            raise AssertionError('path check did not see fixture file')
        descriptor = open_safe(path)
        alias = descriptor
        try:
            observed = external_read_descriptor(alias)
        finally:
            os.close(descriptor)
        return SimulationResult(UNKNOWN, observed, path)
    finally:
        if cleanup:
            shutil.rmtree(root, ignore_errors=True)


simulate_undecidable_flow = simulate_unknown_flow


class SimulationSuite(dict):
    __getattr__ = dict.get


def simulate_flows(base_directory=None):
    if base_directory is None:
        root = tempfile.mkdtemp(prefix='dlint-toctou-suite-')
        cleanup = True
    else:
        root = base_directory
        if not os.path.isdir(root):
            os.makedirs(root)
        cleanup = False
    try:
        safe_directory = os.path.join(root, 'safe')
        race_directory = os.path.join(root, 'race')
        unknown_directory = os.path.join(root, 'unknown')
        result = SimulationSuite(
            safe=simulate_safe_flow(safe_directory),
            race=simulate_race_flow(race_directory),
            unknown=simulate_unknown_flow(unknown_directory),
        )
        return result
    finally:
        if cleanup:
            shutil.rmtree(root, ignore_errors=True)


__all__ = [
    'SAFE', 'RACE', 'UNKNOWN', 'PROVEN', 'RACY', 'UNDECIDABLE',
    'Location', 'Diagnostic', 'AnalysisReport', 'TOCTOUAnalyzer',
    'analyze', 'analyze_source', 'find_toctou', 'trace_open_safe',
]

safe_flow = simulate_safe_flow
race_flow = simulate_race_flow
unknown_flow = simulate_unknown_flow
undecidable_flow = simulate_unknown_flow
simulate = simulate_flows
simulate_toctou = simulate_flows
