#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import sys


def decorator_name(decorator):
    if isinstance(decorator, ast.Attribute):
        # E.g. @module.decorator
        return decorator.attr
    elif isinstance(decorator, ast.Name):
        # E.g. @decorator
        return decorator.id
    elif isinstance(decorator, ast.Call):
        if isinstance(decorator.func, ast.Attribute):
            # E.g. @module.decorator(argument)
            return decorator.func.attr
        elif isinstance(decorator.func, ast.Name):
            # E.g. @decorator(argument)
            return decorator.func.id
    else:
        raise TypeError('expected type ast.Attribute, ast.Name, or ast.Call, received {}'.format(type(decorator)))


def function_has_inlinecallbacks_decorator(function):
    return any(
        decorator_name(decorator) == 'inlineCallbacks'
        for decorator in function.decorator_list
    )


def function_is_empty(function):
    def raise_or_pass_or_docstring(node):
        return (
            isinstance(node, ast.Raise)
            or isinstance(node, ast.Pass)
            or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Str))
        )

    return all(
        raise_or_pass_or_docstring(child)
        for child in function.body
    )


def call_is_returnvalue(call):
    if isinstance(call, ast.Attribute):
        if isinstance(call.value, ast.Name):
            # E.g. defer.returnValue(argument)
            return (
                call.value.id == 'defer'
                and call.attr == 'returnValue'
            )
        else:
            # E.g. foo(argument).bar()
            return False
    elif isinstance(call, ast.Name):
        # E.g. returnValue(argument)
        return call.id == 'returnValue'
    else:
        # E.g. foo(argument).bar()()
        return False


def non_empty_return(_return):
    return _return.value is not None


def walk_callback_same_scope(node, callback):
    is_python_3_5 = sys.version_info >= (3, 5)

    # If we change scope, e.g. enter into a new
    # class or function definition, then halt iteration
    scopes = (ast.ClassDef, ast.FunctionDef)
    if is_python_3_5:
        scopes += (ast.AsyncFunctionDef,)

    def scope_predicate(inner_node):
        return not isinstance(inner_node, scopes)

    walk_callback(node, callback, predicate=scope_predicate)


def walk_callback(node, callback, predicate=lambda n: True):
    for child_node in ast.iter_child_nodes(node):
        if not predicate(child_node):
            continue

        callback(child_node)
        walk_callback(child_node, callback, predicate=predicate)


def kwarg_present(call, kwarg_name):
    return kwarg_name in (keyword.arg for keyword in call.keywords)


def kwarg_not_present(call, kwarg_name):
    return not kwarg_present(call, kwarg_name)


def kwarg_primitive(call, kwarg_name, primitive):
    try:
        # Python 3
        primitive_type = ast.NameConstant

        def comparator(keyword, inner_primitive):
            return (
                isinstance(keyword.value, primitive_type)
                and keyword.value.value == inner_primitive
            )
    except AttributeError:
        # Python 2, AttributeError on ast.NameConstant
        primitive_type = ast.Name

        def comparator(keyword, inner_primitive):
            return (
                isinstance(keyword.value, primitive_type)
                and keyword.value.id == str(inner_primitive)
            )

    return any(
        keyword.arg == kwarg_name
        and comparator(keyword, primitive)
        for keyword in call.keywords
    )


def kwarg_false(call, kwarg_name):
    return kwarg_primitive(call, kwarg_name, False)


def kwarg_true(call, kwarg_name):
    return kwarg_primitive(call, kwarg_name, True)


def kwarg_none(call, kwarg_name):
    return kwarg_primitive(call, kwarg_name, None)


def kwarg_str(call, kwarg_name, s):
    return any(
        keyword.arg == kwarg_name
        and isinstance(keyword.value, ast.Str)
        and keyword.value.s == s
        for keyword in call.keywords
    )


def kwarg_module_path(call, kwarg_name, illegal_module_path, namespace):
    return any(
        keyword.arg == kwarg_name
        and isinstance(keyword.value, (ast.Attribute, ast.Name))
        and namespace.illegal_module_imported(
            module_path_str(keyword.value),
            illegal_module_path
        )
        for keyword in call.keywords
    )


def kwarg_module_path_call(call, kwarg_name, illegal_module_path, namespace):
    return any(
        keyword.arg == kwarg_name
        and isinstance(keyword.value, ast.Call)
        and isinstance(keyword.value.func, (ast.Attribute, ast.Name))
        and namespace.illegal_module_imported(
            module_path_str(keyword.value.func),
            illegal_module_path
        )
        for keyword in call.keywords
    )


def kwarg_any(kwarg_functions):
    """Resolve kwarg predicates with short-circuit evaluation. This optimization
    technique means we do not have to evaluate every predicate if one is already
    true.
    """
    return any(kwarg_function() for kwarg_function in kwarg_functions)


def module_path(node):
    """Recursively walk up a series of node attributes.
    E.g. if we have foo.bar.baz, iterate baz -> bar -> foo.
    """
    if isinstance(node, ast.Attribute):
        return module_path(node.value) + [node.attr]
    elif isinstance(node, ast.Name):
        return [node.id]
    else:
        return []


def module_path_str(node):
    """Return module path as a string instead of a list.
    E.g. "foo.bar.baz" instead of ["foo", "bar", "baz"].
    """
    return ".".join(module_path(node))


def argument_name(arg):
    """Return the bound name for an ast.arg node (Python 3) or a raw
    identifier string (Python 2)."""
    if isinstance(arg, ast.arg):
        return arg.arg

    return arg


def collect_nodes(node, node_types):
    """Walk an entire tree, including nested scopes, and return every node
    that is an instance of one of the provided node types.
    """
    results = []

    def collect_callback(inner_node):
        if isinstance(inner_node, node_types):
            results.append(inner_node)

    walk_callback(node, collect_callback)

    return results


def node_parent_map(root):
    """Map every node in the tree to its direct parent node."""
    parents = {}

    def parent_callback(inner_node):
        for child_node in ast.iter_child_nodes(inner_node):
            parents[child_node] = inner_node

    parent_callback(root)
    walk_callback(root, parent_callback)

    return parents


def node_is_within_types(node, node_types, parents):
    """Return True if any ancestor of the node is an instance of one of the
    provided node types.
    """
    current = node

    while current in parents:
        current = parents[current]
        if isinstance(current, node_types):
            return True

    return False


def literal_node_value(node):
    """Return the literal value of a constant AST node, or None when the node
    is not a statically known literal.
    """
    if hasattr(ast, 'Constant') and isinstance(node, ast.Constant):
        # A NameConstant is folded into Constant on Python 3.8+
        return node.value

    if isinstance(node, ast.Str):
        return node.s
    elif isinstance(node, ast.Num):
        return node.n
    elif hasattr(ast, 'NameConstant') and isinstance(node, ast.NameConstant):
        return node.value

    return None


def node_is_literal(node):
    """Return True when the node is a statically known constant literal."""
    literal_types = (ast.Str, ast.Num)
    if hasattr(ast, 'NameConstant'):
        literal_types += (ast.NameConstant,)
    if hasattr(ast, 'Constant'):
        literal_types += (ast.Constant,)

    return isinstance(node, literal_types)


def call_name(call):
    """Return the function name of a call node for both attribute and bare
    name calls. E.g. "queue.submit" becomes "submit" and "mask" becomes "mask".
    """
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    elif isinstance(call.func, ast.Name):
        return call.func.id

    return None


def same_modules(s1, s2):
    """Compare two module strings where submodules of an illegal
    parent module should also be illegal. I.e. blacklisting 'foo.bar'
    should also make 'foo.bar.baz' illegal.

    The first argument should 'encompass' the second, not the other way
    around. I.e. passing same_modules('foo', 'foo.bar') will return True,
    but same_modules('foo.bar', 'foo') will not.
    """
    modules1 = s1.split(".")
    modules2 = s2.split(".")

    return (
        len(modules1) <= len(modules2)
        and all(m1 == m2 for (m1, m2) in zip(modules1, modules2))
    )


def is_constant_literal(node):
    """Return True when the node is a statically known constant literal."""
    return node_is_literal(node)


def literal_value(node):
    """Return the literal value of a constant AST node, or None when the
    node is not a statically known literal.
    """
    return literal_node_value(node)


def assignment_names(node):
    """Return every identifier bound by an assignment-like node."""
    names = []

    def add_target(target):
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                add_target(element)
        elif isinstance(target, ast.Starred):
            add_target(target.value)

    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            add_target(target)
    elif isinstance(node, ast.For):
        add_target(node.target)
    elif isinstance(node, ast.comprehension):
        add_target(node.target)
    elif isinstance(node, ast.withitem):
        if node.optional_vars is not None:
            add_target(node.optional_vars)

    return names


def function_name(node):
    """Return a readable name for a function or lambda node."""
    if isinstance(node, ast.Lambda):
        return '<lambda>'
    return getattr(node, 'name', '<function>')


def binding_is_loop_binding(assignment_node, root):
    """Return True when the binding happens through a loop target, either
    because the assignment node itself is a loop/comprehension or because one
    of its ancestors (up to ``root``) is a loop.
    """
    loop_types = (ast.For, ast.While, ast.comprehension)
    if hasattr(ast, 'AsyncFor'):
        loop_types += (ast.AsyncFor,)

    if isinstance(assignment_node, loop_types):
        return True

    parents = node_parent_map(root)
    return node_is_within_types(assignment_node, loop_types, parents)
