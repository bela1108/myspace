"""
Transactional, scope aware callback chains for html-sanitizer.

Cleaning callbacks (a.k.a. element pre/postprocessors) may optionally declare
the node scope they are responsible for and the mutation capabilities they
need.  Declared callbacks run against an isolated :class:`Snapshot`; the whole
chain is published to the caller's tree in a single :meth:`CallbackTransaction.commit`.

Every callback invocation is bracketed by a structural diff.  The resulting
:class:`ImpactReport` states exactly which callback touched which node and
which declared check failed (node scope or mutation capability).  Plain
callables without a declaration keep working unchanged and are treated as
fully trusted/legacy callbacks.
"""

from __future__ import annotations

import copy
import hashlib
import inspect
import re

import lxml.html


__all__ = [
    "ALL_CAPABILITIES",
    "CAPABILITY_ATTRIBUTES",
    "CAPABILITY_INSERT",
    "CAPABILITY_MOVE",
    "CAPABILITY_READ",
    "CAPABILITY_REMOVE",
    "CAPABILITY_REPLACE_ANCESTOR",
    "CAPABILITY_TAG",
    "CAPABILITY_TEXT",
    "CallbackContext",
    "CallbackDeclaration",
    "CallbackExecutionError",
    "CallbackTransaction",
    "CallbackTransactionError",
    "CallbackChain",
    "CapabilityViolation",
    "ImpactReport",
    "NodeChange",
    "NodeScope",
    "ScopedCallback",
    "Snapshot",
    "ScopeViolation",
    "TransactionViolation",
    "Violation",
    "coerce_callback",
    "coerce_capabilities",
    "coerce_scope",
    "get_declaration",
    "guarded_callback_call",
    "run_callback_chain",
    "scoped",
    "verify_impact",
]


CAPABILITY_READ = "read"
CAPABILITY_TEXT = "text"
CAPABILITY_ATTRIBUTES = "attributes"
CAPABILITY_TAG = "tag"
CAPABILITY_MOVE = "move"
CAPABILITY_INSERT = "insert"
CAPABILITY_REMOVE = "remove"
CAPABILITY_REPLACE_ANCESTOR = "replace_ancestor"

ALL_CAPABILITIES = frozenset(
    {
        CAPABILITY_READ,
        CAPABILITY_TEXT,
        CAPABILITY_ATTRIBUTES,
        CAPABILITY_TAG,
        CAPABILITY_MOVE,
        CAPABILITY_INSERT,
        CAPABILITY_REMOVE,
        CAPABILITY_REPLACE_ANCESTOR,
    }
)

_WILDCARD = "*"
_MISSING = object()

_CAPABILITY_ALIASES = {
    "attr": CAPABILITY_ATTRIBUTES,
    "attrs": CAPABILITY_ATTRIBUTES,
    "attribute": CAPABILITY_ATTRIBUTES,
    "attrib": CAPABILITY_ATTRIBUTES,
    "delete": CAPABILITY_REMOVE,
    "deletion": CAPABILITY_REMOVE,
    "drop": CAPABILITY_REMOVE,
    "removal": CAPABILITY_REMOVE,
    "create": CAPABILITY_INSERT,
    "creation": CAPABILITY_INSERT,
    "add": CAPABILITY_INSERT,
    "new": CAPABILITY_INSERT,
    "append": CAPABILITY_INSERT,
    "relocate": CAPABILITY_MOVE,
    "reparent": CAPABILITY_MOVE,
    "reorder": CAPABILITY_MOVE,
    "moving": CAPABILITY_MOVE,
    "rename": CAPABILITY_TAG,
    "tag_name": CAPABILITY_TAG,
    "ancestor": CAPABILITY_REPLACE_ANCESTOR,
    "replace-ancestor": CAPABILITY_REPLACE_ANCESTOR,
    "ancestor_replacement": CAPABILITY_REPLACE_ANCESTOR,
    "text_change": CAPABILITY_TEXT,
    "edit": {CAPABILITY_TEXT, CAPABILITY_ATTRIBUTES, CAPABILITY_TAG},
    "write": {CAPABILITY_TEXT, CAPABILITY_ATTRIBUTES},
    "structure": {
        CAPABILITY_MOVE,
        CAPABILITY_INSERT,
        CAPABILITY_REMOVE,
        CAPABILITY_REPLACE_ANCESTOR,
        CAPABILITY_TAG,
    },
    "structural": {
        CAPABILITY_MOVE,
        CAPABILITY_INSERT,
        CAPABILITY_REMOVE,
        CAPABILITY_REPLACE_ANCESTOR,
    },
    "all": _WILDCARD,
    _WILDCARD: _WILDCARD,
}


def is_element(node):
    """Return whether *node* is a real lxml element (not a comment etc.)."""
    return node is not None and isinstance(getattr(node, "tag", None), str)


def coerce_capabilities(value):
    """Normalize a capability declaration.

    ``None`` means "no capability restriction" (everything allowed inside
    the declared scope).  Strings may be comma/whitespace separated.
    """
    if value is None:
        return None
    if value == _WILDCARD:
        return frozenset(ALL_CAPABILITIES)
    if isinstance(value, str):
        raw = [part for part in value.replace(",", " ").split() if part]
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw = list(value)
    else:
        raw = [value]

    capabilities = set()
    for item in raw:
        token = getattr(item, "value", item)
        if not isinstance(token, str):
            raise TypeError(f"Capability names must be strings, got {item!r}")
        key = token.strip().lower().replace("-", "_")
        resolved = _CAPABILITY_ALIASES.get(key, token.strip().lower())
        if resolved == _WILDCARD:
            return frozenset(ALL_CAPABILITIES)
        if isinstance(resolved, set):
            capabilities.update(resolved)
        else:
            capabilities.add(resolved)
    return frozenset(capabilities)


def root_relative_path(node):
    """Index path of *node* from the outermost lxml root of its tree."""
    path = []
    current = node
    parent = current.getparent()
    while parent is not None:
        path.append(list(parent).index(current))
        current = parent
        parent = current.getparent()
    return tuple(reversed(path))


def path_relative_to(node, root):
    """Index path of *node* below *root* (empty tuple when node is root)."""
    path = []
    current = node
    while current is not None and current is not root:
        parent = current.getparent()
        if parent is None:
            break
        path.append(list(parent).index(current))
        current = parent
    return tuple(reversed(path))


def resolve_path(root, path):
    node = root
    for index in path:
        node = node[index]
    return node


def _parse_compound_selector(compound):
    tag = None
    element_id = None
    classes = []
    attributes = []
    token = compound
    if token and token[0].isalpha():
        index = 0
        while index < len(token) and (token[index].isalnum() or token[index] in "-_"):
            index += 1
        tag = token[:index].lower()
        token = token[index:]

    pattern = re.compile(r"([.#\[])([^.#\[\]]+)\]?")
    for match in pattern.finditer(token):
        kind, body = match.group(1), match.group(2)
        if kind == "#":
            element_id = body
        elif kind == ".":
            classes.append(body)
        else:
            if "=" in body:
                name, _, value = body.partition("=")
                value = value.strip().strip("\"'")
                attributes.append((name.strip(), value))
            else:
                attributes.append((body.strip(), None))
    return tag, element_id, classes, attributes


def _compound_matches(parsed, node):
    if not is_element(node):
        return False
    tag, element_id, classes, attributes = parsed
    if tag is not None and node.tag.lower() != tag:
        return False
    if element_id is not None and node.get("id") != element_id:
        return False
    class_tokens = (node.get("class") or "").split()
    if any(class_name not in class_tokens for class_name in classes):
        return False
    for name, value in attributes:
        if name not in node.attrib:
            return False
        if value is not None and node.get(name) != value:
            return False
    return True


def selector_matches(selector, node):
    """Tiny dependency free CSS matcher (tag/#id/.class/[attr] + descendant)."""
    parts = [part for part in selector.split() if part]
    if not parts:
        return False
    compounds = [_parse_compound_selector(part) for part in parts]
    if not _compound_matches(compounds[-1], node):
        return False
    current = node
    for compound in reversed(compounds[:-1]):
        while True:
            current = current.getparent()
            if current is None:
                return False
            if _compound_matches(compound, current):
                break
    return True


class NodeScope:
    """Declared set of nodes a callback is responsible for.

    Supported forms (also freely combinable through keywords):

    * ``None`` / omitted: every node (unrestricted scope).
    * a tag name (``"p"``) or a collection of tag names.
    * a callable predicate ``lambda element: ...``.
    * an lxml element (or collection of elements), meaning those subtrees.
    * a simple CSS selector string (``".body [data-part='body']"``).
    * a mapping of attribute name/value pairs.
    """

    def __init__(
        self,
        spec=None,
        *,
        tags=None,
        predicate=None,
        predicates=None,
        nodes=None,
        selector=None,
        selectors=None,
        attributes=None,
        any_of=None,
    ):
        self.is_all = spec is None and not any(
            value is not None
            for value in (
                tags,
                predicate,
                predicates,
                nodes,
                selector,
                selectors,
                attributes,
                any_of,
            )
        )
        self.tags = None
        self.predicates = []
        self.selectors = []
        self.ref_paths = []
        self.attribute_matchers = []
        self.alternatives = None

        if self.is_all:
            return

        if isinstance(spec, NodeScope):
            self.__dict__.update(copy.deepcopy(spec.__dict__))
            return

        if any_of is not None:
            self.alternatives = [coerce_scope(item) for item in any_of]

        if tags is not None:
            self.tags = {tags} if isinstance(tags, str) else set(tags)
        if predicate is not None:
            self.predicates.append(predicate)
        if predicates is not None:
            self.predicates.extend(predicates)
        if selector is not None:
            self.selectors.append(selector)
        if selectors is not None:
            self.selectors.extend(selectors)
        if attributes is not None:
            self.attribute_matchers.append(dict(attributes))
        if nodes is not None:
            self._consume_nodes(nodes)
        if spec is not None:
            self._consume_spec(spec)

    def _consume_nodes(self, nodes):
        if is_element(nodes):
            nodes = [nodes]
        for node in nodes:
            if is_element(node):
                self.ref_paths.append(root_relative_path(node))

    def _consume_spec(self, spec):
        if callable(spec) and not isinstance(spec, type):
            self.predicates.append(spec)
        elif is_element(spec):
            self._consume_nodes(spec)
        elif isinstance(spec, str):
            if _looks_like_selector(spec):
                self.selectors.append(spec)
            else:
                self.tags = {spec} if self.tags is None else self.tags | {spec}
        elif isinstance(spec, dict):
            if any(key in spec for key in _SCOPE_STRUCTURAL_KEYS):
                self._consume_kwargs_spec(dict(spec))
            else:
                self.attribute_matchers.append(dict(spec))
        elif isinstance(spec, (list, tuple, set, frozenset)):
            items = list(spec)
            if items and all(isinstance(item, str) for item in items):
                self.tags = set(items) if self.tags is None else self.tags | set(items)
            elif all(is_element(item) for item in items):
                self._consume_nodes(items)
            else:
                self.alternatives = [coerce_scope(item) for item in items]
        else:
            raise TypeError(f"Unsupported node scope declaration: {spec!r}")

    def _consume_kwargs_spec(self, spec):  # noqa: C901
        consumed = set()
        for key in ("scope", "node_scope"):
            if key in spec:
                consumed.add(key)
        value = spec.get("scope", _MISSING)
        if value is _MISSING:
            value = spec.get("node_scope", _MISSING)
        if value is not _MISSING and value is not None:
            other = coerce_scope(value)
            self._merge_other(other)
        for key in ("tags", "tag"):
            if spec.get(key) is not None:
                consumed.add(key)
                tags = spec[key]
                self.tags = {tags} if isinstance(tags, str) else set(tags)
        for key in ("predicate", "predicates", "where"):
            value = spec.get(key)
            if value is None:
                continue
            consumed.add(key)
            if key == "predicates":
                self.predicates.extend(value)
            else:
                self.predicates.append(value)
        for key in ("selector", "css", "select"):
            if spec.get(key):
                consumed.add(key)
                self.selectors.append(spec[key])
        for key in ("nodes", "node", "elements", "within"):
            if spec.get(key) is not None:
                consumed.add(key)
                self._consume_nodes(spec[key])
        for key in ("attributes", "attrs"):
            if spec.get(key):
                consumed.add(key)
                self.attribute_matchers.append(dict(spec[key]))
        for key, value in spec.items():
            if key in consumed or key in _SCOPE_META_KEYS:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                self.attribute_matchers.append({key: value})

    def _merge_other(self, other):
        if other.is_all:
            return
        if other.tags is not None:
            self.tags = other.tags if self.tags is None else self.tags & other.tags
        self.predicates.extend(other.predicates)
        self.selectors.extend(other.selectors)
        self.ref_paths.extend(other.ref_paths)
        self.attribute_matchers.extend(other.attribute_matchers)

    @classmethod
    def all(cls):
        """Return the unrestricted scope (every node)."""
        return cls()

    def contains(self, node):
        """Return whether *node* belongs to this scope in its current state."""
        if self.is_all:
            return True
        if self.alternatives is not None and any(
            alternative.contains(node) for alternative in self.alternatives
        ):
            return True
        if not is_element(node):
            return False
        if self.tags is not None and node.tag not in self.tags:
            return False
        if self.predicates and not all(
            predicate(node) for predicate in self.predicates
        ):
            return False
        if self.selectors and not any(
            selector_matches(selector, node) for selector in self.selectors
        ):
            return False
        if self.attribute_matchers and not all(
            all(node.get(key) == value for key, value in matcher.items())
            for matcher in self.attribute_matchers
        ):
            return False
        if self.ref_paths:
            path = root_relative_path(node)
            if not any(
                path == ref or path[: len(ref)] == ref for ref in self.ref_paths
            ):
                return False
        return True

    def contains_path(self, path):
        """Path based membership used for before-state snapshots."""
        if self.is_all:
            return True
        if self.ref_paths:
            return any(path == ref or path[: len(ref)] == ref for ref in self.ref_paths)
        return False

    def describe(self):
        if self.is_all:
            return "all nodes"
        parts = []
        if self.tags is not None:
            parts.append(f"tags={sorted(self.tags)!r}")
        if self.selectors:
            parts.append(f"selectors={self.selectors!r}")
        if self.predicates:
            parts.append(f"{len(self.predicates)} predicate(s)")
        if self.ref_paths:
            parts.append(f"{len(self.ref_paths)} referenced subtree(s)")
        if self.attribute_matchers:
            parts.append(f"attributes={self.attribute_matchers!r}")
        if self.alternatives:
            parts.append("any-of")
        return "NodeScope(" + ", ".join(parts) + ")"

    def __repr__(self):
        return f"<{self.describe()}>"


_SCOPE_STRUCTURAL_KEYS = {
    "scope",
    "node_scope",
    "allowed_nodes",
    "range",
    "tags",
    "tag",
    "predicate",
    "predicates",
    "where",
    "selector",
    "css",
    "select",
    "nodes",
    "node",
    "elements",
    "within",
    "attributes",
    "attrs",
}

_SCOPE_META_KEYS = {
    "capabilities",
    "permissions",
    "may",
    "rights",
    "allowed_capabilities",
    "required_capabilities",
    "name",
    "callback",
    "fn",
    "func",
    "handler",
    "processor",
    "extension",
}

_SCOPE_SPEC_KEYS = _SCOPE_STRUCTURAL_KEYS | _SCOPE_META_KEYS


def _looks_like_selector(value):
    return any(char in value for char in ".#[]:>~+ ") or "=" in value


def coerce_scope(value, **kwargs):
    if value is None and not kwargs:
        return NodeScope()
    if isinstance(value, NodeScope) and not kwargs:
        return value
    if isinstance(value, dict) and not kwargs:
        return NodeScope(value)
    return NodeScope(value, **kwargs)


class CallbackDeclaration:
    """Optional scope and capability declaration for one callback."""

    def __init__(
        self,
        *,
        scope=None,
        node_scope=None,
        allowed_nodes=None,
        within=None,
        capabilities=None,
        permissions=None,
        may=None,
        rights=None,
        name=None,
        **extra,
    ):
        scope_value = _first_set(
            scope,
            node_scope,
            allowed_nodes,
            within,
            extra.get("allowed_scope"),
            extra.get("node_range"),
            extra.get("range"),
        )
        caps_value = _first_set(
            capabilities,
            permissions,
            may,
            rights,
            extra.get("allowed_capabilities"),
            extra.get("required_capabilities"),
            extra.get("mutation_capabilities"),
            extra.get("allowed_actions"),
            extra.get("actions"),
            extra.get("grants"),
        )
        self.scope = coerce_scope(scope_value)
        self.capabilities = coerce_capabilities(caps_value)
        self.name = name
        self.extra = extra

    @property
    def unrestricted_capabilities(self):
        return self.capabilities is None

    def allows_capability(self, capability):
        return self.capabilities is None or capability in self.capabilities

    def describe(self):
        caps = "all" if self.capabilities is None else sorted(self.capabilities)
        return f"declaration(scope={self.scope.describe()}, capabilities={caps})"


def _first_set(*values):
    for value in values:
        if value is not None:
            return value
    return None


_SCOPE_ATTR_NAMES = (
    "__html_sanitizer_scope__",
    "__node_scope__",
    "node_scope",
    "scope",
    "allowed_nodes",
)
_CAP_ATTR_NAMES = (
    "__html_sanitizer_capabilities__",
    "__capabilities__",
    "capabilities",
    "permissions",
    "allowed_capabilities",
    "required_capabilities",
    "may",
)
_DECL_ATTR_NAMES = (
    "__callback_declaration__",
    "__declaration__",
    "callback_declaration",
    "declaration",
)


def get_declaration(callback):
    """Return a :class:`CallbackDeclaration` attached to *callback*, else ``None``.

    Plain legacy callables without any declaration marker return ``None`` so
    callers can keep treating them as fully trusted callbacks.
    """
    if isinstance(callback, ScopedCallback):
        return callback.declaration
    for attr_name in _DECL_ATTR_NAMES:
        declaration = getattr(callback, attr_name, None)
        if isinstance(declaration, CallbackDeclaration):
            return declaration
    scope_value = _missing_attr(callback, _SCOPE_ATTR_NAMES)
    caps_value = _missing_attr(callback, _CAP_ATTR_NAMES)
    marked = getattr(callback, "__scoped_callback__", False) or getattr(
        callback, "__transactional_callback__", False
    )
    if scope_value is _MISSING and caps_value is _MISSING and not marked:
        return None
    return CallbackDeclaration(
        scope=None if scope_value is _MISSING else scope_value,
        capabilities=None if caps_value is _MISSING else caps_value,
        name=getattr(callback, "__name__", None),
    )


def _missing_attr(callback, names):
    for name in names:
        value = getattr(callback, name, _MISSING)
        if value is not _MISSING:
            return value
    return _MISSING


class ScopedCallback:
    """Wrapper attaching a :class:`CallbackDeclaration` to a callable."""

    __scoped_callback__ = True

    def __init__(
        self,
        callback=None,
        *,
        scope=None,
        node_scope=None,
        capabilities=None,
        permissions=None,
        name=None,
        declaration=None,
        **kwargs,
    ):
        if callback is None:
            raise TypeError(
                "ScopedCallback requires a callable; use scoped(...) as a decorator"
            )
        if not callable(callback):
            raise TypeError(f"Callback must be callable, got {callback!r}")
        self.callback = callback
        if declaration is not None:
            self.declaration = declaration
        else:
            self.declaration = CallbackDeclaration(
                scope=scope,
                node_scope=node_scope,
                capabilities=capabilities,
                permissions=permissions,
                name=name or getattr(callback, "__name__", None),
                **kwargs,
            )
        self.__name__ = self.declaration.name or getattr(
            callback, "__name__", "callback"
        )
        self.__wrapped__ = callback

    def invoke(self, element, context=None):
        return invoke_callback(self.callback, element, context)

    def __call__(self, element=None, context=None, *args, **kwargs):
        if args or kwargs:
            return self.callback(element, *args, **kwargs)
        return self.invoke(element, context)

    def __repr__(self):
        return f"<ScopedCallback {self.__name__!r} {self.declaration.describe()}>"


def scoped(callback=None, **declaration_kwargs):
    """Decorator/wrapper declaring scope and capabilities for a callback."""

    def wrap(fn):
        if isinstance(fn, ScopedCallback):
            return ScopedCallback(
                fn.callback,
                declaration=CallbackDeclaration(
                    **{
                        **fn.declaration.__dict__,
                        **{
                            key: value
                            for key, value in declaration_kwargs.items()
                            if value is not None
                        },
                    }
                ),
            )
        return ScopedCallback(fn, **declaration_kwargs)

    if callback is None:
        return wrap
    return wrap(callback)


scoped_callback = scoped
transactional_callback = scoped
declare_callback = scoped


_DICT_CALLBACK_KEYS = (
    "callback",
    "fn",
    "func",
    "handler",
    "processor",
    "extension",
    "callable",
)


def coerce_callback(spec):
    """Normalize plain callables, wrappers, dict specs and tuple specs."""
    if isinstance(spec, ScopedCallback):
        return spec
    if callable(spec):
        return spec
    if isinstance(spec, dict):
        callback = _first_set(*(spec.get(key) for key in _DICT_CALLBACK_KEYS))
        if callback is None:
            raise TypeError(
                f"Callback declaration dict is missing a callable: {spec!r}"
            )
        declaration = CallbackDeclaration(
            name=spec.get("name"),
            scope=_first_set(spec.get("scope"), spec.get("node_scope")),
            capabilities=_first_set(
                spec.get("capabilities"), spec.get("permissions"), spec.get("may")
            ),
        )
        return ScopedCallback(callback, declaration=declaration)
    if isinstance(spec, (tuple, list)):
        if len(spec) == 2:
            callback, scope = spec
            return ScopedCallback(callback, scope=scope)
        if len(spec) >= 3:
            callback, scope, capabilities = spec[:3]
            return ScopedCallback(callback, scope=scope, capabilities=capabilities)
    raise TypeError(f"Unsupported callback specification: {spec!r}")


def callback_wants_context(callback):
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        return False
    parameters = list(signature.parameters.values())
    if any(
        parameter.kind == inspect.Parameter.VAR_POSITIONAL for parameter in parameters
    ):
        return True
    if any(parameter.name == "context" for parameter in parameters):
        return True
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    return len(positional) >= 2


def invoke_callback(callback, element, context=None):
    """Invoke a legacy one-arg callback or a context aware ``(element, ctx)`` one."""
    if isinstance(callback, ScopedCallback):
        return callback.invoke(element, context)
    if callback_wants_context(callback):
        return callback(element, context)
    return callback(element)


class Snapshot:
    """An isolated deep copied view of a tree at one point in time."""

    def __init__(self, root, *, label=None):
        self.root = copy.deepcopy(root)
        self.label = label

    @classmethod
    def capture(cls, root, label=None):
        return cls(root, label=label)

    def to_html(self):
        return lxml.html.tostring(self.root, encoding="unicode")

    @property
    def html(self):
        return self.to_html()

    def digest(self):
        return hashlib.sha256(self.to_html().encode("utf-8")).hexdigest()

    def __str__(self):
        return self.to_html()

    def __repr__(self):
        label = f" {self.label!r}" if self.label else ""
        return f"<Snapshot{label} {self.to_html()[:60]!r}>"


class NodeRecord:
    __slots__ = (
        "node",
        "tag",
        "text",
        "tail",
        "attrib",
        "parent",
        "index",
        "path",
        "ancestors",
    )

    def __init__(self, node, root):
        self.node = node
        self.tag = node.tag
        self.text = node.text
        self.tail = node.tail
        self.attrib = dict(node.attrib)
        self.parent = node.getparent()
        self.index = list(self.parent).index(node) if self.parent is not None else 0
        self.path = path_relative_to(node, root)
        ancestors = []
        current = self.parent
        while current is not None and current is not root:
            ancestors.append(current)
            current = current.getparent()
        if current is root:
            ancestors.append(root)
        self.ancestors = tuple(ancestors)


def build_records(root):
    records = {}
    for node in root.iter():
        if is_element(node):
            records[node] = NodeRecord(node, root)
    return records


class NodeChange:
    """One detected mutation between two tree states."""

    def __init__(
        self,
        kind,
        *,
        node=None,
        required_capability=None,
        message="",
        details=None,
        **refs,
    ):
        self.kind = kind
        self.node = node
        self.required_capability = required_capability or kind
        self.message = message or kind
        self.details = details or {}
        self.refs = refs
        self.absorbed_by = None

    def __repr__(self):
        return f"<NodeChange {self.kind} node={self.node!r}>"


CHANGE_TEXT = "text"
CHANGE_TAIL = "tail"
CHANGE_ATTRIBUTES = "attributes"
CHANGE_TAG = "tag"
CHANGE_INSERT = "insert"
CHANGE_REMOVE = "remove"
CHANGE_MOVE = "move"
CHANGE_REORDER = "reorder"
CHANGE_REPLACE_ANCESTOR = "replace_ancestor"


def diff_tree(root, records):
    """Compare the current *root* against pre-callback *records*."""
    changes = []
    current_elements = [node for node in root.iter() if is_element(node)]
    current_set = set(current_elements)

    for node in current_elements:
        record = records.get(node)
        if record is None:
            changes.append(
                NodeChange(
                    CHANGE_INSERT,
                    node=node,
                    required_capability=CAPABILITY_INSERT,
                    message="node was inserted",
                )
            )
            continue

        if node.tag != record.tag:
            changes.append(
                NodeChange(
                    CHANGE_TAG,
                    node=node,
                    required_capability=CAPABILITY_TAG,
                    message=f"tag changed {record.tag!r} -> {node.tag!r}",
                    details={"before": record.tag, "after": node.tag},
                    before_path=record.path,
                )
            )

        if (node.text or "") != (record.text or ""):
            changes.append(
                NodeChange(
                    CHANGE_TEXT,
                    node=node,
                    required_capability=CAPABILITY_TEXT,
                    message="text content changed",
                    details={"before": record.text, "after": node.text},
                    before_path=record.path,
                )
            )

        if (node.tail or "") != (record.tail or ""):
            changes.append(
                NodeChange(
                    CHANGE_TAIL,
                    node=node,
                    required_capability=CAPABILITY_TEXT,
                    message="tail text changed",
                    details={"before": record.tail, "after": node.tail},
                    before_path=record.path,
                )
            )

        if dict(node.attrib) != record.attrib:
            before_keys = set(record.attrib)
            after_keys = set(node.attrib)
            changed = {
                key
                for key in before_keys & after_keys
                if record.attrib.get(key) != node.get(key)
            }
            changes.append(
                NodeChange(
                    CHANGE_ATTRIBUTES,
                    node=node,
                    required_capability=CAPABILITY_ATTRIBUTES,
                    message="attributes changed",
                    details={
                        "added": sorted(after_keys - before_keys),
                        "removed": sorted(before_keys - after_keys),
                        "changed": sorted(changed),
                    },
                    before_path=record.path,
                )
            )

        parent = node.getparent()
        if parent is not record.parent:
            changes.append(
                NodeChange(
                    CHANGE_MOVE,
                    node=node,
                    required_capability=CAPABILITY_MOVE,
                    message="node was moved to a different parent",
                    details={"before_path": record.path},
                    before_path=record.path,
                )
            )
        elif parent is not None:
            index = list(parent).index(node)
            if index != record.index:
                changes.append(
                    NodeChange(
                        CHANGE_REORDER,
                        node=node,
                        required_capability=CAPABILITY_MOVE,
                        message="node position changed inside its parent",
                        details={"before_index": record.index, "after_index": index},
                        before_path=record.path,
                    )
                )

    for node, record in records.items():
        if node in current_set:
            continue
        parent = record.parent
        if parent is not None and parent not in current_set:
            parent_record = records.get(parent)
            if parent_record is not None and parent not in current_set:
                continue
        changes.append(
            NodeChange(
                CHANGE_REMOVE,
                node=node,
                required_capability=CAPABILITY_REMOVE,
                message="node was removed",
                before_path=record.path,
            )
        )

    _detect_ancestor_replacements(changes, records, current_set, root)
    return changes


def _detect_ancestor_replacements(changes, records, current_set, root):
    replacement_changes = []
    handled_ancestors = set()

    for node, record in records.items():
        if node not in current_set:
            continue
        missing_ancestor = None
        for ancestor in record.ancestors:
            if ancestor not in current_set:
                missing_ancestor = ancestor
                break
        if missing_ancestor is None or missing_ancestor in handled_ancestors:
            continue
        ancestor_record = records.get(missing_ancestor)
        replacement = _find_replacement(ancestor_record, records, current_set)
        if replacement is None:
            continue
        handled_ancestors.add(missing_ancestor)
        change = NodeChange(
            CHANGE_REPLACE_ANCESTOR,
            node=node,
            ancestor=missing_ancestor,
            replacement=replacement,
            required_capability=CAPABILITY_REPLACE_ANCESTOR,
            message="an ancestor element was replaced",
            before_path=ancestor_record.path if ancestor_record else None,
        )
        replacement_changes.append(change)

    for replacement_change in replacement_changes:
        ancestor = replacement_change.refs["ancestor"]
        new_node = replacement_change.refs["replacement"]
        for change in changes:
            if change.absorbed_by is not None:
                continue
            if (change.kind == CHANGE_REMOVE and change.node is ancestor) or (
                change.kind == CHANGE_INSERT and change.node is new_node
            ):
                change.absorbed_by = replacement_change
            elif change.kind in {CHANGE_MOVE, CHANGE_REORDER}:
                record = records.get(change.node)
                if record is not None and ancestor in record.ancestors:
                    change.absorbed_by = replacement_change
        changes.append(replacement_change)


def _find_replacement(ancestor_record, records, current_set):
    if ancestor_record is None:
        return None
    parent = ancestor_record.parent
    if parent is None or parent not in current_set:
        return None
    index = ancestor_record.index
    candidates = []
    if len(parent) > index:
        candidates.append(parent[index])
    for offset in (-1, 1):
        candidate_index = index + offset
        if 0 <= candidate_index < len(parent):
            candidates.append(parent[candidate_index])
    for candidate in candidates:
        if is_element(candidate) and candidate not in records:
            return candidate
    return None


class Violation:
    """One failed declaration check."""

    def __init__(
        self,
        *,
        code,
        message,
        callback_name=None,
        callback=None,
        node=None,
        change=None,
        required_capability=None,
        details=None,
    ):
        self.code = code
        self.message = message
        self.callback_name = callback_name
        self.callback = callback
        self.node = node
        self.change = change
        self.required_capability = required_capability
        self.details = details or {}

    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
            "callback": self.callback_name,
            "node": _describe_node(self.node),
            "required_capability": self.required_capability,
            "details": self.details,
        }

    def __str__(self):
        prefix = f"[{self.code}]"
        if self.callback_name:
            prefix += f" callback={self.callback_name!r}"
        node = _describe_node(self.node)
        if node:
            prefix += f" node={node}"
        return f"{prefix}: {self.message}"


def _describe_node(node):
    if not is_element(node):
        return None
    attribution = ""
    for key in ("data-role", "data-part", "id", "class"):
        value = node.get(key)
        if value:
            attribution += f" {key}={value!r}"
    text = (node.text or "").strip().replace("\n", " ")[:30]
    return f"<{node.tag}{attribution}>{text}"


class ImpactReport:
    """All changes measured for one callback and resulting violations."""

    def __init__(self, changes=None, violations=None, callback_name=None):
        self.changes = list(changes or [])
        self.violations = list(violations or [])
        self.callback_name = callback_name

    @property
    def passed(self):
        return not self.violations

    ok = passed

    @property
    def failures(self):
        return self.violations

    @property
    def scope_violations(self):
        return [v for v in self.violations if v.code == "scope_violation"]

    @property
    def capability_violations(self):
        return [v for v in self.violations if v.code == "capability_violation"]

    def summary(self):
        if not self.violations:
            return (
                f"callback {self.callback_name!r}: "
                f"{len(self.changes)} change(s), all within its declaration"
            )
        lines = [
            f"callback {self.callback_name!r} failed {len(self.violations)} check(s):"
        ]
        lines.extend(f"  - {violation}" for violation in self.violations)
        return "\n".join(lines)

    def __str__(self):
        return self.summary()


def verify_impact(
    changes, declaration, *, before_root=None, root=None, callback_name=None
):
    """Check every *change* against the scope/capability *declaration*."""
    violations = []
    scope = declaration.scope if declaration is not None else NodeScope()
    if scope is None:
        scope = NodeScope()

    for change in changes:
        if change.absorbed_by is not None:
            continue

        scope_problem = _check_scope(change, scope, before_root, root)
        if scope_problem is not None:
            violations.append(
                Violation(
                    code="scope_violation",
                    message=scope_problem,
                    callback_name=callback_name,
                    node=_primary_node(change),
                    change=change,
                    details={"kind": change.kind},
                )
            )

        if declaration is not None and not declaration.allows_capability(
            change.required_capability
        ):
            violations.append(
                Violation(
                    code="capability_violation",
                    message=(
                        f"mutation {change.kind!r} requires capability "
                        f"{change.required_capability!r}, which was not declared"
                    ),
                    callback_name=callback_name,
                    node=_primary_node(change),
                    change=change,
                    required_capability=change.required_capability,
                    details={"kind": change.kind},
                )
            )

    return violations


def _primary_node(change):
    ancestor = change.refs.get("ancestor")
    if ancestor is not None:
        return ancestor
    return change.node


def _scope_allows_before(scope, before_root, path):
    if scope.is_all:
        return True
    if path is not None and scope.contains_path(path):
        return True
    if before_root is None or path is None:
        return False
    try:
        before_node = resolve_path(before_root, path)
    except (IndexError, TypeError):
        return False
    return scope.contains(before_node)


def _scope_allows_after(scope, root, node):
    if scope.is_all:
        return True
    if not is_element(node):
        return False
    if scope.contains(node):
        return True
    if root is not None:
        path = path_relative_to(node, root)
        if scope.contains_path(path):
            return True
    parent = node.getparent()
    while parent is not None:
        if scope.contains(parent):
            return True
        parent = parent.getparent()
    return False


def _move_destination_allowed(scope, root, node):
    """Judge a move destination by its new location, not the moved node.

    A moved node often keeps the marker a predicate matches on, so testing
    the node itself would allow moving it into an unscoped subtree.
    """
    if scope.is_all:
        return True
    if root is not None:
        path = path_relative_to(node, root)
        if scope.contains_path(path):
            return True
    parent = node.getparent()
    while parent is not None:
        if scope.contains(parent):
            return True
        parent = parent.getparent()
    return False


def _check_scope(change, scope, before_root, root):  # noqa: C901
    kind = change.kind
    node = change.node

    if kind == CHANGE_INSERT:
        if scope.is_all:
            return None
        if is_element(node) and (
            scope.contains(node) or _scope_allows_after(scope, root, node)
        ):
            return None
        return "inserted node is outside the declared node scope"

    if kind == CHANGE_REMOVE:
        path = change.refs.get("before_path")
        if _scope_allows_before(scope, before_root, path):
            return None
        if path and len(path) and _scope_allows_before(scope, before_root, path[:-1]):
            return None
        return "removed node is outside the declared node scope"

    if kind == CHANGE_REPLACE_ANCESTOR:
        ancestor = change.refs.get("ancestor")
        replacement = change.refs.get("replacement")
        ancestor_path = change.refs.get("before_path")
        ancestor_allowed = _scope_allows_before(scope, before_root, ancestor_path)
        if not ancestor_allowed and is_element(ancestor):
            ancestor_allowed = scope.contains(ancestor)
        replacement_allowed = True
        if replacement is not None:
            replacement_allowed = scope.contains(replacement) or _scope_allows_after(
                scope, root, replacement
            )
        if not ancestor_allowed or not replacement_allowed:
            return (
                "replaced ancestor is outside the declared node scope "
                f"(ancestor allowed={ancestor_allowed}, replacement allowed={replacement_allowed})"
            )
        return None

    record_path = change.refs.get("before_path")
    if record_path is not None:
        before_allowed = _scope_allows_before(scope, before_root, record_path)
    else:
        before_allowed = scope.is_all or (is_element(node) and scope.contains(node))

    if kind == CHANGE_REORDER:
        if not before_allowed:
            return "reordered node is outside the declared node scope"
        return None

    if kind == CHANGE_MOVE:
        destination_allowed = _move_destination_allowed(scope, root, node)
        if not before_allowed or not destination_allowed:
            return (
                "moved node crosses the boundary of the declared node scope "
                f"(before allowed={before_allowed}, "
                f"destination allowed={destination_allowed})"
            )
        return None

    if not before_allowed:
        return "modified node is outside the declared node scope"
    return None


class CallbackTransactionError(RuntimeError):
    """Base class for transaction/callback failures."""

    def __init__(self, message="", *, report=None, violations=None):
        super().__init__(message)
        self.report = report
        self.violations = list(violations or [])

    @property
    def scope_violations(self):
        return [
            violation
            for violation in self.violations
            if getattr(violation, "code", None) == "scope_violation"
        ]

    @property
    def capability_violations(self):
        return [
            violation
            for violation in self.violations
            if getattr(violation, "code", None) == "capability_violation"
        ]

    @property
    def failure_report(self):
        return self.report


TransactionError = CallbackTransactionError


class TransactionViolation(CallbackTransactionError):  # noqa: N818
    """One or more declaration checks failed."""

    def __init__(self, message="", *, report=None, violations=None):
        if not message and violations:
            message = "\n".join(str(violation) for violation in violations)
        super().__init__(message, report=report, violations=violations)
        if report is not None:
            report.violations = list(violations or report.violations)


class ScopeViolation(TransactionViolation):
    """A callback touched nodes outside its declared scope."""


class CapabilityViolation(TransactionViolation):
    """A callback used a mutation it did not declare capabilities for."""


ScopeViolationError = ScopeViolation
CapabilityViolationError = CapabilityViolation
ScopeError = ScopeViolation
CapabilityError = CapabilityViolation


class CallbackExecutionError(CallbackTransactionError):
    """A callback raised while the chain was being composed."""

    def __init__(self, message="", *, original=None, report=None, violations=None):
        super().__init__(message, report=report, violations=violations)
        self.original = original
        if original is not None and self.__cause__ is None:
            self.__cause__ = original


CallbackFailed = CallbackExecutionError
CallbackExecutionFailure = CallbackExecutionError
ExtensionFailed = CallbackExecutionError
CallbackError = CallbackExecutionError
ExtensionExecutionError = CallbackExecutionError


def exception_for_violations(violations, report=None):
    scope_violations = [v for v in violations if v.code == "scope_violation"]
    if scope_violations:
        message = "\n".join(str(v) for v in violations)
        return ScopeViolation(message, report=report, violations=violations)
    message = "\n".join(str(v) for v in violations)
    return CapabilityViolation(message, report=report, violations=violations)


class CallbackContext:
    """Per callback handout: explicit snapshot, scope and transaction handle."""

    def __init__(
        self,
        *,
        transaction=None,
        index=None,
        name=None,
        declaration=None,
        snapshot=None,
        root=None,
    ):
        self.transaction = transaction
        self.index = index
        self.name = name
        self.declaration = declaration
        self.scope = declaration.scope if declaration is not None else NodeScope()
        self.capabilities = (
            declaration.capabilities if declaration is not None else None
        )
        self.snapshot = snapshot
        self._root = root
        self.returned = None

    @property
    def root(self):
        if self._root is not None:
            return self._root
        return self.transaction.root if self.transaction is not None else None

    @property
    def tree(self):
        return self.root

    def read_committed(self):
        return self.transaction.read_html() if self.transaction is not None else None


class CallbackTransaction:
    """Isolated composition of an ordered callback chain.

    The caller's tree is never mutated until :meth:`commit`.  Any raised
    callback or failed scope/capability check discards the isolated working
    snapshot, so external readers keep seeing the last committed state.
    """

    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_COMPOSED = "composed"
    STATUS_COMMITTED = "committed"
    STATUS_ROLLED_BACK = "rolled_back"

    def __init__(self, root=None, callbacks=None, *, html=None, parser=None, **kwargs):
        if callbacks is None and root is not None and not is_element(root):
            if isinstance(root, str):
                html = root
                root = None
            else:
                callbacks = root
                root = None
        if root is None and html is not None:
            root = (parser or lxml.html.fromstring)(html)
        if callbacks is None:
            callbacks = kwargs.pop("processors", None)
        self.callbacks = [coerce_callback(cb) for cb in (callbacks or [])]
        self.parser = parser
        self.status = self.STATUS_PENDING
        self.reports = []
        self.violations = []
        self.errors = []
        self.original_root = None
        self.committed_snapshot = None
        self.working_snapshot = None
        self.root = None
        self.subject = None
        if root is not None:
            self.bind(root)

    def bind(self, root):
        """Bind a deferred chain to the tree it should operate on."""
        if self.original_root is not None and self.original_root is not root:
            raise CallbackTransactionError("Transaction is already bound to a root")
        self.original_root = root
        self.committed_snapshot = Snapshot.capture(root, label="committed")
        self.working_snapshot = Snapshot.capture(root, label="working")
        self.root = self.working_snapshot.root
        self.subject = self.root
        return self

    @classmethod
    def from_html(cls, html, callbacks=None):
        return cls(callbacks=callbacks, html=html)

    def add(self, callback, *, scope=None, capabilities=None, **kwargs):
        if scope is not None or capabilities is not None or kwargs:
            callback = ScopedCallback(
                callback, scope=scope, capabilities=capabilities, **kwargs
            )
        self.callbacks.append(coerce_callback(callback))
        return self

    use = add

    def read_snapshot(self):
        return self.committed_snapshot

    def read_html(self):
        """Serialize the last committed state (never a half-composed tree)."""
        if self.committed_snapshot is None:
            return None
        return self.committed_snapshot.to_html()

    def read(self):
        return self.read_html()

    def _ensure_runnable(self):
        if self.status == self.STATUS_COMMITTED:
            raise CallbackTransactionError("Transaction has already been committed")
        if self.status == self.STATUS_ROLLED_BACK:
            raise CallbackTransactionError("Transaction has been rolled back")

    def run(self, root=None, *, commit=False):
        """Run the whole chain on the isolated snapshot.

        A root may be supplied for chains constructed in deferred style,
        e.g. ``CallbackChain(processors).run(root)``.
        """
        if root is not None and self.original_root is None:
            self.bind(root)
        if self.original_root is None:
            raise CallbackTransactionError(
                "CallbackTransaction requires a root element or html="
            )
        self._ensure_runnable()
        self.status = self.STATUS_RUNNING
        try:
            for index, callback in enumerate(self.callbacks):
                self._run_callback(index, callback)
        except BaseException:
            self.rollback()
            raise
        self.status = self.STATUS_COMPOSED
        self.working_snapshot = Snapshot.capture(self.root, label="composed")
        if commit:
            self.commit()
        return self

    def process(self, root=None, *, commit=True):
        """Run the chain and return the committed root element."""
        self.run(root, commit=commit)
        return self.original_root

    apply = process

    execute = run

    def _callback_name(self, index, callback):
        declaration = get_declaration(callback)
        if declaration is not None and declaration.name:
            return declaration.name
        wrapped = getattr(callback, "callback", callback)
        return getattr(wrapped, "__name__", None) or f"callback_{index}"

    def _run_callback(self, index, callback):
        declaration = get_declaration(callback) or CallbackDeclaration()
        name = self._callback_name(index, callback)
        before_snapshot = Snapshot.capture(self.root, label=f"before:{name}")
        records = build_records(self.root)
        context = CallbackContext(
            transaction=self,
            index=index,
            name=name,
            declaration=declaration,
            snapshot=before_snapshot,
        )

        error = None
        try:
            returned = invoke_callback(callback, self.subject, context)
        except Exception as exc:  # extensions may fail halfway
            error = exc
            returned = None

        changes = diff_tree(self.root, records)
        violations = verify_impact(
            changes,
            declaration,
            before_root=before_snapshot.root,
            root=self.root,
            callback_name=name,
        )
        report = ImpactReport(changes, violations, callback_name=name)
        self.reports.append(report)
        self.violations.extend(violations)
        context.returned = returned

        if error is not None:
            execution_error = CallbackExecutionError(
                f"callback {name!r} raised {type(error).__name__}: {error}",
                original=error,
                report=report,
                violations=violations,
            )
            self.errors.append(execution_error)
            raise execution_error from error

        if violations:
            raise exception_for_violations(violations, report)

        if is_element(returned):
            self.subject = returned

    def commit(self):
        """Publish the composed snapshot into the caller's tree."""
        if self.status == self.STATUS_ROLLED_BACK:
            raise CallbackTransactionError(
                "Cannot commit a rolled back transaction",
                violations=self.violations,
            )
        if self.status == self.STATUS_COMMITTED:
            return self.original_root
        _publish_tree(self.original_root, self.root)
        self.committed_snapshot = Snapshot.capture(
            self.original_root, label="committed"
        )
        self.status = self.STATUS_COMMITTED
        return self.original_root

    def rollback(self):
        """Discard the isolated working snapshot; the caller tree is untouched."""
        self.root = None
        self.subject = None
        self.working_snapshot = None
        if self.status != self.STATUS_COMMITTED:
            self.status = self.STATUS_ROLLED_BACK
        return self.original_root

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            if self.status == self.STATUS_RUNNING:
                self.rollback()
            return False
        if self.status == self.STATUS_COMPOSED:
            self.commit()
        return False


CallbackChain = CallbackTransaction
ProcessorChain = CallbackTransaction
Transaction = CallbackTransaction
Chain = CallbackTransaction


def _publish_tree(destination, source):
    if destination.tag != source.tag:
        destination.tag = source.tag
    destination.text = source.text
    destination.tail = source.tail
    destination.attrib.clear()
    for key, value in source.attrib.items():
        destination.set(key, value)
    for child in list(destination):
        destination.remove(child)
    for child in source:
        destination.append(copy.deepcopy(child))


def run_callback_chain(*arguments, commit=True, return_transaction=False, **options):
    """Run a callback chain atomically.

    Argument order is tolerated: ``run_callback_chain(callbacks, root)`` and
    ``run_callback_chain(root, callbacks)`` both work.  A single callable is
    accepted as the chain and an HTML string is parsed into a root.  Returns
    the committed root element, or the :class:`CallbackTransaction` when
    ``return_transaction=True``.
    """
    html = options.pop("html", None)
    parser = options.pop("parser", None)
    default_scope = options.pop("scope", None)
    default_capabilities = options.pop("capabilities", None)
    keyword_root = options.pop("root", None)
    keyword_callbacks = options.pop("callbacks", None)
    if keyword_root is not None:
        arguments = (keyword_root, *arguments)
    if keyword_callbacks is not None:
        arguments = (*arguments, keyword_callbacks)

    roots = [value for value in arguments if is_element(value)]
    strings = [value for value in arguments if isinstance(value, str) and "<" in value]
    chains = [
        value
        for value in arguments
        if value is not None
        and not is_element(value)
        and not (isinstance(value, str) and "<" in value)
    ]

    root = roots[0] if roots else None
    if root is None and html is not None:
        root = (parser or lxml.html.fromstring)(html)
    if root is None and strings:
        root = (parser or lxml.html.fromstring)(strings[0])

    callbacks = chains[0] if chains else []
    if callbacks is None:
        callbacks = []
    if callable(callbacks):
        callbacks = [callbacks]
    elif isinstance(callbacks, (tuple, list)):
        callbacks = list(callbacks)
    if default_scope is not None or default_capabilities is not None:
        callbacks = [
            callback
            if get_declaration(callback) is not None
            else ScopedCallback(
                callback,
                scope=default_scope,
                capabilities=default_capabilities,
            )
            for callback in callbacks
        ]

    if root is None:
        raise TypeError("run_callback_chain expects a root element or html=")

    transaction = CallbackTransaction(root, callbacks, parser=parser, **options)
    transaction.run(commit=commit)
    return transaction if return_transaction else transaction.original_root


def guarded_callback_call(
    callback,
    element,
    root,
    *,
    declaration=None,
    callback_name=None,
):
    """Run one callback on a live sanitizer tree and verify its impact.

    Returns the callback result.  Raises :class:`TransactionViolation` or
    :class:`CallbackExecutionError` with a full :class:`ImpactReport`.
    """
    if declaration is None:
        declaration = get_declaration(callback)
    if declaration is None:
        return invoke_callback(callback, element, None)
    name = (
        callback_name or declaration.name or getattr(callback, "__name__", "callback")
    )
    before_snapshot = Snapshot.capture(root, label=f"before:{name}")
    records = build_records(root)
    context = CallbackContext(
        index=0,
        name=name,
        declaration=declaration,
        snapshot=before_snapshot,
        root=root,
    )
    error = None
    try:
        result = invoke_callback(callback, element, context)
    except Exception as exc:
        error = exc
        result = None
    changes = diff_tree(root, records)
    violations = verify_impact(
        changes,
        declaration,
        before_root=before_snapshot.root,
        root=root,
        callback_name=name,
    )
    report = ImpactReport(changes, violations, callback_name=name)
    if error is not None:
        raise CallbackExecutionError(
            f"callback {name!r} raised {type(error).__name__}: {error}",
            original=error,
            report=report,
            violations=violations,
        ) from error
    if violations:
        raise exception_for_violations(violations, report)
    return result


ScopedProcessor = ScopedCallback
ScopedExtension = ScopedCallback
CallbackSpec = ScopedCallback
ProcessorSpec = ScopedCallback
ExtensionSpec = ScopedCallback
Scoped = ScopedCallback
ProcessorDeclaration = CallbackDeclaration
CallbackScope = NodeScope
ScopeDeclaration = NodeScope
TransactionalChain = CallbackTransaction
transactional = CallbackTransaction
