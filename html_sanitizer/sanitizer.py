import re
import unicodedata
from collections import deque
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from inspect import Parameter, signature

import lxml.html
import lxml.html.clean


__all__ = (
    "UndeclaredMutationError",
    "ScopedCallback",
    "SanitizerCallback",
    "ProcessorDeclaration",
    "ProcessorConfig",
    "OutOfScopeError",
    "NodeScopeError",
    "CallbackSpec",
    "CallbackError",
    "CallbackProcessor",
    "CallbackScopeError",
    "Capability",
    "ElementCallback",
    "ElementProcessor",
    "ElementProcessorSpec",
    "ElementScope",
    "Mutation",
    "MutationError",
    "MutationViolation",
    "NodeRange",
    "NodeScope",
    "NodeScopeSpec",
    "ProcessingContext",
    "ProcessingError",
    "Processor",
    "ProcessorError",
    "ProcessorMutation",
    "ProcessorMutationError",
    "ProcessorScopeError",
    "ProcessorSpec",
    "Sanitizer",
    "SanitizerError",
    "SanitizerProcessor",
    "Scope",
    "ScopeError",
    "ScopeViolation",
    "ScopeViolationError",
    "ScopedProcessor",
    "TransactionError",
    "callback",
    "element_processor",
    "processor",
    "sanitizer_callback",
    "scoped",
    "scoped_processor",
)


class SanitizerError(RuntimeError):
    """Base class for errors raised by the sanitizer."""


class Mutation(str, Enum):
    """
    Names of the changes a cleaning callback may declare.

    The values are strings on purpose so that plain string sets continue to
    work. ``Mutation.TEXT`` and ``"text"`` are interchangeable.
    """

    TEXT = "text"
    TAIL = "tail"
    ATTRIBUTES = "attributes"
    ATTRIBUTE = "attributes"  # noqa: PIE796
    ATTRIB = "attributes"  # noqa: PIE796
    TAG = "tag"
    NAME = "tag"  # noqa: PIE796
    CHILDREN = "children"
    CONTENT = "content"
    STRUCTURE = "structure"
    MOVE = "move"
    PARENT = "parent"
    ADD = "add"
    INSERT = "add"  # noqa: PIE796
    REMOVE = "remove"
    DELETE = "remove"  # noqa: PIE796
    REPLACE = "replace"
    ALL = "all"


Capability = Mutation
ProcessorMutation = Mutation


_ALL_MUTATIONS = frozenset(
    {
        "text",
        "tail",
        "attributes",
        "tag",
        "children",
        "add",
        "remove",
        "move",
        "parent",
        "replace",
    }
)


_CAPABILITY_IMPLIES = {
    "all": _ALL_MUTATIONS,
    "*": _ALL_MUTATIONS,
    "text": frozenset({"text", "tail"}),
    "content": frozenset({"text", "tail", "children", "add", "remove", "replace"}),
    "contents": frozenset({"text", "tail", "children", "add", "remove", "replace"}),
    "attributes": frozenset({"attributes"}),
    "attribute": frozenset({"attributes"}),
    "attrs": frozenset({"attributes"}),
    "attr": frozenset({"attributes"}),
    "tag": frozenset({"tag", "replace"}),
    "name": frozenset({"tag", "replace"}),
    "rename": frozenset({"tag", "replace"}),
    "children": frozenset({"children", "add", "remove", "replace", "move"}),
    "child": frozenset({"children", "add", "remove", "replace", "move"}),
    "structure": frozenset(
        {
            "text",
            "tail",
            "attributes",
            "tag",
            "children",
            "add",
            "remove",
            "move",
            "parent",
            "replace",
        }
    ),
    "tree": frozenset(
        {
            "text",
            "tail",
            "attributes",
            "tag",
            "children",
            "add",
            "remove",
            "move",
            "parent",
            "replace",
        }
    ),
    "move": frozenset({"move", "parent", "children"}),
    "parent": frozenset({"parent", "move", "children"}),
    "add": frozenset({"add", "children"}),
    "insert": frozenset({"add", "children"}),
    "remove": frozenset({"remove", "children"}),
    "delete": frozenset({"remove", "children"}),
    "replace": frozenset({"replace", "children", "tag", "add", "remove"}),
    "replacement": frozenset({"replace", "children", "tag", "add", "remove"}),
    "read": frozenset(),
    "readonly": frozenset(),
}


def _enum_value(value):
    return value.value if isinstance(value, Enum) else value


_MUTATION_ALIASES = {
    "write_text": "text",
    "set_text": "text",
    "text_write": "text",
    "write_attribute": "attributes",
    "write_attributes": "attributes",
    "set_attribute": "attributes",
    "set_attributes": "attributes",
    "attribute_write": "attributes",
    "write_tag": "tag",
    "set_tag": "tag",
    "rename_tag": "tag",
    "write_children": "children",
    "set_children": "children",
    "child_write": "children",
    "insert": "add",
    "append": "add",
    "delete": "remove",
    "drop": "remove",
    "unwrap": "remove",
    "write_structure": "structure",
    "structural": "structure",
    "move_node": "move",
    "move_nodes": "move",
    "replace_node": "replace",
    "replace_nodes": "replace",
    "all_mutations": "all",
    "any": "all",
    "write": "structure",
    "modify": "structure",
    "mutate": "structure",
    "update": "structure",
    "none": "",
    "read_only": "",
}


def _normalize_mutations(value):
    if value is None:
        return None
    if isinstance(value, str):
        values = tuple(part for chunk in value.split(",") for part in chunk.split())
    elif isinstance(value, dict):
        values = [key for key, enabled in value.items() if enabled]
    else:
        try:
            values = tuple(value)
        except TypeError as exc:
            raise TypeError(
                f"Expected a string or an iterable of mutation names, got {value!r}"
            ) from exc

    mutations = set()
    for value in values:
        normalized = _enum_value(value)
        if not isinstance(normalized, str):
            raise TypeError(
                f"Expected mutation names to be strings, got {normalized!r}"
            )
        normalized = normalized.strip().lower()
        normalized = _MUTATION_ALIASES.get(normalized, normalized)
        if normalized:
            mutations.add(normalized)
    return frozenset(mutations)


def _tag_name(tag):
    return tag if isinstance(tag, str) else str(tag)


def _selector_predicate(selector):
    alternatives = [part.strip() for part in selector.split(",") if part.strip()]
    if not alternatives:
        raise TypeError(f"Empty node scope selector {selector!r}")

    def matches(element):
        for alternative in alternatives:
            if _single_selector_matches(element, alternative):
                return True
        return False

    return matches


def _single_selector_matches(element, selector):  # noqa: C901
    tag = _tag_name(element.tag)
    position = 0

    if selector[0] == "*":
        position = 1
    elif selector[0].isalpha():
        match = re.match(r"[A-Za-z][\w:-]*", selector)
        if match:
            if tag.lower() != match.group(0).lower():
                return False
            position = match.end()
    elif selector[0] not in ".#[":
        raise TypeError(f"Unsupported node scope selector {selector!r}")

    rest = selector[position:]
    while rest:
        if rest.startswith("."):
            match = re.match(r"\.([\w-]+)", rest)
            if not match:
                raise TypeError(f"Unsupported node scope selector {selector!r}")
            classes = (element.get("class") or "").split()
            if match.group(1) not in classes:
                return False
            rest = rest[match.end() :]
        elif rest.startswith("#"):
            match = re.match(r"#([\w-]+)", rest)
            if not match:
                raise TypeError(f"Unsupported node scope selector {selector!r}")
            if element.get("id") != match.group(1):
                return False
            rest = rest[match.end() :]
        elif rest.startswith("["):
            match = re.match(
                r"\[\s*([\w:-]+)\s*(?:([~^$*]?=)\s*"
                r"(?:\"([^\"]*)\"|'([^']*)'|([^\]]*?))\s*)?\]",
                rest,
            )
            if not match:
                raise TypeError(f"Unsupported node scope selector {selector!r}")
            name, operator = match.group(1), match.group(2)
            expected = next(
                (value for value in match.groups()[2:] if value is not None),
                None,
            )
            actual = element.get(name)
            if actual is None:
                return False
            if operator is None:
                pass
            elif (
                operator == "="
                and actual != (expected or "")
                or operator == "~="
                and (expected or "") not in actual.split()
                or operator == "^="
                and not actual.startswith(expected or "")
                or operator == "$="
                and not actual.endswith(expected or "")
                or operator == "*="
                and (expected or "") not in actual
            ):
                return False
            rest = rest[match.end() :]
        else:
            raise TypeError(f"Unsupported node scope selector {selector!r}")
    return True


def _element_predicate(spec):  # noqa: C901
    if isinstance(spec, NodeScope):
        return spec.matches
    if callable(spec):
        return spec
    if isinstance(spec, str):
        if spec.startswith(("/", "//", "(", "./", ".//")):
            cache = {}

            def xpath_matches(element):
                root = element.getroottree()
                key = id(root)
                matches = cache.get(key)
                if matches is None:
                    try:
                        matches = {id(el) for el in root.xpath(spec)}
                    except Exception as exc:
                        raise TypeError(
                            f"Invalid node scope XPath {spec!r}: {exc}"
                        ) from exc
                    cache[key] = matches
                return id(element) in matches

            return xpath_matches
        return _selector_predicate(spec)
    if isinstance(spec, dict):
        predicates = []
        for key, value in spec.items():
            normalized_key = str(key).lower()
            if normalized_key in {"include_descendants", "descendants"}:
                continue
            if normalized_key in {"tag", "tags"}:
                tags = {value} if isinstance(value, str) else set(value)
                predicates.append(lambda el, tags=tags: _tag_name(el.tag) in tags)
            elif normalized_key in {"class", "classes"}:
                classes = {value} if isinstance(value, str) else set(value)
                predicates.append(
                    lambda el, classes=classes: bool(
                        classes & set((el.get("class") or "").split())
                    )
                )
            elif normalized_key in {"id", "element_id"}:
                ids = {value} if isinstance(value, str) else set(value)
                predicates.append(lambda el, ids=ids: el.get("id") in ids)
            elif normalized_key in {"attribute", "attributes", "attr", "attrs"}:
                if isinstance(value, dict):
                    predicates.append(
                        lambda el, attrs=value: all(
                            el.get(name) == expected for name, expected in attrs.items()
                        )
                    )
                elif isinstance(value, str):
                    predicates.append(lambda el, name=value: name in el.attrib)
                else:
                    names = set(value)
                    predicates.append(lambda el, names=names: names.issubset(el.attrib))
            elif normalized_key in {"selector", "css", "css_selector"}:
                predicates.append(_selector_predicate(value))
            elif normalized_key in {"xpath", "path"}:
                predicates.append(_element_predicate(value))
            elif normalized_key in {"predicate", "matches", "match"}:
                predicates.append(value)
            elif normalized_key in {"element", "elements", "nodes"}:
                predicates.append(_element_predicate(value))
            elif normalized_key in {"text"}:
                predicates.append(lambda el, text=value: (el.text or "") == text)
            elif str(key).startswith(("data-", "aria-")):
                predicates.append(
                    lambda el, name=str(key), expected=value: el.get(name) == expected
                )
            else:
                raise TypeError(f"Unsupported node scope key {key!r}")

        if not predicates:
            raise TypeError("Empty node scope specification")

        def dict_matches(element):
            return all(predicate(element) for predicate in predicates)

        return dict_matches
    if isinstance(spec, (set, frozenset, list, tuple)):
        values = tuple(spec)
        if not values:
            raise TypeError("Empty node scope cannot match anything")
        if all(isinstance(value, str) for value in values):
            if any(
                any(marker in value for marker in ".#[,")
                or value.startswith(("/", "./", "//", ".//"))
                for value in values
            ):
                predicates = [_element_predicate(value) for value in values]
                return lambda element: any(
                    predicate(element) for predicate in predicates
                )
            tags = set(values)
            return lambda element: _tag_name(element.tag) in tags
        if all(hasattr(value, "tag") for value in values):
            elements = set(values)
            descendants = set()
            for element in elements:
                descendants.update(element.iterdescendants())
            return lambda candidate: candidate in elements or candidate in descendants
        if all(isinstance(value, NodeScope) for value in values):
            return lambda element: any(value.matches(element) for value in values)
        raise TypeError(f"Unsupported node scope specification {spec!r}")
    if hasattr(spec, "tag"):
        element = spec
        descendants = set(element.iterdescendants())
        return lambda candidate: candidate is element or candidate in descendants
    raise TypeError(f"Unsupported node scope specification {spec!r}")


class NodeScope:
    """
    Describes the nodes a cleaning callback is allowed to touch.

    A scope accepts a predicate, a tag name, a set of tag names, a small CSS
    selector subset (``"p.notice"``, ``"#main"``, ``"[data-kind=course]"``), an
    XPath expression, a mapping of conditions or explicit lxml elements.

    By default the scope is a region: the matching node and its descendants are
    in scope. This makes it possible to guard e.g. a paragraph and everything
    rendered inside it.
    """

    def __init__(self, spec=None, **kwargs):
        spec_options = spec if isinstance(spec, dict) else {}
        include_descendants = kwargs.pop(
            "include_descendants",
            kwargs.pop(
                "descendants",
                spec_options.get(
                    "include_descendants",
                    spec_options.get("descendants", True),
                ),
            ),
        )
        self.include_descendants = bool(include_descendants)

        predicates = []
        if spec is not None:
            predicates.append(_element_predicate(spec))

        if kwargs:
            predicates.append(_element_predicate(kwargs))

        if not predicates:
            raise TypeError("A node scope needs at least one matcher")

        self._predicates = tuple(predicates)

    @property
    def descendants(self):
        return self.include_descendants

    def matches(self, element):
        return all(predicate(element) for predicate in self._predicates)

    def applies_to(self, element):
        """Return whether the callback should be invoked for this element.

        Scopes describe a region for mutation validation. The callback itself
        is invoked once for each node matching the scope root, not once for
        every descendant in the region.
        """
        return self.matches(element)

    def roots(self, states):
        return {element for element in states if self.matches(element)}

    def contains(self, element, states, roots):
        if element is None:
            return False
        if not self.include_descendants:
            return element in roots

        seen = set()
        current = element
        while current is not None and current not in seen:
            seen.add(current)
            if current in roots:
                return True
            state = states.get(current)
            if state is not None:
                current = state.parent
            else:
                try:
                    current = current.getparent()
                except AttributeError:
                    current = None
        return False

    def __repr__(self):
        return f"NodeScope({self._predicates!r})"


Scope = NodeScope
ElementScope = NodeScope
NodeRange = NodeScope
NodeScopeSpec = NodeScope


@dataclass
class ProcessingContext:
    """
    Context passed to new-style callbacks which declare a second parameter.

    ``snapshot`` is an explicit deep copy of the document as it looked before
    this callback ran. Mutating it never changes the live tree.
    """

    root: object
    element: object
    processor: str
    phase: str = "preprocess"
    scope: NodeScope | None = None
    mutations: frozenset[str] | None = None
    _snapshot: object | None = field(default=None, init=False, repr=False)

    @property
    def tree(self):
        return self.root

    @property
    def document(self):
        return self.root

    @property
    def current(self):
        return self.element

    @property
    def target(self):
        return self.element

    @property
    def name(self):
        return self.processor

    @property
    def snapshot(self):
        if self._snapshot is None:
            self._snapshot = deepcopy(self.root)
        return self._snapshot

    @property
    def before(self):
        return self.snapshot

    @property
    def original(self):
        return self.snapshot

    def __getattr__(self, name):
        # Let callbacks which expect a snapshot element in the second
        # argument inspect it directly.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.snapshot, name)

    def __iter__(self):
        return iter(self.snapshot)

    def __len__(self):
        return len(self.snapshot)

    def __getitem__(self, index):
        return self.snapshot[index]


def _looks_like_document_callback(callback):
    try:
        parameters = tuple(signature(callback).parameters.values())
    except (TypeError, ValueError):
        return False
    if not parameters:
        return False
    return parameters[0].name in {
        "root",
        "document",
        "document_root",
        "doc",
        "tree",
    }


def _callback_name(callback):
    return getattr(callback, "__name__", None) or type(callback).__name__


def _wants_context(callback):
    try:
        parameters = tuple(signature(callback).parameters.values())
    except (TypeError, ValueError):
        return False
    if any(
        parameter.name in {"context", "ctx", "transaction", "snapshot", "state"}
        for parameter in parameters
    ):
        return True
    required_positional = [
        parameter
        for parameter in parameters
        if parameter.default is Parameter.empty
        and parameter.kind
        in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)
    ]
    return len(required_positional) >= 2


def _call_callback(callback, element, context, accepts_context=None):
    if accepts_context is None:
        accepts_context = _wants_context(callback)
    if accepts_context:
        return callback(element, context)
    return callback(element)


class Processor:
    """
    A cleaning callback together with an optional scope and mutation set.

    ``Processor(fn)`` can be used wherever a plain callback was used before.
    Likewise any object with a ``process`` method is accepted. Plain callables
    without declarations keep their old, unrestricted behaviour.
    """

    def __init__(  # noqa: C901
        self,
        callback=None,
        *args,
        processor=None,
        func=None,
        function=None,
        fn=None,
        process=None,
        scope=None,
        mutations=None,
        capabilities=None,
        capability=None,
        modifies=None,
        writes=None,
        allowed_mutations=None,
        name=None,
        label=None,
        document=False,
        accepts_context=None,
        node_scope=None,
        **kwargs,
    ):
        if len(args) > 2:
            raise TypeError("Processor accepts at most callback, scope and mutations")
        if args:
            if scope is not None:
                raise TypeError("Scope was given more than once")
            scope = args[0]
            if len(args) > 1:
                if mutations is not None:
                    raise TypeError("Mutations were given more than once")
                mutations = args[1]
        if node_scope is not None:
            if scope is not None:
                raise TypeError("Scope was given more than once")
            scope = node_scope

        if kwargs:
            for alias, target in (
                ("nodes", "scope"),
                ("node_range", "scope"),
                ("within", "scope"),
                ("region", "scope"),
                ("mutates", "mutations"),
                ("changes", "mutations"),
                ("effects", "mutations"),
                ("can_modify", "mutations"),
                ("with_context", "accepts_context"),
                ("whole_document", "document"),
            ):
                if alias not in kwargs:
                    continue
                value = kwargs.pop(alias)
                if target == "scope":
                    if scope is not None:
                        raise TypeError("Scope was given more than once")
                    scope = value
                elif target == "mutations":
                    if mutations is not None:
                        raise TypeError("Mutations were given more than once")
                    mutations = value
                elif target == "accepts_context":
                    if accepts_context is not None:
                        raise TypeError("accepts_context was given more than once")
                    accepts_context = value
                elif target == "document":
                    document = value
            if kwargs:
                raise TypeError(f"Unknown processor options {sorted(kwargs)!r}")

        if isinstance(callback, dict):
            spec = dict(callback)
            for alias, target in (
                ("fn", "callback"),
                ("func", "callback"),
                ("function", "callback"),
                ("processor", "callback"),
                ("callable", "callback"),
                ("process", "callback"),
                ("nodes", "scope"),
                ("node_scope", "scope"),
                ("node_range", "scope"),
                ("within", "scope"),
                ("region", "scope"),
                ("mutates", "mutations"),
                ("changes", "mutations"),
                ("effects", "mutations"),
                ("can_modify", "mutations"),
                ("with_context", "accepts_context"),
                ("whole_document", "document"),
            ):
                if alias not in spec:
                    continue
                value = spec.pop(alias)
                spec.setdefault(target, value)
            callback = spec.pop(
                "callback",
                spec.pop(
                    "processor",
                    spec.pop(
                        "func",
                        spec.pop("function", spec.pop("fn", None)),
                    ),
                ),
            )
            scope = spec.pop("scope", spec.pop("node_scope", scope))
            mutations = spec.pop(
                "mutations",
                spec.pop(
                    "capabilities",
                    spec.pop(
                        "capability",
                        spec.pop(
                            "modifies",
                            spec.pop(
                                "writes",
                                spec.pop("allowed_mutations", mutations),
                            ),
                        ),
                    ),
                ),
            )
            name = spec.pop("name", spec.pop("label", name))
            document = spec.pop("document", document)
            accepts_context = spec.pop("accepts_context", accepts_context)
            if spec:
                raise TypeError(f"Unknown processor options {sorted(spec)!r}")

        callback = next(
            (
                value
                for value in (callback, processor, func, function, fn, process)
                if value is not None
            ),
            None,
        )
        if callback is None:
            raise TypeError("A processor needs a callback")
        if not callable(callback):
            process = getattr(callback, "process", None)
            if not callable(process):
                raise TypeError(f"Processor callback {callback!r} is not callable")
            callback = process

        declared_mutations = next(
            (
                value
                for value in (
                    mutations,
                    capabilities,
                    capability,
                    modifies,
                    writes,
                    allowed_mutations,
                )
                if value is not None
            ),
            None,
        )

        self.callback = callback
        self.processor = callback
        self.func = callback
        self.scope = (
            scope if scope is None or isinstance(scope, NodeScope) else NodeScope(scope)
        )
        self.mutations = _normalize_mutations(declared_mutations)
        self.name = name or label or _callback_name(callback)
        self.document = bool(document)
        self.accepts_context = accepts_context

    def __call__(self, element, context=None):
        if context is None:
            return _call_callback(self.callback, element, None, self.accepts_context)
        return _call_callback(self.callback, element, context, self.accepts_context)

    def __repr__(self):
        return (
            f"Processor({self.name!r}, scope={self.scope!r},"
            f" mutations={self.mutations!r})"
        )


ElementProcessor = Processor
ScopedProcessor = Processor
ProcessorSpec = Processor
CallbackProcessor = Processor
SanitizerProcessor = Processor
ElementProcessorSpec = Processor
ElementCallback = Processor
CallbackSpec = Processor
ProcessorDeclaration = Processor
ProcessorConfig = Processor
ScopedCallback = Processor
SanitizerCallback = Processor


@dataclass(frozen=True)
class _ProcessorSpec:
    callback: object
    scope: NodeScope | None
    mutations: frozenset[str] | None
    name: str
    document: bool = False
    accepts_context: bool | None = None
    legacy: bool = False

    @property
    def validates(self):
        return self.scope is not None or self.mutations is not None

    @property
    def transactional(self):
        return not self.legacy


def _spec_from_processor(processor, *, legacy=False):
    if isinstance(processor, _ProcessorSpec):
        return processor
    if isinstance(processor, Processor):
        return _ProcessorSpec(
            callback=processor.callback,
            scope=processor.scope,
            mutations=processor.mutations,
            name=processor.name,
            document=processor.document,
            accepts_context=processor.accepts_context,
            legacy=legacy,
        )
    raise TypeError(f"Cannot convert {processor!r} to a processor specification")


def _normalize_processor(processor):
    if isinstance(processor, _ProcessorSpec):
        return processor
    if isinstance(processor, Processor):
        return _spec_from_processor(processor)
    if isinstance(processor, dict):
        return _spec_from_processor(Processor(**processor))
    if isinstance(processor, (tuple, list)):
        if not 1 <= len(processor) <= 3:
            raise TypeError(
                "Processor tuples must contain callback, optional scope and"
                f" optional mutations, got {processor!r}"
            )
        callback = processor[0]
        scope = processor[1] if len(processor) > 1 else None
        mutations = processor[2] if len(processor) > 2 else None
        return _spec_from_processor(
            Processor(callback, scope=scope, mutations=mutations)
        )

    callback = processor
    if not callable(callback):
        process = getattr(callback, "process", None)
        if callable(process):
            callback = process
        else:
            raise TypeError(f"Element processors must be callable, got {processor!r}")

    metadata_names = (
        "scope",
        "node_scope",
        "node_range",
        "nodes",
        "within",
        "region",
        "mutations",
        "capabilities",
        "capability",
        "mutates",
        "changes",
        "effects",
        "can_modify",
        "modifies",
        "writes",
        "allowed_mutations",
        "document",
        "accepts_context",
    )
    has_metadata = any(hasattr(processor, name) for name in metadata_names)
    if not has_metadata:
        return _ProcessorSpec(
            callback=callback,
            scope=None,
            mutations=None,
            name=_callback_name(callback),
            legacy=True,
        )

    scope = getattr(processor, "scope", None)
    for name in (
        "node_scope",
        "node_range",
        "nodes",
        "within",
        "region",
    ):
        if scope is None:
            scope = getattr(processor, name, None)
    scope = scope if scope is None or isinstance(scope, NodeScope) else NodeScope(scope)
    mutations = next(
        (
            getattr(processor, name)
            for name in (
                "mutations",
                "capabilities",
                "capability",
                "mutates",
                "changes",
                "effects",
                "can_modify",
                "modifies",
                "writes",
                "allowed_mutations",
            )
            if getattr(processor, name, None) is not None
        ),
        None,
    )
    return _ProcessorSpec(
        callback=callback,
        scope=scope,
        mutations=_normalize_mutations(mutations),
        name=getattr(processor, "name", None)
        or getattr(processor, "label", None)
        or _callback_name(callback),
        document=bool(getattr(processor, "document", False)),
        accepts_context=getattr(processor, "accepts_context", None),
        legacy=False,
    )


def element_processor(
    callback=None,
    *args,
    scope=None,
    mutations=None,
    capabilities=None,
    modifies=None,
    writes=None,
    name=None,
    document=False,
    accepts_context=None,
    **kwargs,
):
    """Decorator for a declared cleaning callback."""

    if len(args) > 2:
        raise TypeError("element_processor accepts at most scope and mutations")
    if args:
        if scope is not None:
            raise TypeError("Scope was given more than once")
        scope = args[0]
        if len(args) > 1:
            if mutations is not None:
                raise TypeError("Mutations were given more than once")
            mutations = args[1]

    def decorate(function):
        return Processor(
            function,
            scope=scope,
            mutations=mutations,
            capabilities=capabilities,
            modifies=modifies,
            writes=writes,
            name=name,
            document=document,
            accepts_context=accepts_context,
            **kwargs,
        )

    if callback is None:
        return decorate
    return decorate(callback)


processor = element_processor
scoped_processor = element_processor
sanitizer_callback = element_processor
scoped = element_processor
callback = element_processor


@dataclass
class _NodeState:
    tag: object
    attrib: dict
    text: str | None
    tail: str | None
    parent: object | None
    children: tuple
    index: int | None


@dataclass
class _Change:
    kind: str
    node: object
    old_parent: object | None = None
    new_parent: object | None = None
    replacement_of: object | None = None


@dataclass(frozen=True)
class MutationViolation:
    """A single out-of-scope or undeclared mutation."""

    kind: str
    path: str
    reasons: tuple[str, ...]
    node: object = field(default=None, compare=False, repr=False)

    @property
    def mutation(self):
        return self.kind

    @property
    def node_path(self):
        return self.path

    @property
    def reason(self):
        return "; ".join(self.reasons)

    def __str__(self):
        return f"{self.path}: {self.kind}: {'; '.join(self.reasons)}"


class ProcessorError(SanitizerError):
    """Raised when a declared cleaning callback cannot be completed."""

    def __init__(
        self,
        message,
        *,
        processor=None,
        element=None,
        path=None,
        cause=None,
    ):
        super().__init__(message)
        self.processor = processor
        self.processor_name = (
            processor
            if isinstance(processor, str)
            else _callback_name(processor)
            if processor is not None
            else None
        )
        self.element = element
        self.node = element
        self.path = path
        self.failed_path = path
        self.failed_element = element
        self.cause = cause


class ProcessorScopeError(ProcessorError, ValueError):
    """Raised when a callback touched nodes outside its declared contract."""

    def __init__(self, processor, violations, *, phase="preprocess"):
        violations = tuple(violations)
        spec = None if isinstance(processor, str) else processor
        name = processor if isinstance(processor, str) else processor.name
        details = "; ".join(str(violation) for violation in violations)
        super().__init__(
            f"Processor {name!r} failed its transactional {phase} contract: {details}",
            processor=name,
            element=violations[0].node if violations else None,
            path=violations[0].path if violations else None,
        )
        self.name = name
        self.processor_spec = spec
        self.scope = getattr(spec, "scope", None)
        self.mutations = getattr(spec, "mutations", None)
        self.violations = violations
        self.phase = phase
        self.failed_paths = tuple(violation.path for violation in violations)
        self.failed_nodes = tuple(violation.node for violation in violations)
        self.mutation_kinds = tuple(violation.kind for violation in violations)
        self.reasons = tuple(
            reason for violation in violations for reason in violation.reasons
        )


ScopeError = ProcessorScopeError
ScopeViolation = ProcessorScopeError
ScopeViolationError = ProcessorScopeError
ProcessorMutationError = ProcessorScopeError
CallbackScopeError = ProcessorScopeError
NodeScopeError = ProcessorScopeError
OutOfScopeError = ProcessorScopeError
UndeclaredMutationError = ProcessorScopeError
MutationError = ProcessorError
TransactionError = ProcessorError
ProcessingError = ProcessorError
CallbackError = ProcessorError


def _capture_states(root):
    states = {}
    stack = [(root, None, None)]
    while stack:
        element, parent, index = stack.pop()
        children = tuple(element)
        states[element] = _NodeState(
            tag=element.tag,
            attrib=dict(element.attrib),
            text=element.text,
            tail=element.tail,
            parent=parent,
            children=children,
            index=index,
        )
        for child_index in range(len(children) - 1, -1, -1):
            stack.append((children[child_index], element, child_index))
    return states


def _restore_states(root, states):
    for element, state in states.items():
        try:
            element.attrib.clear()
            element.attrib.update(state.attrib)
            element.text = state.text
            element.tail = state.tail
            if isinstance(state.tag, str):
                element.tag = state.tag
        except (AttributeError, TypeError, ValueError):
            pass

    for element in states:
        for child in list(element):
            element.remove(child)

    for element, state in states.items():
        for child in state.children:
            element.append(child)


def _node_path(element, states=None, base=None):
    parts = []
    current = element
    while current is not None:
        state = states.get(current) if states else None
        tag = _tag_name(state.tag if state is not None else current.tag)
        parent = state.parent if state is not None else current.getparent()
        if parent is None or current is base:
            parts.append(tag)
        else:
            if state is not None and state.index is not None:
                index = state.index + 1
            else:
                siblings = list(parent)
                index = siblings.index(current) + 1 if current in siblings else 1
            parts.append(f"{tag}[{index}]")
        if current is base:
            break
        current = parent
    return "/" + "/".join(reversed(parts))


def _mark_replacements(changes, before, after):
    removed = {}
    for change in changes:
        if change.kind == "remove" and change.old_parent is not None:
            state = before[change.node]
            removed[(change.old_parent, state.index)] = change

    for change in changes:
        if change.kind == "add" and change.new_parent is not None:
            state = after[change.node]
            replacement = removed.get((change.new_parent, state.index))
            if replacement is not None:
                change.replacement_of = replacement.node
                replacement.replacement_of = change.node


def _diff_states(before, after):
    changes = []

    for element, old in before.items():
        new = after.get(element)
        if new is None:
            if old.parent is None or old.parent in after:
                changes.append(_Change("remove", element, old_parent=old.parent))
            continue

        if _tag_name(old.tag) != _tag_name(new.tag):
            changes.append(_Change("tag", element))
        if old.attrib != new.attrib:
            changes.append(_Change("attributes", element))
        if old.text != new.text:
            changes.append(_Change("text", element))
        if old.tail != new.tail:
            changes.append(_Change("tail", element))
        if old.parent is not new.parent:
            changes.append(
                _Change(
                    "move",
                    element,
                    old_parent=old.parent,
                    new_parent=new.parent,
                )
            )
        if tuple(old.children) != tuple(new.children):
            changes.append(_Change("children", element))

    for element, new in after.items():
        if element not in before and (new.parent is None or new.parent in before):
            changes.append(_Change("add", element, new_parent=new.parent))

    _mark_replacements(changes, before, after)
    return changes


def _capability_allows(mutations, kind):
    if mutations is None:
        return True
    if not mutations:
        return False
    for mutation in mutations:
        if mutation in {"all", "*"}:
            return True
        implied = _CAPABILITY_IMPLIES.get(mutation)
        if implied is not None and kind in implied:
            return True
        if mutation == kind:
            return True
    return False


def _changed_direct_children(old, new):
    old_children = tuple(old.children)
    new_children = tuple(new.children)
    changed = set(old_children) ^ set(new_children)
    for child in set(old_children) & set(new_children):
        if old_children.index(child) != new_children.index(child):
            changed.add(child)
    return changed


def _scope_change_allowed(  # noqa: C901
    change,
    scope,
    before,
    after,
    roots_before,
    roots_after,
    replacements=(),
):
    if scope is None:
        return True

    def old_scope(element):
        return scope.contains(element, before, roots_before)

    def new_scope(element):
        return scope.contains(element, after, roots_after)

    if change.kind in {"text", "tail", "attributes", "tag"}:
        return old_scope(change.node) or new_scope(change.node)

    if change.kind == "remove":
        return old_scope(change.node) or change.replacement_of is not None

    if change.kind == "add":
        if change.replacement_of is not None and old_scope(change.replacement_of):
            return True
        return new_scope(change.node) or new_scope(change.new_parent)

    if change.kind == "move":
        node = change.node
        neighboring_state = before.get(node)
        old_parent = (
            neighboring_state.parent
            if neighboring_state is not None
            else change.old_parent
        )
        new_parent = change.new_parent
        if new_parent is not None and new_scope(new_parent):
            return True
        return (
            new_parent is not None
            and old_parent is not None
            and old_parent not in after
            and old_scope(old_parent)
            and neighboring_state is not None
            and before[old_parent].parent is new_parent
        )

    if change.kind == "children":
        parent = change.node
        if old_scope(parent) or new_scope(parent):
            return True

        old = before.get(parent)
        new = after.get(parent)
        if old is None or new is None:
            return False
        if _tag_name(old.tag) != _tag_name(new.tag) or old.attrib != new.attrib:
            return False

        changed = _changed_direct_children(old, new)
        if not changed:
            return False
        for child in changed:
            if child in replacements:
                continue
            if not (old_scope(child) or new_scope(child)):
                return False
        return True

    return False


def _validate_spec(spec, before, after, changes, base=None):
    if not spec.validates:
        return ()

    roots_before = spec.scope.roots(before) if spec.scope is not None else set()
    roots_after = spec.scope.roots(after) if spec.scope is not None else set()

    replacements = {
        replacement
        for change in changes
        if (replacement := change.replacement_of) is not None
    }
    for change in changes:
        if change.replacement_of is not None:
            replacements.add(change.node)

    violations = []
    for change in changes:
        reasons = []
        if not _scope_change_allowed(
            change,
            spec.scope,
            before,
            after,
            roots_before,
            roots_after,
            replacements,
        ):
            reasons.append("node is outside the declared scope")
        if not _capability_allows(spec.mutations, change.kind):
            reasons.append(
                f"mutation {change.kind!r} is not declared"
                f" (allowed: {', '.join(sorted(spec.mutations)) or 'none'})"
            )
        if reasons:
            states = after if change.node in after else before
            violations.append(
                MutationViolation(
                    kind=change.kind,
                    path=_node_path(change.node, states, base),
                    reasons=tuple(reasons),
                    node=change.node,
                )
            )
    return tuple(violations)


def _annotate_exception(exc, spec, element, states, phase, base=None):
    try:
        exc.processor_name = spec.name
        exc.processor = spec.name
        exc.element = element
        exc.path = _node_path(element, states, base)
    except (AttributeError, TypeError):
        pass
    add_note = getattr(exc, "add_note", None)
    if add_note is not None:
        add_note(
            f"while running {phase} callback {spec.name!r}"
            f" on {_node_path(element, states, base)}"
        )


def sanitize_href(href):
    """
    Verify that a given href is benign and allowed.

    This is a stupid check, which probably should be much more elaborate
    to be safe.
    """
    if href.startswith(("/", "mailto:", "http:", "https:", "#", "tel:")):
        return href
    return "#"


typographic_whitespace_names = [
    "NO-BREAK SPACE",
    "EN QUAD",
    "EM QUAD",
    "EN SPACE",
    "EM SPACE",
    "THREE-PER-EM SPACE",
    "FOUR-PER-EM SPACE",
    "SIX-PER-EM SPACE",
    "FIGURE SPACE",
    "PUNCTUATION SPACE",
    "THIN SPACE",
    "HAIR SPACE",
    "NARROW NO-BREAK SPACE",
    "MEDIUM MATHEMATICAL SPACE",
    "IDEOGRAPHIC SPACE",
]

typographic_whitespace = "".join(
    {unicodedata.lookup(n) for n in typographic_whitespace_names}
)


def bold_span_to_strong(element):
    if element.tag == "span" and "bold" in element.get("style", ""):
        element.tag = "strong"
    return element


def italic_span_to_em(element):
    if element.tag == "span" and "italic" in element.get("style", ""):
        element.tag = "em"
    return element


def tag_replacer(from_, to_):
    def replacer(element):
        if element.tag == from_:
            element.tag = to_
        return element

    return replacer


def target_blank_noopener(element):
    if (
        element.tag == "a"
        and element.attrib.get("target") == "_blank"
        and "noopener" not in element.attrib.get("rel", "")
    ):
        element.attrib["rel"] = " ".join(
            part for part in (element.attrib.get("rel", ""), "noopener") if part
        )
    return element


def anchor_id_to_name(element):
    if (
        element.tag == "a"
        and element.attrib.get("id")
        and not element.attrib.get("name")
    ):
        element.attrib["name"] = element.attrib["id"]
    return element


def filter_control_characters(text):
    """Filter out control characters that lxml cannot handle."""
    if not text:
        return text
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)


def normalize_whitespace_in_text_or_tail(
    element,
    *,
    whitespace_re=None,
    keep_typographic_whitespace=False,
    normalize_text=True,
    normalize_tail=True,
):
    # Always filter control characters regardless of whitespace settings
    if element.text:
        element.text = filter_control_characters(element.text)
    if element.tail:
        element.tail = filter_control_characters(element.tail)

    if keep_typographic_whitespace:
        return element

    if whitespace_re is None:
        whitespace_re = re.compile(r"\s+")
    if element.text and normalize_text:
        while True:
            text = whitespace_re.sub(" ", element.text)
            if element.text == text:
                break
            element.text = text

    if element.tail and normalize_tail:
        while True:
            text = whitespace_re.sub(" ", element.tail)
            if element.tail == text:
                break
            element.tail = text

    return element


DEFAULT_SETTINGS = {
    "tags": {
        "a",
        "h1",
        "h2",
        "h3",
        "strong",
        "em",
        "p",
        "ul",
        "ol",
        "li",
        "br",
        "sub",
        "sup",
        "hr",
    },
    "attributes": {"a": ("href", "name", "target", "title", "rel")},
    "empty": {"hr", "a", "br"},
    "separate": {"a", "p", "li"},
    "whitespace": {"br"},
    "preserve_whitespace": {"pre"},
    "keep_typographic_whitespace": False,
    "drop_disallowed_contents": False,
    "add_nofollow": False,
    "autolink": False,
    "embedded_hosts": set(),
    "sanitize_href": sanitize_href,
    "element_preprocessors": [
        # convert span elements into em/strong if a matching style rule
        # has been found. strong has precedence, strong & em at the same
        # time is not supported
        bold_span_to_strong,
        italic_span_to_em,
        tag_replacer("b", "strong"),
        tag_replacer("i", "em"),
        tag_replacer("form", "p"),
        target_blank_noopener,
        anchor_id_to_name,
    ],
    "element_postprocessors": [],
    "document_preprocessors": [],
    "document_postprocessors": [],
}


def coerce_to_set(value):
    if isinstance(value, set):
        return value
    elif isinstance(value, tuple | list):
        return set(value)
    raise TypeError(f"Expected a set but got value {value!r} of type {type(value)}")


class Sanitizer:
    def __init__(self, settings=None):
        settings = dict(settings or {})

        # Friendly aliases. The explicit names always win.
        if "preprocessors" in settings and "element_preprocessors" not in settings:
            settings["element_preprocessors"] = settings.pop("preprocessors")
        if "postprocessors" in settings and "element_postprocessors" not in settings:
            settings["element_postprocessors"] = settings.pop("postprocessors")
        if "callbacks" in settings and "processors" not in settings:
            settings["processors"] = settings.pop("callbacks")
        if "processors" in settings:
            element_callbacks = list(
                settings.get(
                    "element_preprocessors",
                    DEFAULT_SETTINGS["element_preprocessors"],
                )
            )
            document_callbacks = list(
                settings.get(
                    "document_preprocessors",
                    DEFAULT_SETTINGS["document_preprocessors"],
                )
            )
            for processor in settings.pop("processors"):
                normalized = _normalize_processor(processor)
                if normalized.document or _looks_like_document_callback(
                    normalized.callback
                ):
                    document_callbacks.append(processor)
                else:
                    element_callbacks.append(processor)
            settings["element_preprocessors"] = element_callbacks
            settings["document_preprocessors"] = document_callbacks

        self.__dict__.update(DEFAULT_SETTINGS)
        self.__dict__.update(settings)

        # Allow iterables of any kind, not just sets.
        self.tags = coerce_to_set(self.tags)
        self.empty = coerce_to_set(self.empty)
        self.separate = coerce_to_set(self.separate)
        self.whitespace = coerce_to_set(self.whitespace)
        self.embedded_hosts = coerce_to_set(self.embedded_hosts)
        # Preserving whitespace inside tags which are removed later would
        # leak unnormalized whitespace into the output.
        self.preserve_whitespace = coerce_to_set(self.preserve_whitespace) & self.tags
        self.attributes = {
            tag: coerce_to_set(attributes)
            for tag, attributes in self.attributes.items()
        }

        if self.keep_typographic_whitespace:
            re_whitespace = r"[^\S%s]" % typographic_whitespace
        else:
            re_whitespace = r"\s"

        self.only_whitespace_re = re.compile(rf"^{re_whitespace}*$")
        self.whitespace_re = re.compile(rf"{re_whitespace}+")

        # Validate the settings.
        if not self.tags:
            raise TypeError(
                "Empty list of allowed tags is not supported by the underlying"
                " lxml cleaner. If you really do not want to pass any tags"
                " pass a made-up tag name which will never exist in your"
                " document."
            )
        if not self.tags.issuperset(self.empty):
            raise TypeError(
                f'Tags in "empty", but not allowed: {self.empty - self.tags!r}'
            )
        if not self.tags.issuperset(self.separate):
            raise TypeError(
                f'Tags in "separate", but not allowed: {self.separate - self.tags!r}'
            )
        if not self.tags.issuperset(self.attributes.keys()):
            raise TypeError(
                f'Tags in "attributes", but not allowed: {set(self.attributes.keys()) - self.tags!r}'
            )

        anchor_attributes = self.attributes.get("a", ())
        if "target" in anchor_attributes and "rel" not in anchor_attributes:
            raise TypeError(
                'Always allow "rel" when allowing "target" as anchor attribute'
            )

        self.element_preprocessors = list(self.element_preprocessors)
        self.element_postprocessors = list(self.element_postprocessors)
        self.document_preprocessors = list(self.document_preprocessors)
        self.document_postprocessors = list(self.document_postprocessors)

        # Normalize callbacks once during construction so that invalid scope or
        # mutation declarations are reported as configuration errors. They are
        # normalized again in sanitize() so that changing these lists after
        # construction keeps working like it did for old-style callbacks.
        self._element_preprocessors = [
            _normalize_processor(processor) for processor in self.element_preprocessors
        ]
        self._element_postprocessors = [
            _normalize_processor(processor) for processor in self.element_postprocessors
        ]
        self._document_preprocessors = [
            _normalize_processor(processor) for processor in self.document_preprocessors
        ]
        self._document_postprocessors = [
            _normalize_processor(processor)
            for processor in self.document_postprocessors
        ]
        self._transactional_callbacks = any(
            not spec.legacy
            for spec in (
                self._element_preprocessors
                + self._element_postprocessors
                + self._document_preprocessors
                + self._document_postprocessors
            )
        )

    @staticmethod
    def is_mergeable(e1, e2):
        """
        Decide if the adjacent elements of the same type e1 and e2 can be
        merged. This can be overriden to honouring distinct classes etc.
        """
        return True

    def normalize_whitespace(self, element):
        inside = any(e.tag in self.preserve_whitespace for e in element.iterancestors())
        return normalize_whitespace_in_text_or_tail(
            element,
            whitespace_re=self.whitespace_re,
            keep_typographic_whitespace=self.keep_typographic_whitespace,
            normalize_text=not inside and element.tag not in self.preserve_whitespace,
            normalize_tail=not inside,
        )

    def _apply_processor_chain(self, specs, element, root, phase, rollback_states=None):
        if not specs:
            return element

        # The overwhelmingly common case: only old-style callbacks. Keep the
        # exact old behaviour (and pay no snapshot/diff cost).
        if all(spec.legacy for spec in specs):
            for spec in specs:
                element = spec.callback(element)
            return element

        tree_root = root.getroottree().getroot()
        if rollback_states is None:
            rollback_states = _capture_states(tree_root)

        for spec in specs:
            if spec.document:
                continue
            if spec.scope is not None and not spec.scope.applies_to(element):
                continue

            before = _capture_states(tree_root) if spec.validates else None
            context = ProcessingContext(
                root=root,
                element=element,
                processor=spec.name,
                phase=phase,
                scope=spec.scope,
                mutations=spec.mutations,
            )

            try:
                if spec.legacy:
                    result = spec.callback(element)
                else:
                    result = _call_callback(
                        spec.callback,
                        element,
                        context,
                        spec.accepts_context,
                    )
            except BaseException as exc:
                _restore_states(tree_root, rollback_states)
                _annotate_exception(
                    exc,
                    spec,
                    element,
                    before if before is not None else _capture_states(tree_root),
                    phase,
                    base=root,
                )
                if spec.legacy:
                    raise
                path = _node_path(element, before or _capture_states(tree_root), root)
                raise ProcessorError(
                    f"Processor {spec.name!r} failed during {phase} at {path}:"
                    f" {type(exc).__name__}: {exc}",
                    processor=spec.name,
                    element=element,
                    path=path,
                    cause=exc,
                ) from exc

            if result is None:
                result = element

            if before is not None:
                after = _capture_states(tree_root)
                violations = _validate_spec(
                    spec,
                    before,
                    after,
                    _diff_states(before, after),
                    base=root,
                )
                if violations:
                    _restore_states(tree_root, rollback_states)
                    raise ProcessorScopeError(spec, violations, phase=phase)

            element = result

        return element

    def _apply_document_chain(self, specs, root, phase, rollback_states=None):
        if not specs:
            return
        tree_root = root.getroottree().getroot()
        if rollback_states is None:
            rollback_states = _capture_states(tree_root)

        for spec in specs:
            before = _capture_states(tree_root) if spec.validates else None
            context = ProcessingContext(
                root=root,
                element=root,
                processor=spec.name,
                phase=phase,
                scope=spec.scope,
                mutations=spec.mutations,
            )
            try:
                if spec.legacy:
                    result = spec.callback(root)
                else:
                    result = _call_callback(
                        spec.callback,
                        root,
                        context,
                        spec.accepts_context,
                    )
            except BaseException as exc:
                _restore_states(tree_root, rollback_states)
                _annotate_exception(
                    exc,
                    spec,
                    root,
                    before if before is not None else _capture_states(tree_root),
                    phase,
                    base=root,
                )
                if spec.legacy:
                    raise
                raise ProcessorError(
                    f"Processor {spec.name!r} failed during {phase}:"
                    f" {type(exc).__name__}: {exc}",
                    processor=spec.name,
                    element=root,
                    path=_node_path(root, before or _capture_states(tree_root), root),
                    cause=exc,
                ) from exc

            if result is not None and result is not root:
                _restore_states(tree_root, rollback_states)
                raise ProcessorError(
                    f"Processor {spec.name!r} returned a different document"
                    f" during {phase}; document callbacks must mutate the"
                    " supplied snapshot in place",
                    processor=spec.name,
                    element=root,
                    path=_node_path(root, before or _capture_states(tree_root), root),
                )

            if before is not None:
                after = _capture_states(tree_root)
                violations = _validate_spec(
                    spec,
                    before,
                    after,
                    _diff_states(before, after),
                    base=root,
                )
                if violations:
                    _restore_states(tree_root, rollback_states)
                    raise ProcessorScopeError(spec, violations, phase=phase)

    def sanitize(self, html):  # noqa: C901 -- I know.
        """
        Clean HTML code from ugly copy-pasted CSS and empty elements

        Removes everything not explicitly allowed in ``self.allowed_tags``.

        Requires ``lxml`` and, for especially broken HTML, ``beautifulsoup4``.
        """

        # normalize unicode
        if self.keep_typographic_whitespace:
            html = unicodedata.normalize("NFC", html)
        else:
            html = unicodedata.normalize("NFKC", html)

        html = "<div>%s</div>" % html
        try:
            doc = lxml.html.fromstring(html)
            lxml.html.tostring(doc, encoding="utf-8")
        except Exception:
            from lxml.html import soupparser  # noqa: PLC0415

            doc = soupparser.fromstring(html)

        lxml.html.clean.Cleaner(
            remove_unknown_tags=False,
            # Remove style *tags* if not explicitly allowed
            style="style" not in self.tags,
            # Do not strip out style attributes; we still need the style
            # information to convert spans into em/strong tags
            safe_attrs_only=False,
            inline_style=False,
            # Do not strip all form tags; we will filter them below
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)

        doc = self.normalize_whitespace(doc)

        element_preprocessors = [
            _normalize_processor(processor) for processor in self.element_preprocessors
        ]
        element_postprocessors = [
            _normalize_processor(processor) for processor in self.element_postprocessors
        ]
        document_preprocessors = [
            _normalize_processor(processor) for processor in self.document_preprocessors
        ]
        document_postprocessors = [
            _normalize_processor(processor)
            for processor in self.document_postprocessors
        ]
        transactional = any(
            not spec.legacy
            for spec in (
                element_preprocessors
                + element_postprocessors
                + document_preprocessors
                + document_postprocessors
            )
        )
        rollback_states = (
            _capture_states(doc.getroottree().getroot()) if transactional else None
        )
        self._apply_document_chain(
            [spec for spec in element_preprocessors if spec.document]
            + document_preprocessors,
            doc,
            "document preprocess",
            rollback_states,
        )

        # walk the tree recursively, because we want to be able to remove
        # previously emptied elements completely
        backlog = deque(doc.iterdescendants())

        while True:
            try:
                element = backlog.pop()
            except IndexError:
                break

            element = self._apply_processor_chain(
                element_preprocessors,
                element,
                doc,
                "preprocess",
                rollback_states,
            )

            if self.drop_disallowed_contents and element.tag not in self.tags:
                element.drop_tree()
                continue

            element = self.normalize_whitespace(element)

            # remove empty tags if they are not explicitly allowed
            if (
                (not element.text or self.only_whitespace_re.match(element.text))
                and element.tag not in self.empty
                and not len(element)
            ):
                element.drop_tag()
                continue

            # remove tags which only contain whitespace and/or <br>s
            if (
                element.tag not in self.empty
                and self.only_whitespace_re.match(element.text or "")
                and {e.tag for e in element} <= self.whitespace
                and all(self.only_whitespace_re.match(e.tail or "") for e in element)
            ):
                element.drop_tree()
                continue

            if element.tag in {"li", "p"}:
                # remove p-in-li and p-in-p tags
                for p in element.findall("p"):
                    if getattr(p, "text", None):
                        p.text = " " + p.text + " "
                    p.drop_tag()

                # remove list markers, maybe copy-pasted from word or whatever
                if element.text:
                    element.text = filter_control_characters(
                        re.sub(r"^\s*(-|\*|&#183;)\s+", "", element.text)
                    )

            elif element.tag in self.whitespace:
                # Drop the next element if
                # 1. it is a <br> too and 2. there is no content in-between
                nx = element.getnext()
                if (
                    nx is not None
                    and nx.tag == element.tag
                    and (
                        not element.tail or self.only_whitespace_re.match(element.tail)
                    )
                ):
                    nx.drop_tag()

            if not element.text:
                # No text before first child and first child is a <br>: Drop it
                first = next(iter(element), None)
                if first is not None and first.tag in self.whitespace:
                    first.drop_tag()
                    # Maybe we have more than one <br>
                    backlog.append(element)
                    continue

            if element.tag in (self.tags - self.separate):
                # Check whether we should merge adjacent elements of the same
                # tag type
                nx = element.getnext()
                if (
                    self.only_whitespace_re.match(element.tail or "")
                    and nx is not None
                    and nx.tag == element.tag
                    and self.is_mergeable(element, nx)
                ):
                    # Yes, we should. Tail is empty, that is, no text between
                    # tags of a mergeable type.
                    if nx.text:
                        if len(element):
                            list(element)[-1].tail = "{}{}".format(
                                list(element)[-1].tail or "",
                                nx.text,
                            )
                        else:
                            element.text = "{}{}{}".format(
                                element.text or "", element.tail or "", nx.text
                            )

                    for child in nx:
                        element.append(child)

                    # tail is merged with previous element.
                    element.tail = nx.tail
                    nx.getparent().remove(nx)

                    # Process element again
                    backlog.append(element)
                    continue

            element = self._apply_processor_chain(
                element_postprocessors,
                element,
                doc,
                "postprocess",
                rollback_states,
            )

            # remove all attributes which are not explicitly allowed
            allowed = self.attributes.get(element.tag, [])
            for key in element.keys():  # noqa: SIM118 (do not remove .keys())
                if key not in allowed:
                    del element.attrib[key]
                elif not self.keep_typographic_whitespace:
                    element.set(key, self.whitespace_re.sub(" ", element.get(key)))

            # Clean hrefs so that they are benign
            href = element.get("href")
            if href is not None:
                element.set("href", self.sanitize_href(href))

            element = self.normalize_whitespace(element)

        self._apply_document_chain(
            [spec for spec in element_postprocessors if spec.document]
            + document_postprocessors,
            doc,
            "document postprocess",
            rollback_states,
        )

        if self.autolink is True:
            lxml.html.clean.autolink(doc)
        elif isinstance(self.autolink, dict):
            lxml.html.clean.autolink(doc, **self.autolink)

        # Run cleaner again, but this time with even more strict settings
        lxml.html.clean.Cleaner(
            allow_tags=self.tags,
            remove_unknown_tags=False,
            safe_attrs_only=False,  # Our attributes allowlist is sufficient.
            add_nofollow=self.add_nofollow,
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)

        html = lxml.html.tostring(doc, encoding="unicode")

        # add a space before the closing slash in empty tags
        html = re.sub(r"<([^/>]+)/>", r"<\1 />", html)

        # remove wrapping tag needed by XML parser
        html = re.sub(r"^<div>|</div>$", "", html)

        return html
