"""Strict, layer-aware handling of COSE Critical header parameters.

The regular verification helpers in pycose only check the cryptographic
signature.  A COSE ``crit`` declaration says that the receiver must understand
the listed header parameters before accepting a message.  This module adds an
opt-in verification path that keeps those two decisions separate:

* the signature result is reported as ``signature_valid``;
* every Critical declaration is checked in the protected header bucket of the
  layer that declared it;
* the caller has to register a handler for every extension it understands.

For ``COSE_Sign`` the message header and each signer header are evaluated
independently.  An extension handled by the message layer does not count as
handling evidence for a signer (and vice versa).
"""

import inspect
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from pycose.headers import CoseHeaderAttribute, Critical, KID


# Snapshot the attributes pycose ships with.  Attributes added later by an
# application are explicit extensions and still require a local handler.
_BUILTIN_HEADER_ALIASES = set(CoseHeaderAttribute.get_registered_classes().keys())
for _builtin_attr in set(CoseHeaderAttribute.get_registered_classes().values()):
    _BUILTIN_HEADER_ALIASES.add(_builtin_attr)
    _BUILTIN_HEADER_ALIASES.add(_builtin_attr.identifier)
    _BUILTIN_HEADER_ALIASES.add(_builtin_attr.fullname)
    _BUILTIN_HEADER_ALIASES.add(_builtin_attr.fullname.upper())


class _Unsupported(object):
    def __repr__(self):
        return "UNSUPPORTED"


#: Return this from a Critical extension handler when the extension is known by
#: name but the current receiver cannot interpret it.
UNSUPPORTED = _Unsupported()


_MISSING = object()


def _is_attribute_class(value: Any) -> bool:
    return isinstance(value, type) and issubclass(value, CoseHeaderAttribute)


def _label_aliases(label: Any) -> List[Any]:
    """Return the interchangeable identifier/name spellings for a header label."""

    aliases = []

    def add(alias: Any) -> None:
        try:
            hash(alias)
        except TypeError:
            return
        if alias not in aliases:
            aliases.append(alias)

    if _is_attribute_class(label):
        add(label)
        add(label.identifier)
        add(label.fullname)
        add(label.fullname.upper())
    elif isinstance(label, int):
        add(label)
        registered = CoseHeaderAttribute.get_registered_classes()
        attr = registered.get(label)
        if _is_attribute_class(attr):
            add(attr)
            add(attr.fullname)
            add(attr.fullname.upper())
    elif isinstance(label, str):
        add(label)
        registered = CoseHeaderAttribute.get_registered_classes()
        attr = registered.get(label.upper())
        if _is_attribute_class(attr):
            add(attr)
            add(attr.identifier)
    else:
        add(label)
        identifier = getattr(label, "identifier", _MISSING)
        fullname = getattr(label, "fullname", _MISSING)
        if identifier is not _MISSING:
            add(identifier)
        if fullname is not _MISSING:
            add(fullname)
            if isinstance(fullname, str):
                add(fullname.upper())

    return aliases


def _is_library_attribute(label: Any) -> bool:
    """True when the header label is one of the standard COSE attributes."""

    for alias in _label_aliases(label):
        if alias in _BUILTIN_HEADER_ALIASES:
            return True
    return False


def _find_field(header: Optional[dict], label: Any):
    """Find a field in one header bucket only, never falling back to another."""

    if not header:
        return False, None

    wanted = _label_aliases(label)
    for key, value in header.items():
        key_aliases = _label_aliases(key)
        for alias in key_aliases:
            if alias in wanted:
                return True, value

    return False, None


def _as_registry(value: Any) -> 'CriticalExtensionRegistry':
    """Normalize the caller-facing handler inputs to a registry."""

    if value is None:
        return CriticalExtensionRegistry()
    if isinstance(value, CriticalExtensionRegistry):
        return value
    if isinstance(value, dict):
        return CriticalExtensionRegistry(value)
    if isinstance(value, (str, int)):
        return CriticalExtensionRegistry({value: None})
    if isinstance(value, (list, tuple, set, frozenset)):
        return CriticalExtensionRegistry({label: None for label in value})
    if hasattr(value, "handlers"):
        return CriticalExtensionRegistry(value.handlers)
    if callable(value):
        # A bare callable only makes sense as a handler for an explicit label;
        # keeping it as an unsupported input is safer than guessing a label.
        raise TypeError("Critical extension handlers must be a mapping or a registry")
    raise TypeError("Unsupported Critical extension registration: {!r}".format(value))


class CriticalExtensionRegistry(object):
    """A set of COSE Critical header labels and their local handlers.

    ``handlers`` maps a header label (integer, string, or header attribute class)
    to either a callable or ``None``.  ``None`` means "this receiver understands
    the field but has no extra semantic check for it".

    A handler can accept just the field value, or ``(value, context)``.  The
    context is a :class:`CriticalCheckContext` and carries the layer, signer
    index, protected header, and an optional caller supplied ``now`` value.

    Returning ``False`` (or any falsy value) rejects the layer.  Returning
    ``UNSUPPORTED`` or raising ``NotImplementedError`` marks the extension as
    explicitly unsupported.  Raising any other exception marks it as failed.
    ``None`` is treated as success, which makes assert/raise style validators
    convenient.
    """

    def __init__(self, handlers: Optional[Dict[Any, Any]] = None):
        self._handlers: Dict[Any, Any] = {}
        if handlers:
            self.register_many(handlers)

    def register(self, label: Any, handler: Optional[Callable] = None) -> 'CriticalExtensionRegistry':
        """Register one extension label.

        Registering with ``handler=None`` means the label is understood without
        an additional semantic check.
        """

        for alias in _label_aliases(label):
            self._handlers[alias] = handler
        return self

    register_extension = register

    def register_many(self, handlers: Dict[Any, Any]) -> 'CriticalExtensionRegistry':
        for label, handler in handlers.items():
            self.register(label, handler)
        return self

    def update(self, handlers: Dict[Any, Any]) -> 'CriticalExtensionRegistry':
        """Convenience spelling for adding more handlers."""
        return self.register_many(handlers)

    @classmethod
    def from_mapping(cls, handlers: Dict[Any, Any]) -> 'CriticalExtensionRegistry':
        return cls(handlers)

    def get(self, label: Any, default: Any = _MISSING) -> Any:
        for alias in _label_aliases(label):
            if alias in self._handlers:
                return self._handlers[alias]

        # Standard COSE header attributes are interpreted by the library
        # itself; custom extensions always need explicit registration.
        if _is_library_attribute(label):
            return None

        return default

    def supports(self, label: Any) -> bool:
        return self.get(label) is not _MISSING

    def __contains__(self, label: Any) -> bool:
        return self.supports(label)

    def __len__(self) -> int:
        return len(self._handlers)

    def __repr__(self) -> str:
        return "CriticalExtensionRegistry({!r})".format(self._handlers)


@dataclass
class CriticalCheckContext:
    """Context supplied to a Critical extension handler."""

    layer: str
    label: Any = None
    signer_index: Optional[int] = None
    message: Any = None
    signer: Any = None
    protected_header: Optional[dict] = None
    unprotected_header: Optional[dict] = None
    now: Any = None


@dataclass
class CriticalCheckResult:
    """The outcome of evaluating one Critical declaration."""

    label: Any
    status: str
    value: Any = None
    result: Any = None
    error: Optional[str] = None

    @property
    def supported(self) -> bool:
        return self.status != "unsupported"

    @property
    def unsupported(self) -> bool:
        return self.status == "unsupported"

    @property
    def understood(self) -> bool:
        return self.supported

    @property
    def accepted(self) -> bool:
        return self.status == "passed"

    @property
    def passed(self) -> bool:
        return self.accepted

    @property
    def verified(self) -> bool:
        return self.accepted

    @property
    def valid(self) -> bool:
        return self.accepted

    @property
    def ok(self) -> bool:
        return self.accepted

    @property
    def reason(self) -> Optional[str]:
        return self.error

    def __bool__(self) -> bool:
        return self.accepted


@dataclass
class LayerVerificationResult:
    """Strict verification result for one COSE header layer."""

    layer: str
    signature_valid: Optional[bool] = None
    critical_results: List[CriticalCheckResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    signer_index: Optional[int] = None
    protected_header: Optional[dict] = None
    signer: Any = None

    @property
    def critical(self) -> Dict[Any, CriticalCheckResult]:
        return {check.label: check for check in self.critical_results}

    @property
    def extensions(self) -> Dict[Any, CriticalCheckResult]:
        return self.critical

    @property
    def critical_ok(self) -> bool:
        return all(check.accepted for check in self.critical_results)

    @property
    def accepted(self) -> bool:
        return self.signature_valid is not False and not self.errors and self.critical_ok

    @property
    def valid(self) -> bool:
        return self.accepted

    @property
    def is_accepted(self) -> bool:
        return self.accepted

    @property
    def overall_accepted(self) -> bool:
        return self.accepted

    @property
    def ok(self) -> bool:
        return self.accepted

    @property
    def verified(self) -> bool:
        return self.accepted

    @property
    def signature_verified(self) -> Optional[bool]:
        return self.signature_valid

    @property
    def cryptographic_valid(self) -> Optional[bool]:
        return self.signature_valid

    @property
    def crypto_valid(self) -> Optional[bool]:
        return self.signature_valid

    @property
    def cryptographically_valid(self) -> Optional[bool]:
        return self.signature_valid

    @property
    def all_critical_accepted(self) -> bool:
        return self.critical_ok

    @property
    def unsupported(self) -> List[Any]:
        return [check.label for check in self.critical_results if check.status == "unsupported"]

    @property
    def unsupported_labels(self) -> List[Any]:
        return self.unsupported

    @property
    def failed(self) -> List[Any]:
        return [check.label for check in self.critical_results if check.status == "failed"]

    @property
    def missing(self) -> List[Any]:
        return [check.label for check in self.critical_results if check.status == "missing"]

    @property
    def kid(self) -> Any:
        if self.signer is None:
            return None
        try:
            return self.signer.get_attr(KID)
        except Exception:
            return None

    def __bool__(self) -> bool:
        return self.accepted


class StrictVerificationResult(LayerVerificationResult):
    """Strict result for a single-signature message (COSE_Sign1)."""

    @property
    def message(self) -> 'StrictVerificationResult':
        return self


@dataclass
class SignStrictVerificationResult(object):
    """Strict result for a multi-signature message (COSE_Sign).

    ``message`` contains the top-level header result, while ``signers`` contains
    one independent result per ``COSE_Signature``.  The overall result is only
    accepted when the message layer and every signer layer are accepted.
    """

    message: LayerVerificationResult
    signers: List[LayerVerificationResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return bool(self.signers) and not self.errors and self.message.accepted and \
            all(signer.accepted for signer in self.signers)

    @property
    def valid(self) -> bool:
        return self.accepted

    @property
    def is_accepted(self) -> bool:
        return self.accepted

    @property
    def overall_accepted(self) -> bool:
        return self.accepted

    @property
    def ok(self) -> bool:
        return self.accepted

    @property
    def verified(self) -> bool:
        return self.accepted

    @property
    def signature_valid(self) -> bool:
        return bool(self.signers) and all(signer.signature_valid is True for signer in self.signers)

    @property
    def all_signatures_valid(self) -> bool:
        return self.signature_valid

    @property
    def cryptographic_valid(self) -> bool:
        return self.signature_valid

    @property
    def crypto_valid(self) -> bool:
        return self.signature_valid

    @property
    def cryptographically_valid(self) -> bool:
        return self.signature_valid

    @property
    def crypto_results(self) -> List[Optional[bool]]:
        return [signer.signature_valid for signer in self.signers]

    @property
    def critical(self) -> Dict[Any, CriticalCheckResult]:
        return self.message.critical

    @property
    def message_critical(self) -> Dict[Any, CriticalCheckResult]:
        return self.message.critical

    @property
    def critical_results(self) -> List[CriticalCheckResult]:
        return self.message.critical_results

    @property
    def signer_results(self) -> List[LayerVerificationResult]:
        return self.signers

    @property
    def signature_results(self) -> List[LayerVerificationResult]:
        return self.signers

    @property
    def message_result(self) -> LayerVerificationResult:
        return self.message

    @property
    def unsupported(self) -> List[Any]:
        labels: List[Any] = []
        for layer in [self.message] + list(self.signers):
            for label in layer.unsupported:
                if label not in labels:
                    labels.append(label)
        return labels

    @property
    def unsupported_at(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self.message.unsupported:
            result["message"] = self.message.unsupported
        for index, signer in enumerate(self.signers):
            if signer.unsupported:
                result["signer:{}".format(index)] = signer.unsupported
        return result

    def __bool__(self) -> bool:
        return self.accepted


def _invoke_handler(handler: Any, value: Any, context: CriticalCheckContext) -> Any:
    if handler is None:
        return True

    target = handler

    if not callable(target):
        for name in ("verify", "check", "validate", "interpret", "handle"):
            candidate = getattr(target, name, None)
            if callable(candidate):
                target = candidate
                break
        else:
            return value == target

    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return target(value)

    parameters = list(signature.parameters.values())
    positional = [p for p in parameters
                  if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    has_varargs = any(p.kind == p.VAR_POSITIONAL for p in parameters)

    keyword_arguments = {}
    for parameter in parameters:
        if parameter.kind != parameter.KEYWORD_ONLY:
            continue
        if parameter.name in ("now", "current_time", "timestamp"):
            keyword_arguments[parameter.name] = context.now
        elif parameter.name in ("context", "ctx"):
            keyword_arguments[parameter.name] = context
        elif parameter.name == "label":
            keyword_arguments[parameter.name] = context.label

    if has_varargs or len(positional) >= 2:
        second = context
        if len(positional) >= 2 and positional[1].name in ("now", "current_time", "timestamp"):
            second = context.now
        return target(value, second, **keyword_arguments)
    if len(positional) == 1:
        return target(value, **keyword_arguments)
    return target(**keyword_arguments)


def _classify_handler_result(raw: Any) -> str:
    if raw is UNSUPPORTED:
        return "unsupported"
    if raw is None:
        return "passed"
    if isinstance(raw, tuple) and raw and isinstance(raw[0], bool):
        return "passed" if raw[0] else "failed"
    if isinstance(raw, dict):
        for name in ("accepted", "passed", "verified", "valid", "ok"):
            if isinstance(raw.get(name), bool):
                return "passed" if raw[name] else "failed"
    for name in ("accepted", "passed", "verified", "valid", "ok"):
        candidate = getattr(raw, name, _MISSING)
        if isinstance(candidate, bool):
            return "passed" if candidate else "failed"
    return "passed" if bool(raw) else "failed"


def evaluate_layer(protected_header: Optional[dict],
                   unprotected_header: Optional[dict],
                   registry: Optional[Any],
                   layer: str,
                   signer_index: Optional[int] = None,
                   message: Any = None,
                   signer: Any = None,
                   now: Any = None,
                   signature_valid: Optional[bool] = None,
                   initial_errors: Optional[Iterable[str]] = None) -> LayerVerificationResult:
    """Evaluate only the Critical declarations belonging to one header layer."""

    registry = _as_registry(registry)
    checks: List[CriticalCheckResult] = []
    errors: List[str] = list(initial_errors or [])

    if now is None:
        now = datetime.now(timezone.utc)

    context = CriticalCheckContext(
        layer=layer,
        signer_index=signer_index,
        message=message,
        signer=signer,
        protected_header=protected_header,
        unprotected_header=unprotected_header,
        now=now,
    )

    unprotected_has_crit, _ = _find_field(unprotected_header, Critical)
    if unprotected_has_crit:
        errors.append("Critical header parameter must be in the protected header")

    protected_has_crit, critical_value = _find_field(protected_header, Critical)
    critical_labels = []
    if protected_has_crit:
        if not isinstance(critical_value, list) or len(critical_value) == 0:
            errors.append("Critical header parameter must be a non-empty array")
        else:
            critical_labels = critical_value

    for label in critical_labels:
        context.label = label
        handler = registry.get(label)
        if handler is _MISSING:
            checks.append(CriticalCheckResult(
                label=label,
                status="unsupported",
                error="No handler registered for Critical header parameter {!r}".format(label),
            ))
            continue

        present, value = _find_field(protected_header, label)
        if not present:
            checks.append(CriticalCheckResult(
                label=label,
                status="missing",
                error="Critical header parameter {!r} is not in the protected header".format(label),
            ))
            continue

        duplicate, _ = _find_field(unprotected_header, label)
        if duplicate:
            errors.append(
                "Header parameter {!r} appears in both the protected and unprotected headers".format(label)
            )

        try:
            raw = _invoke_handler(handler, value, context)
            status = _classify_handler_result(raw)
            error = None
            if status == "unsupported":
                error = "Critical header parameter {!r} is explicitly unsupported".format(label)
            elif status == "failed":
                error = "Critical header parameter {!r} failed its local check".format(label)
            checks.append(CriticalCheckResult(
                label=label,
                status=status,
                value=value,
                result=raw,
                error=error,
            ))
        except NotImplementedError:
            checks.append(CriticalCheckResult(
                label=label,
                status="unsupported",
                value=value,
                error="Critical header parameter {!r} is explicitly unsupported".format(label),
            ))
        except Exception as exc:  # handler failures reject this layer only
            checks.append(CriticalCheckResult(
                label=label,
                status="failed",
                value=value,
                error="{}: {}".format(type(exc).__name__, exc),
            ))

    return LayerVerificationResult(
        layer=layer,
        signature_valid=signature_valid,
        critical_results=checks,
        errors=errors,
        signer_index=signer_index,
        protected_header=protected_header,
        signer=signer,
    )


def _pick_kwarg(kwargs: Dict[str, Any], names: Iterable[str], default: Any = None) -> Any:
    for name in names:
        if name in kwargs and kwargs[name] is not None:
            return kwargs[name]
    return default


_MESSAGE_EXTENSION_KEYS = (
    "critical_extensions", "extensions", "critical_handlers", "handlers",
    "message_extensions", "message_critical", "message_registry", "registry",
    "critical", "supported_critical", "supported_extensions", "understood_extensions",
)
_SIGNER_EXTENSION_KEYS = (
    "signer_critical_extensions", "signer_extensions", "signer_handlers",
    "signer_critical", "signer_registry", "signature_extensions",
    "signers_extensions", "per_signer_extensions",
)
_MESSAGE_HANDLER_ATTRS = (
    "critical_extensions", "critical_handlers", "critical_registry",
    "supported_critical", "message_critical_extensions",
)
_SIGNER_HANDLER_ATTRS = (
    "critical_extensions", "critical_handlers", "critical_registry",
    "supported_critical", "signer_critical_extensions",
)


def _object_input(value: Any, names: Iterable[str]) -> Any:
    for name in names:
        candidate = getattr(value, name, None)
        if candidate is not None:
            return candidate
    return None


def _merge_inputs(*inputs: Any) -> CriticalExtensionRegistry:
    registry = CriticalExtensionRegistry()
    for value in inputs:
        if value is None:
            continue
        other = _as_registry(value)
        registry.register_many(other._handlers)
    return registry


def _normalize_signer_registries(value: Any, count: int) -> List[CriticalExtensionRegistry]:
    if value is None:
        return [CriticalExtensionRegistry() for _ in range(count)]

    if isinstance(value, CriticalExtensionRegistry):
        return [value for _ in range(count)]

    if isinstance(value, dict):
        # A per-signer mapping has registries/mappings as all of its values and
        # integer keys that address signer slots.  Otherwise it is a label map
        # that applies to every signer.
        if value and all(isinstance(k, int) and isinstance(v, (dict, CriticalExtensionRegistry))
                         for k, v in value.items()):
            registries = []
            for index in range(count):
                registries.append(_as_registry(value.get(index)))
            return registries
        registry = _as_registry(value)
        return [registry for _ in range(count)]

    if isinstance(value, (list, tuple)):
        if all(v is None or isinstance(v, (dict, CriticalExtensionRegistry)) for v in value):
            registries = [_as_registry(v) for v in value[:count]]
            while len(registries) < count:
                registries.append(CriticalExtensionRegistry())
            return registries
        registry = _as_registry(value)
        return [registry for _ in range(count)]

    registry = _as_registry(value)
    return [registry for _ in range(count)]


def verify_sign1_strict(message: Any,
                        critical_extensions: Any = None,
                        detached_payload: Optional[bytes] = None,
                        now: Any = None,
                        **kwargs) -> StrictVerificationResult:
    """Strictly verify a ``Sign1Message``."""

    message_inputs = [critical_extensions]
    message_inputs.append(_pick_kwarg(kwargs, _MESSAGE_EXTENSION_KEYS))
    message_inputs.append(_object_input(message, _MESSAGE_HANDLER_ATTRS))
    # Sign1 has a single, message-level layer.  Accepting the signer spelling is
    # a convenience for callers that share option-building code with COSE_Sign.
    message_inputs.append(_pick_kwarg(kwargs, _SIGNER_EXTENSION_KEYS))
    registry = _merge_inputs(*message_inputs)

    if detached_payload is None:
        detached_payload = kwargs.get("detached_payload")
    if now is None:
        now = kwargs.get("now")

    initial_errors: List[str] = []
    try:
        signature_valid = message.verify_signature(detached_payload=detached_payload)
    except Exception as exc:
        signature_valid = False
        initial_errors.append("{}: {}".format(type(exc).__name__, exc))

    layer_result = evaluate_layer(
        message.phdr,
        message.uhdr,
        registry,
        layer="message",
        message=message,
        now=now,
        signature_valid=signature_valid,
        initial_errors=initial_errors,
    )

    return StrictVerificationResult(
        layer=layer_result.layer,
        signature_valid=layer_result.signature_valid,
        critical_results=layer_result.critical_results,
        errors=layer_result.errors,
        signer_index=layer_result.signer_index,
        protected_header=layer_result.protected_header,
        signer=layer_result.signer,
    )


def verify_sign_message_strict(message: Any,
                               critical_extensions: Any = None,
                               signer_critical_extensions: Any = None,
                               detached_payload: Optional[bytes] = None,
                               now: Any = None,
                               **kwargs) -> SignStrictVerificationResult:
    """Strictly verify a ``SignMessage``, keeping each signer independent."""

    message_registry = _merge_inputs(
        critical_extensions,
        _pick_kwarg(kwargs, _MESSAGE_EXTENSION_KEYS),
        _object_input(message, _MESSAGE_HANDLER_ATTRS),
    )
    signer_input = signer_critical_extensions
    if signer_input is None:
        signer_input = _pick_kwarg(kwargs, _SIGNER_EXTENSION_KEYS)

    if detached_payload is None:
        detached_payload = kwargs.get("detached_payload")
    if now is None:
        now = kwargs.get("now")

    message_result = evaluate_layer(
        message.phdr,
        message.uhdr,
        message_registry,
        layer="message",
        message=message,
        now=now,
        signature_valid=None,
    )

    signer_registries = _normalize_signer_registries(signer_input, len(message.signers))
    signer_results: List[LayerVerificationResult] = []

    for index, signer in enumerate(message.signers):
        initial_errors: List[str] = []
        try:
            signature_valid = signer.verify_signature(detached_payload=detached_payload)
        except Exception as exc:
            signature_valid = False
            initial_errors.append("{}: {}".format(type(exc).__name__, exc))

        signer_registry = _merge_inputs(
            signer_registries[index],
            _object_input(signer, _SIGNER_HANDLER_ATTRS),
        )

        signer_results.append(evaluate_layer(
            signer.phdr,
            signer.uhdr,
            signer_registry,
            layer="signer",
            signer_index=index,
            message=message,
            signer=signer,
            now=now,
            signature_valid=signature_valid,
            initial_errors=initial_errors,
        ))

    errors: List[str] = []
    if not message.signers:
        errors.append("COSE_Sign message contains no signers")

    return SignStrictVerificationResult(
        message=message_result,
        signers=signer_results,
        errors=errors,
    )


def verify_signer_strict(signer: Any,
                         critical_extensions: Any = None,
                         detached_payload: Optional[bytes] = None,
                         now: Any = None,
                         **kwargs) -> LayerVerificationResult:
    """Strictly verify one ``CoseSignature`` in isolation."""

    registry = _merge_inputs(
        critical_extensions,
        _pick_kwarg(kwargs, _SIGNER_EXTENSION_KEYS),
        _pick_kwarg(kwargs, _MESSAGE_EXTENSION_KEYS),
        _object_input(signer, _SIGNER_HANDLER_ATTRS),
    )

    if detached_payload is None:
        detached_payload = kwargs.get("detached_payload")
    if now is None:
        now = kwargs.get("now")

    initial_errors: List[str] = []
    try:
        signature_valid = signer.verify_signature(detached_payload=detached_payload)
    except Exception as exc:
        signature_valid = False
        initial_errors.append("{}: {}".format(type(exc).__name__, exc))

    return evaluate_layer(
        signer.phdr,
        signer.uhdr,
        registry,
        layer="signer",
        message=signer._parent,
        signer=signer,
        now=now,
        signature_valid=signature_valid,
        initial_errors=initial_errors,
    )


def verify_strict(message: Any, *args, **kwargs):
    """Dispatch strict verification based on the COSE object shape.

    ``Sign1Message`` and ``CoseSignature`` have a single layer; ``SignMessage``
    has a message layer plus one layer per signer.
    """

    if hasattr(message, "signers"):
        return verify_sign_message_strict(message, *args, **kwargs)
    if hasattr(message, "_parent"):
        return verify_signer_strict(message, *args, **kwargs)
    return verify_sign1_strict(message, *args, **kwargs)


# Friendly aliases for callers that prefer the longer result name.
CriticalVerificationResult = StrictVerificationResult
SignerVerificationResult = LayerVerificationResult


__all__ = [
    "UNSUPPORTED",
    "CriticalCheckContext",
    "CriticalCheckResult",
    "CriticalExtensionRegistry",
    "CriticalVerificationResult",
    "LayerVerificationResult",
    "SignStrictVerificationResult",
    "SignerVerificationResult",
    "StrictVerificationResult",
    "evaluate_layer",
    "verify_sign1_strict",
    "verify_sign_message_strict",
    "verify_signer_strict",
    "verify_strict",
]
