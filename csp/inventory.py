from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from html.parser import HTMLParser
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

from django.conf import settings

from csp.constants import (
    HEADER,
    HEADER_REPORT_ONLY,
    NONCE,
    NONE,
    SELF,
    STRICT_DYNAMIC,
    UNSAFE_INLINE,
)

Status = Literal["allowed", "blocked", "indeterminate"]


# The CSP fallback graph. An explicitly present directive is never skipped, even
# when its value is empty: an empty directive means "block everything".
DIRECTIVE_FALLBACKS: dict[str, tuple[str, ...]] = {
    "child-src": ("child-src", "default-src"),
    "connect-src": ("connect-src", "default-src"),
    "default-src": ("default-src",),
    "font-src": ("font-src", "default-src"),
    "frame-src": ("frame-src", "child-src", "default-src"),
    "img-src": ("img-src", "default-src"),
    "manifest-src": ("manifest-src", "default-src"),
    "media-src": ("media-src", "default-src"),
    "object-src": ("object-src", "default-src"),
    "prefetch-src": ("prefetch-src", "default-src"),
    "script-src": ("script-src", "default-src"),
    "script-src-attr": ("script-src-attr", "script-src", "default-src"),
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "style-src": ("style-src", "default-src"),
    "style-src-attr": ("style-src-attr", "style-src", "default-src"),
    "style-src-elem": ("style-src-elem", "style-src", "default-src"),
    "worker-src": ("worker-src", "child-src", "script-src", "default-src"),
    "base-uri": ("base-uri",),
    "form-action": ("form-action",),
    "frame-ancestors": ("frame-ancestors",),
    "navigate-to": ("navigate-to",),
    "report-to": ("report-to",),
    "report-uri": ("report-uri",),
    "sandbox": ("sandbox",),
    "require-sri-for": ("require-sri-for",),
    "require-trusted-types-for": ("require-trusted-types-for",),
    "trusted-types": ("trusted-types",),
}

RESOURCE_DIRECTIVES: dict[str, str] = {
    "script": "script-src-elem",
    "script-attribute": "script-src-attr",
    "style": "style-src-elem",
    "style-attribute": "style-src-attr",
    "image": "img-src",
    "media": "media-src",
    "font": "font-src",
    "frame": "frame-src",
    "object": "object-src",
    "manifest": "manifest-src",
    "worker": "worker-src",
    "connect": "connect-src",
}

PURPOSE_DIRECTIVES = RESOURCE_DIRECTIVES
FALLBACK_DIRECTIVES = DIRECTIVE_FALLBACKS

_RESOURCE_ALIASES = {
    "script-src": "script",
    "script-src-elem": "script",
    "script-src-attr": "script-attribute",
    "style-src": "style",
    "style-src-elem": "style",
    "style-src-attr": "style-attribute",
    "stylesheet": "style",
    "styles": "style",
    "css": "style",
    "scripts": "script",
    "js": "script",
}

_CATEGORY_OF = {
    "script": "script",
    "script-attribute": "script",
    "style": "style",
    "style-attribute": "style",
    "image": "image",
    "media": "media",
    "font": "font",
    "frame": "frame",
    "object": "object",
    "manifest": "manifest",
    "worker": "worker",
    "connect": "connect",
}

_SCHEMES = {"http", "https", "data", "blob", "filesystem", "ws", "wss"}
_NONCE_RE = re.compile(r"^'nonce-([^']+)'$", re.IGNORECASE)
_HASH_RE = re.compile(r"^'(sha256|sha384|sha512)-([^']+)'$", re.IGNORECASE)
_DJANGO_SCRIPT_RE = re.compile(r"{%\s*script\b(.*?)%}", re.DOTALL)
_DJANGO_ENDSCRIPT_RE = re.compile(r"{%\s*endscript\s*%}")


def _normalise_name(name: str) -> str:
    return str(name).strip().lower()


def _plural_values(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, bool):
        return (str(value),)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(str(k) for k in value)
    if isinstance(value, Iterable):
        return tuple(str(v) for v in value)
    return (str(value),)


def normalize_config(config: Mapping[str, Any] | None) -> dict[str, tuple[str, ...]]:
    """Normalise a ``DIRECTIVES`` mapping without losing explicit empty values."""
    directives: dict[str, tuple[str, ...]] = {}
    if not config:
        return directives
    for key, value in config.items():
        name = _normalise_name(key)
        if value is None:
            continue
        if isinstance(value, bool):
            if value:
                directives[name] = ()
            continue
        directives[name] = _plural_values(value)
    return directives


def parse_policy(policy: str | Mapping[str, Any] | PolicySpec | None) -> dict[str, tuple[str, ...]]:
    """Parse either a CSP header or a Django ``DIRECTIVES`` mapping.

    The result keeps empty directives. This distinction matters because an
    explicitly empty ``script-src`` blocks scripts instead of falling back to
    ``default-src``.
    """
    if policy is None:
        return {}
    if isinstance(policy, PolicySpec):
        return dict(policy.directives)
    if isinstance(policy, Mapping):
        nested = policy.get("DIRECTIVES")
        if isinstance(nested, Mapping):
            from csp.utils import default_config

            return normalize_config(default_config(nested))
        return normalize_config(policy)

    directives: dict[str, tuple[str, ...]] = {}
    for chunk in str(policy).split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        pieces = chunk.split()
        name = _normalise_name(pieces[0])
        values = tuple(pieces[1:])
        if name not in directives:
            directives[name] = values
    return directives


def canonical_policy(directives: Mapping[str, Sequence[str]]) -> str:
    """Return an order-independent representation of a parsed policy."""
    return "; ".join(f"{name} {' '.join(sorted(values))}".strip() for name, values in sorted(directives.items()))


def policy_identity(directives: Mapping[str, Sequence[str]]) -> str:
    return hashlib.sha256(canonical_policy(directives).encode("utf-8")).hexdigest()


def _normalise_origin(origin: str) -> str | None:
    origin = origin.strip()
    if not origin:
        return None
    parsed = urlsplit(origin if "://" in origin else f"//{origin}")
    if not parsed.netloc:
        return None
    scheme = parsed.scheme or "http"
    return f"{scheme}://{parsed.netloc}".lower()


def _url_origin(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}".lower()


@dataclass(frozen=True)
class PolicySpec:
    """A parsed policy together with the caller's local-origin context."""

    directives: Mapping[str, tuple[str, ...]]
    self_origins: tuple[str, ...] = ()
    report_only: bool = False
    source: str = "inline"

    @classmethod
    def from_any(
        cls,
        policy: str | Mapping[str, Any] | PolicySpec | None,
        *,
        self_origins: Iterable[str] = (),
        report_only: bool = False,
        source: str | None = None,
    ) -> PolicySpec:
        if isinstance(policy, PolicySpec):
            origins = tuple(policy.self_origins) + tuple(str(o) for o in self_origins)
            return replace(policy, self_origins=tuple(dict.fromkeys(origins)))

        empty_settings = False
        if policy is None:
            setting_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
            configured = getattr(settings, setting_name, None)
            if configured:
                policy = {"DIRECTIVES": configured.get("DIRECTIVES", {})}
            else:
                policy = {}
                empty_settings = True
            if source is None:
                source = f"settings:{setting_name}"

        if not empty_settings and isinstance(policy, Mapping) and not isinstance(policy.get("DIRECTIVES"), Mapping):
            policy = {"DIRECTIVES": policy}

        origins = tuple(filter(None, (_normalise_origin(str(o)) for o in self_origins)))
        return cls(
            directives=parse_policy(policy),
            self_origins=tuple(dict.fromkeys(origins)),
            report_only=report_only,
            source=source or "inline",
        )

    @property
    def identity(self) -> str:
        return policy_identity(self.directives)

    def resolve(self, directive: str) -> DirectiveResolution:
        return resolve_directive(self.directives, directive)

    def with_origins(self, *origins: str | None) -> PolicySpec:
        values = tuple(filter(None, (o for o in origins if o)))
        merged = tuple(dict.fromkeys((*self.self_origins, *(str(o) for o in values))))
        return replace(self, self_origins=merged)


@dataclass(frozen=True)
class DirectiveResolution:
    """The directive that actually binds a resource kind."""

    requested: str
    effective: str | None
    sources: tuple[str, ...] = ()
    chain: tuple[str, ...] = ()
    inherited: bool = False
    explicit_empty: bool = False
    reason: str = ""

    @property
    def directive(self) -> str | None:
        return self.effective

    @property
    def name(self) -> str | None:
        return self.effective

    @property
    def values(self) -> tuple[str, ...]:
        return self.sources

    @property
    def present(self) -> bool:
        return self.effective is not None

    def __str__(self) -> str:
        return self.effective or ""


def fallback_chain(directive: str) -> tuple[str, ...]:
    name = _normalise_name(directive)
    return DIRECTIVE_FALLBACKS.get(name, (name, "default-src"))


def resource_directive(purpose: str) -> str:
    """Map a template use (script/style/image/...) to its requested directive."""
    name = _normalise_name(purpose)
    name = _RESOURCE_ALIASES.get(name, name)
    return RESOURCE_DIRECTIVES.get(name, name if name.endswith("-src") else f"{name}-src")


def resolve_directive(
    policy: str | Mapping[str, Any] | PolicySpec | None,
    requested: str,
) -> DirectiveResolution:
    directives = parse_policy(policy)
    requested = _normalise_name(requested)
    requested = _RESOURCE_ALIASES.get(requested, requested)
    requested = RESOURCE_DIRECTIVES.get(requested, requested)
    chain = fallback_chain(requested)

    for name in chain:
        if name in directives:
            sources = directives[name]
            return DirectiveResolution(
                requested=requested,
                effective=name,
                sources=sources,
                chain=chain,
                inherited=name != requested,
                explicit_empty=not sources,
                reason="explicit-empty" if not sources else ("inherited" if name != requested else "directive"),
            )

    return DirectiveResolution(
        requested=requested,
        effective=None,
        chain=chain,
        inherited=True,
        reason="no-directive-or-default",
    )


def effective_directive(
    policy: str | Mapping[str, Any] | PolicySpec | None,
    directive: str,
) -> str | None:
    """Return the name of the directive that ultimately applies."""
    return resolve_directive(policy, directive).effective


def _purpose_name(value: str) -> str:
    name = _normalise_name(value).replace("_", "-")
    return _RESOURCE_ALIASES.get(name, name)


def purpose_category(value: str) -> str:
    name = _purpose_name(value)
    return _CATEGORY_OF.get(name, name)


@dataclass(frozen=True)
class Resource:
    """One script, style, or other fetchable resource in a template snapshot."""

    purpose: str
    tag: str = ""
    attribute: str | None = None
    url: str | None = None
    inline: bool = False
    content: str = ""
    nonce: str | None = None
    attrs: Mapping[str, str] = field(default_factory=dict)
    position: int = 0
    line: int | None = None
    column: int | None = None

    @property
    def kind(self) -> str:
        return purpose_category(self.purpose)

    @property
    def type(self) -> str:
        return self.kind

    @property
    def resource_type(self) -> str:
        return self.purpose

    @property
    def category(self) -> str:
        return self.kind

    @property
    def directive(self) -> str:
        return resource_directive(self.purpose)

    @property
    def is_local(self) -> bool:
        return self.url is None or not urlsplit(self.url).netloc

    @property
    def content_key(self) -> str:
        value = self.url if self.url else self.content.strip()
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    @property
    def key(self) -> str:
        for attr in ("data-csp-id", "id", "name"):
            if self.attrs.get(attr):
                return self.attrs[attr]
        if self.url:
            return self.url
        return self.content_key

    @property
    def qualified_key(self) -> str:
        return f"{self.kind}:{self.key}"

    @property
    def identity(self) -> str:
        return self.key

    @property
    def label(self) -> str:
        if self.url:
            return self.url
        text = self.content.strip().replace("\n", " ")
        return text[:80]


class _TemplateParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[Resource] = []
        self._position = 0
        self._pending: dict[str, Any] | None = None
        self._pending_index: int | None = None

    def _next_position(self) -> int:
        self._position += 1
        return self._position

    def _add(self, resource: Resource) -> None:
        self.resources.append(resource)

    def _raw_resource(self, tag: str, attrs: Mapping[str, str], position: int, line: int, column: int) -> None:
        purpose = "script" if tag == "script" else "style"
        resource = Resource(
            purpose=purpose,
            tag=tag,
            url=attrs.get("src"),
            inline=not bool(attrs.get("src")),
            nonce=attrs.get("nonce"),
            attrs=dict(attrs),
            position=position,
            line=line,
            column=column,
        )
        self._add(resource)
        self._pending = {"tag": tag, "attrs": dict(attrs), "parts": [], "position": position, "line": line, "column": column}
        self._pending_index = len(self.resources) - 1

    def _finish_pending(self, tag: str) -> None:
        if self._pending is None or self._pending["tag"] != tag or self._pending_index is None:
            return
        pending = self._pending
        content = "".join(pending["parts"])
        current = self.resources[self._pending_index]
        self.resources[self._pending_index] = replace(current, content=content, inline=not bool(pending["attrs"].get("src")))
        self._pending = None
        self._pending_index = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {str(k).lower(): ("" if v is None else v) for k, v in attrs}
        line, column = self.getpos()
        position = self._next_position()

        if tag in ("script", "style"):
            self._raw_resource(tag, values, position, line, column)
            return

        resource = self._resource_for_tag(tag, values, position, line, column)
        if resource is not None:
            self._add(resource)

        if values.get("style"):
            self._add(
                Resource(
                    purpose="style-attribute",
                    tag=tag,
                    attribute="style",
                    inline=True,
                    content=values["style"],
                    attrs=dict(values),
                    position=self._next_position(),
                    line=line,
                    column=column,
                )
            )

        for name, value in values.items():
            if name.startswith("on") and len(name) > 2 and value:
                self._add(
                    Resource(
                        purpose="script-attribute",
                        tag=tag,
                        attribute=name,
                        inline=True,
                        content=value,
                        attrs=dict(values),
                        position=self._next_position(),
                        line=line,
                        column=column,
                    )
                )

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() in ("script", "style"):
            self._finish_pending(tag.lower())

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in ("script", "style"):
            self._finish_pending(tag)

    def handle_data(self, data: str) -> None:
        if self._pending is not None:
            self._pending["parts"].append(data)

    @staticmethod
    def _resource_for_tag(tag: str, attrs: Mapping[str, str], position: int, line: int, column: int) -> Resource | None:
        url: str | None = None
        purpose: str | None = None

        if tag == "link":
            rels = {part.lower() for part in attrs.get("rel", "").split()}
            as_value = attrs.get("as", "").lower()
            if "stylesheet" in rels or ("preload" in rels and as_value == "style"):
                purpose, url = "style", attrs.get("href")
            elif "preload" in rels and as_value == "script":
                purpose, url = "script", attrs.get("href")
            elif rels & {"icon", "apple-touch-icon"}:
                purpose, url = "image", attrs.get("href")
            elif "manifest" in rels:
                purpose, url = "manifest", attrs.get("href")
        elif tag == "img":
            purpose, url = "image", attrs.get("src")
        elif tag in ("audio", "video", "source", "track"):
            purpose, url = "media", attrs.get("src")
        elif tag in ("iframe", "frame"):
            purpose, url = "frame", attrs.get("src")
        elif tag in ("object", "embed"):
            purpose, url = "object", attrs.get("data") or attrs.get("src")
        elif tag == "form":
            purpose, url = "form-action", attrs.get("action")

        if purpose is None:
            return None
        return Resource(
            purpose=purpose,
            tag=tag,
            attribute={"link": "href", "object": "data", "form": "action"}.get(tag, "src"),
            url=url,
            inline=False,
            attrs=dict(attrs),
            position=position,
            line=line,
            column=column,
        )


def parse_template(template: str, *, request_url: str | None = None) -> tuple[Resource, ...]:
    """Extract the resources declared by a rendered template snippet."""
    template = _DJANGO_SCRIPT_RE.sub(lambda match: f"<script {match.group(1).strip()}>".replace(" >", ">"), template)
    template = _DJANGO_ENDSCRIPT_RE.sub("</script>", template)
    parser = _TemplateParser()
    parser.feed(str(template))
    parser.close()
    resources = sorted(parser.resources, key=lambda item: item.position)
    if request_url:
        base = urlsplit(request_url)
        base_url = request_url if base.scheme and base.netloc else request_url
        resources = tuple(
            replace(item, url=urljoin(base_url, item.url)) if item.url and not urlsplit(item.url).scheme else item for item in resources
        )
    return tuple(resources)


def _select_allowlist(
    allowlist: Any,
    caller: Any,
    resource: Resource,
) -> tuple[str, ...]:
    if allowlist is None:
        return ()

    value: Any = allowlist
    if isinstance(allowlist, Mapping):
        keys = {_normalise_name(str(key)) for key in allowlist}
        known = set(RESOURCE_DIRECTIVES) | set(DIRECTIVE_FALLBACKS) | {"script", "style", "script-attribute", "style-attribute"}
        if keys & known:
            value = (
                allowlist.get(resource.purpose)
                or allowlist.get(resource.kind)
                or allowlist.get(resource.directive)
                or allowlist.get(resource.directive.replace("-elem", ""))
                or ()
            )
        else:
            # A caller-scoped mapping must not silently fall back to another
            # caller's allowlist. Only an explicit default is shared.
            if caller is not None:
                value = allowlist.get(caller, allowlist.get(str(caller)))
            if value is None:
                value = allowlist.get("default", allowlist.get(None))

    if isinstance(value, Mapping):
        value = value.get(resource.purpose) or value.get(resource.kind) or value.get(resource.directive) or ()

    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        return tuple(str(item) for item in value)
    return (str(value),)


def _is_self(resource: Resource, policy: PolicySpec) -> bool:
    if resource.url is None:
        return True
    if resource.url.startswith("//"):
        return False
    origin = _url_origin(resource.url)
    if origin is None:
        # A relative URL is already on the document's origin.
        return not urlsplit(resource.url).netloc
    origins = set(policy.self_origins)
    return origin in origins


def _hash_source_matches(resource: Resource, source: str) -> bool:
    match = _HASH_RE.match(source)
    if not match:
        return False
    algorithm, expected = match.groups()
    digest = hashlib.new(algorithm, resource.content.encode("utf-8")).digest()
    actual = base64.b64encode(digest).decode("ascii")
    return actual == expected


def _resource_url_for_matching(resource: Resource, policy: PolicySpec) -> str | None:
    if not resource.url:
        return None
    if urlsplit(resource.url).netloc:
        return resource.url
    for origin in policy.self_origins:
        if origin:
            return urljoin(origin + "/", resource.url)
    return resource.url


def _host_source_matches(resource: Resource, source: str, policy: PolicySpec) -> bool:
    resource_url = _resource_url_for_matching(resource, policy)
    if not resource_url:
        return False
    try:
        target = urlsplit(resource_url)
    except ValueError:
        return False
    if not target.netloc:
        return False

    expression = source
    scheme = None
    if "://" in expression:
        scheme, expression = expression.split("://", 1)
        scheme = scheme.lower()

    host_part, _, path_part = expression.partition("/")
    port: str | None = None
    if host_part.startswith("["):
        host, _, rest = host_part.partition("]")
        host += "]"
        if rest.startswith(":"):
            port = rest[1:]
    elif ":" in host_part:
        host, port = host_part.rsplit(":", 1)
    else:
        host = host_part

    if scheme and scheme != target.scheme.lower():
        return False
    target_host = (target.hostname or "").lower()
    host = host.lower()
    if host == "*":
        host_matches = True
    elif host.startswith("*."):
        suffix = host[2:]
        host_matches = target_host.endswith("." + suffix)
    else:
        host_matches = target_host == host
    if not host_matches:
        return False

    target_port = target.port
    if target_port is None:
        target_port = {"http": 80, "https": 443}.get(target.scheme.lower())
    if port is not None and port not in ("", "*"):
        if int(port) != target_port:
            return False
    elif port is None and target_port not in (None, 80, 443):
        return False

    if path_part:
        path = "/" + path_part
        if path.endswith("/"):
            if not target.path.startswith(path):
                return False
        elif target.path != path:
            return False
    return True


def _literal_allowlist_matches(resource: Resource, source: str) -> bool:
    if not resource.url:
        return False
    if source == resource.url:
        return True
    if source.endswith("/") and resource.url.startswith(source):
        return True
    if source.startswith("/"):
        path = urlsplit(resource.url).path
        return path == source or (source.endswith("/") and path.startswith(source))
    return False


def _source_matches(resource: Resource, source: str, policy: PolicySpec) -> bool:
    source = str(source)
    if source == SELF:
        return _is_self(resource, policy)
    if source == NONE:
        return False
    if source == str(NONCE):
        return bool(resource.nonce)
    nonce = _NONCE_RE.match(source)
    if nonce:
        return bool(resource.nonce) and resource.nonce == nonce.group(1)
    if _HASH_RE.match(source):
        return resource.inline and _hash_source_matches(resource, source)
    if source == UNSAFE_INLINE:
        return resource.inline
    if source.lower() in {"'unsafe-eval'", "'report-sample'", "'wasm-unsafe-eval'", "'unsafe-allow-redirects'"}:
        return False
    if source == STRICT_DYNAMIC:
        return False
    if source == "*":
        return resource.url is not None or resource.inline
    if source.endswith(":") and source[:-1].lower() in _SCHEMES:
        resource_url = _resource_url_for_matching(resource, policy)
        return bool(resource_url) and urlsplit(resource_url).scheme.lower() == source[:-1].lower()
    if _literal_allowlist_matches(resource, source):
        return True
    return _host_source_matches(resource, source, policy)


@dataclass(frozen=True)
class ResourceDecision:
    resource: Resource
    resolution: DirectiveResolution
    status: Status
    matched: str | None = None
    reason: str = ""
    approval: ApprovedResource | None = None

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    @property
    def passed(self) -> bool:
        return self.allowed

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    @property
    def purpose(self) -> str:
        return self.resource.purpose

    @property
    def kind(self) -> str:
        return self.resource.kind

    @property
    def type(self) -> str:
        return self.resource.kind

    @property
    def directive(self) -> str | None:
        return self.resolution.effective

    @property
    def effective_directive(self) -> str | None:
        return self.resolution.effective

    @property
    def requested_directive(self) -> str:
        return self.resolution.requested

    @property
    def inherited(self) -> bool:
        return self.resolution.inherited

    def __bool__(self) -> bool:
        return self.allowed


def _evaluate(
    resource: Resource,
    policy: PolicySpec,
    allowlist: tuple[str, ...],
) -> ResourceDecision:
    resolution = resolve_directive(policy, resource.directive)

    if resolution.effective is None:
        status: Status = "allowed"
        matched = None
        reason = "no restricting directive or default-src"
    else:
        sources = resolution.sources
        status = "blocked"
        matched = None
        reason = "no source matched"

        if not sources:
            reason = "directive is explicitly empty"
        elif resource.inline:
            nonce_or_hash = tuple(s for s in sources if str(s) == str(NONCE) or _NONCE_RE.match(str(s)) or _HASH_RE.match(str(s)))
            for source in nonce_or_hash:
                if _source_matches(resource, source, policy):
                    status, matched, reason = "allowed", source, "inline nonce or hash matched"
                    break
            if status != "allowed" and not nonce_or_hash and UNSAFE_INLINE in sources:
                status, matched, reason = "allowed", UNSAFE_INLINE, "inline source allowed"
            elif status != "allowed" and nonce_or_hash:
                reason = "inline content has no matching nonce or hash"
        else:
            strict = STRICT_DYNAMIC in sources and resource.kind == "script"
            if not strict:
                for source in sources:
                    if _source_matches(resource, source, policy):
                        status, matched, reason = "allowed", str(source), "source matched"
                        break
            else:
                for source in sources:
                    if (str(source) == str(NONCE) or _NONCE_RE.match(str(source))) and _source_matches(resource, source, policy):
                        status, matched, reason = "allowed", str(source), "nonce matched with strict-dynamic"
                        break
                if status != "allowed":
                    status = "indeterminate"
                    reason = "strict-dynamic requires a runtime trust chain"

    if status != "allowed" and allowlist:
        for source in allowlist:
            if _source_matches(resource, source, policy):
                status, matched, reason = "allowed", source, "caller-scoped local allowlist matched"
                break

    return ResourceDecision(resource=resource, resolution=resolution, status=status, matched=matched, reason=reason)


@dataclass(frozen=True)
class ApprovedResource:
    key: str
    purpose: str | None = None
    directive: str | None = None
    allowed: bool | None = None

    @property
    def category(self) -> str | None:
        return purpose_category(self.purpose) if self.purpose else None


@dataclass(frozen=True)
class ApprovalMismatch:
    resource: Resource
    approved: ApprovedResource
    actual_purpose: str
    reason: str

    @property
    def stale_purpose(self) -> bool:
        return self.reason == "stale-purpose"

    @property
    def stale(self) -> bool:
        return self.stale_purpose

    @property
    def declared_purpose(self) -> str:
        return self.actual_purpose

    @property
    def recorded_purpose(self) -> str | None:
        return self.approved.purpose


def _coerce_approved(key: str, value: Any) -> ApprovedResource:
    if isinstance(value, ApprovedResource):
        return value
    if isinstance(value, str):
        return ApprovedResource(key=key, purpose=value)
    if isinstance(value, Mapping):
        purpose = value.get("purpose") or value.get("kind") or value.get("type") or value.get("resource_type") or value.get("category")
        return ApprovedResource(
            key=str(value.get("key", key)),
            purpose=str(purpose) if purpose is not None else None,
            directive=str(value["directive"]) if value.get("directive") is not None else None,
            allowed=value.get("allowed") if isinstance(value.get("allowed"), bool) else None,
        )
    purpose = (
        getattr(value, "purpose", None) or getattr(value, "kind", None) or getattr(value, "resource_type", None) or getattr(value, "category", None)
    )
    directive = getattr(value, "directive", None)
    allowed = getattr(value, "allowed", None)
    return ApprovedResource(
        key=str(getattr(value, "key", None) or getattr(value, "identity", None) or getattr(value, "id", None) or key),
        purpose=str(purpose) if purpose is not None else None,
        directive=str(directive) if directive is not None else None,
        allowed=allowed if isinstance(allowed, bool) else None,
    )


def coerce_approvals(approvals: Any) -> dict[str, ApprovedResource]:
    """Accept either ``key -> purpose`` or structured approval records."""
    if approvals is None:
        return {}
    if isinstance(approvals, Mapping):
        result: dict[str, ApprovedResource] = {}
        if {_normalise_name(str(k)) for k in approvals} <= {"script", "style", "script-attribute", "style-attribute"}:
            for purpose, keys in approvals.items():
                if isinstance(keys, str):
                    keys = (keys,)
                for key in keys:
                    result[str(key)] = ApprovedResource(key=str(key), purpose=str(purpose))
            return result
        for key, value in approvals.items():
            result[str(key)] = _coerce_approved(str(key), value)
        return result
    result = {}
    for entry in approvals:
        key = str(getattr(entry, "key", None) or (entry.get("key") if isinstance(entry, Mapping) else ""))
        if not key:
            key = str(getattr(entry, "id", ""))
        result[key] = _coerce_approved(key, entry)
    return result


def _approval_for(resource: Resource, approvals: Mapping[str, ApprovedResource]) -> ApprovedResource | None:
    content = resource.content.strip()
    content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    content_b64 = base64.b64encode(hashlib.sha256(content.encode("utf-8")).digest()).decode("ascii")
    candidates = (
        resource.key,
        resource.identity,
        resource.qualified_key,
        f"{resource.kind}:{resource.content_key}",
        resource.content_key,
        content,
        resource.content,
        content_sha256,
        f"sha256:{content_sha256}",
        content_b64,
        f"sha256-{content_b64}",
        resource.url,
        str(resource.position),
    )
    for candidate in candidates:
        if candidate and candidate in approvals:
            return approvals[candidate]
    if resource.url:
        for approved in approvals.values():
            if approved.key == resource.url:
                return approved
    for approved in approvals.values():
        if (
            approved.key.endswith(f":{resource.content_key}")
            or approved.key.endswith(f":{resource.key}")
            or approved.key.endswith(f":{content_sha256}")
            or approved.key.endswith(f":{content_b64}")
        ):
            return approved
    return None


@dataclass(frozen=True)
class CategoryReview:
    category: str
    decisions: tuple[ResourceDecision, ...]
    stale: tuple[ApprovalMismatch, ...] = ()

    @property
    def resources(self) -> tuple[Resource, ...]:
        return tuple(decision.resource for decision in self.decisions)

    @property
    def present(self) -> bool:
        return bool(self.decisions)

    @property
    def allowed(self) -> bool:
        return all(decision.allowed for decision in self.decisions)

    @property
    def passed(self) -> bool:
        return self.allowed

    @property
    def kind(self) -> str:
        return self.category

    @property
    def purpose(self) -> str:
        return self.category

    @property
    def status(self) -> str:
        if not self.decisions:
            return "not-present"
        if any(decision.status == "blocked" for decision in self.decisions):
            return "blocked"
        if any(decision.status == "indeterminate" for decision in self.decisions):
            return "indeterminate"
        return "allowed"

    def __bool__(self) -> bool:
        return self.allowed

    def __iter__(self) -> Iterator[ResourceDecision]:
        return iter(self.decisions)

    def __len__(self) -> int:
        return len(self.decisions)


@dataclass(frozen=True, init=False)
class TemplateSnapshot:
    """An immutable rendered-template snapshot shared by every observation."""

    html: str
    resources: tuple[Resource, ...]
    name: str | None = None
    request_url: str | None = None
    self_origins: tuple[str, ...] = ()

    def __init__(
        self,
        html: str | None = None,
        *,
        template: str | None = None,
        name: str | None = None,
        request_url: str | None = None,
        self_origins: Iterable[str] = (),
    ) -> None:
        value = html if html is not None else template
        if value is None:
            raise TypeError("TemplateSnapshot requires html or template")
        origins = tuple(filter(None, (_normalise_origin(str(origin)) for origin in self_origins)))
        object.__setattr__(self, "html", str(value))
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "request_url", request_url)
        object.__setattr__(self, "self_origins", origins)
        object.__setattr__(self, "resources", parse_template(str(value), request_url=request_url))

    @property
    def template(self) -> str:
        return self.html

    def audit(self, policy: str | Mapping[str, Any] | PolicySpec | None = None, **kwargs: Any) -> InventoryReport:
        return audit_snapshot(self, policy=policy, **kwargs)

    def inventory(self, policy: str | Mapping[str, Any] | PolicySpec | None = None, **kwargs: Any) -> InventoryReport:
        return self.audit(policy, **kwargs)


@dataclass(frozen=True)
class InventoryReport:
    snapshot: TemplateSnapshot
    policy: PolicySpec
    decisions: tuple[ResourceDecision, ...]
    approvals: Mapping[str, ApprovedResource] = field(default_factory=dict)
    mismatches: tuple[ApprovalMismatch, ...] = ()
    role: str = "release"

    @property
    def resources(self) -> tuple[Resource, ...]:
        return self.snapshot.resources

    @property
    def template(self) -> str:
        return self.snapshot.html

    @property
    def directives(self) -> Mapping[str, tuple[str, ...]]:
        return self.policy.directives

    @property
    def policy_string(self) -> str:
        return canonical_policy(self.policy.directives)

    @property
    def allowed(self) -> bool:
        return all(decision.allowed for decision in self.decisions)

    @property
    def passed(self) -> bool:
        return self.allowed

    @property
    def by_purpose(self) -> dict[str, CategoryReview]:
        result: dict[str, CategoryReview] = {}
        for decision in self.decisions:
            result.setdefault(decision.resource.purpose, [])
        for purpose in result:
            decisions = tuple(decision for decision in self.decisions if decision.resource.purpose == purpose)
            stale = tuple(mismatch for mismatch in self.mismatches if mismatch.resource.purpose == purpose)
            result[purpose] = CategoryReview(category=purpose, decisions=decisions, stale=stale)
        return result

    @property
    def by_category(self) -> dict[str, CategoryReview]:
        grouped: dict[str, list[ResourceDecision]] = {}
        for decision in self.decisions:
            grouped.setdefault(decision.resource.kind, []).append(decision)
        return {
            category: CategoryReview(
                category=category,
                decisions=tuple(decisions),
                stale=tuple(mismatch for mismatch in self.mismatches if mismatch.resource.kind == category),
            )
            for category, decisions in grouped.items()
        }

    @property
    def by_kind(self) -> dict[str, CategoryReview]:
        return self.by_category

    @property
    def by_type(self) -> dict[str, CategoryReview]:
        return self.by_category

    @property
    def style_observation(self) -> CategoryReview:
        return self.by_category.get("style", CategoryReview(category="style", decisions=()))

    @property
    def script_release(self) -> CategoryReview:
        return self.by_category.get("script", CategoryReview(category="script", decisions=()))

    @property
    def style(self) -> CategoryReview:
        return self.style_observation

    @property
    def script(self) -> CategoryReview:
        return self.script_release

    @property
    def styles(self) -> CategoryReview:
        return self.style_observation

    @property
    def scripts(self) -> CategoryReview:
        return self.script_release

    @property
    def stale_approvals(self) -> tuple[ApprovalMismatch, ...]:
        return self.mismatches

    @property
    def approval_valid(self) -> bool:
        return not self.mismatches

    def __getitem__(self, key: str) -> CategoryReview:
        category = purpose_category(key)
        reviews = self.by_category
        if category in reviews:
            return reviews[category]
        purposes = self.by_purpose
        if key in purposes:
            return purposes[key]
        raise KeyError(key)

    def __iter__(self) -> Iterator[ResourceDecision]:
        return iter(self.decisions)

    def __len__(self) -> int:
        return len(self.decisions)

    @property
    def categories(self) -> dict[str, CategoryReview]:
        return self.by_category

    def decisions_for(self, purpose: str) -> tuple[ResourceDecision, ...]:
        category = purpose_category(purpose)
        return tuple(decision for decision in self.decisions if decision.resource.kind == category)

    def get(self, purpose: str, default: CategoryReview | None = None) -> CategoryReview | None:
        try:
            return self[purpose]
        except KeyError:
            return default

    def can_release(self, purpose: str = "script", *, require_approval: bool = False) -> bool:
        category = purpose_category(purpose)
        decisions = tuple(decision for decision in self.decisions if decision.resource.kind == category)
        if not decisions or not all(decision.allowed for decision in decisions):
            return False
        if any(mismatch.resource.kind == category for mismatch in self.mismatches):
            return False
        if require_approval:
            return all(_approval_for(decision.resource, self.approvals) is not None for decision in decisions)
        return True

    def can_approve(self, purpose: str = "script", *, require_approval: bool = False) -> bool:
        return self.can_release(purpose, require_approval=require_approval)

    def explain(self, purpose: str | None = None) -> str:
        lines = [f"Policy source: {self.policy.source} ({'report-only' if self.policy.report_only else 'enforced'})"]
        selected = self.decisions
        if purpose:
            category = purpose_category(purpose)
            selected = tuple(decision for decision in selected if decision.resource.kind == category)
        if not selected:
            lines.append(f"No {purpose or 'auditable'} resources in the template snapshot.")
        for decision in selected:
            resource = decision.resource
            chain = " -> ".join(decision.resolution.chain)
            effective = decision.directive or "unresolved"
            sources = " ".join(decision.resolution.sources) or "(empty)"
            lines.append(f"{resource.purpose} {resource.label!r}: {decision.status} via {effective} [{chain}; {sources}] ({decision.reason})")
        for mismatch in self.mismatches:
            lines.append(
                f"approval {mismatch.approved.key!r} says {mismatch.approved.purpose!r}, but the snapshot declares {mismatch.actual_purpose!r}"
            )
        if self.script_release.present and self.style_observation.allowed and not self.can_release("script"):
            lines.append(
                "The style result cannot approve a script release: the snapshot's script elements "
                "use script-src-elem/script-src (then default-src), which is evaluated separately "
                "from the style directives."
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": canonical_policy(self.policy.directives),
            "policy_identity": self.policy.identity,
            "role": self.role,
            "resources": [
                {
                    "purpose": decision.resource.purpose,
                    "key": decision.resource.key,
                    "url": decision.resource.url,
                    "status": decision.status,
                    "directive": decision.directive,
                    "inherited": decision.inherited,
                    "matched": decision.matched,
                    "reason": decision.reason,
                }
                for decision in self.decisions
            ],
            "stale_approvals": [
                {
                    "key": mismatch.approved.key,
                    "approved_purpose": mismatch.approved.purpose,
                    "actual_purpose": mismatch.actual_purpose,
                    "reason": mismatch.reason,
                }
                for mismatch in self.mismatches
            ],
        }


@dataclass(frozen=True)
class PolicyObservation:
    """Observation and release decisions derived from one template snapshot."""

    snapshot: TemplateSnapshot
    observation: InventoryReport | None = None
    release: InventoryReport | None = None

    @property
    def style_observation(self) -> CategoryReview:
        if self.observation is None:
            return CategoryReview(category="style", decisions=())
        return self.observation.style_observation

    @property
    def script_release(self) -> CategoryReview:
        if self.release is None:
            return CategoryReview(category="script", decisions=())
        return self.release.script_release

    def can_release(self, purpose: str = "script", *, require_approval: bool = False) -> bool:
        return self.release is not None and self.release.can_release(purpose, require_approval=require_approval)

    def explain(self) -> str:
        lines = []
        if self.observation is None:
            lines.append("Style observation: no observation policy was supplied.")
        else:
            lines.append("Style observation:\n" + self.observation.explain("style"))
        if self.release is None:
            lines.append("Script release: no enforced policy was supplied.")
        else:
            lines.append("Script release:\n" + self.release.explain("script"))
        if self.style_observation.allowed and not self.can_release("script"):
            lines.append(
                "The style result cannot approve a script release: the snapshot's script elements "
                "use script-src-elem/script-src (then default-src), which is evaluated separately "
                "from the style directives."
            )
        return "\n\n".join(lines)


def snapshot_template(
    template: str | None = None,
    *,
    html: str | None = None,
    name: str | None = None,
    request_url: str | None = None,
    self_origins: Iterable[str] = (),
) -> TemplateSnapshot:
    template = template if template is not None else html
    if template is None:
        raise TypeError("snapshot_template requires template or html")
    return TemplateSnapshot(template, name=name, request_url=request_url, self_origins=self_origins)


def _request_url(request: Any) -> str | None:
    if request is None:
        return None
    try:
        return str(request.build_absolute_uri("/"))
    except (AttributeError, TypeError, ValueError):
        host = getattr(request, "get_host", lambda: None)()
        if not host:
            return None
        scheme = getattr(request, "scheme", "http") or "http"
        return f"{scheme}://{host}/"


def audit_snapshot(
    snapshot: TemplateSnapshot | str | None = None,
    policy: str | Mapping[str, Any] | PolicySpec | None = None,
    *,
    html: str | None = None,
    template: str | None = None,
    directives: Mapping[str, Any] | None = None,
    header: str | None = None,
    policy_header: str | None = None,
    self_origins: Iterable[str] = (),
    local_origins: Iterable[str] | None = None,
    local_allowlist: Any = None,
    allowlist: Any = None,
    allowlists: Any = None,
    caller_allowlists: Any = None,
    caller: Any = None,
    caller_id: Any = None,
    approvals: Any = None,
    approved: Any = None,
    approval_records: Any = None,
    report_only: bool = False,
    role: str | None = None,
    request_url: str | None = None,
    request: Any = None,
    use_settings: bool = True,
) -> InventoryReport:
    """Audit one template snapshot against one effective response policy."""
    if snapshot is None:
        snapshot = html if html is not None else template
    if snapshot is None:
        raise TypeError("audit_snapshot requires a snapshot, html, or template")
    if policy is None:
        policy = directives if directives is not None else header if header is not None else policy_header
    if local_origins is not None and not self_origins:
        self_origins = local_origins
    if caller is None:
        caller = caller_id
    if approvals is None:
        approvals = approved if approved is not None else approval_records
    if request is not None:
        request_url = request_url or _request_url(request)
        if not self_origins:
            host = getattr(request, "get_host", lambda: None)()
            scheme = getattr(request, "scheme", "http") or "http"
            if host:
                self_origins = (f"{scheme}://{host}",)
    if not isinstance(snapshot, TemplateSnapshot):
        if not isinstance(snapshot, str) and hasattr(snapshot, "render"):
            from django.template import Context

            snapshot = snapshot.render(Context({"request": request}))
        snapshot = TemplateSnapshot(snapshot, request_url=request_url, self_origins=self_origins)

    effective_request_url = request_url or snapshot.request_url
    origins = tuple(dict.fromkeys((*snapshot.self_origins, *(str(origin) for origin in self_origins))))
    if policy is None and not use_settings:
        policy_spec = PolicySpec(directives={}, self_origins=origins, report_only=report_only, source="response")
    else:
        policy_spec = PolicySpec.from_any(policy, self_origins=origins, report_only=report_only)
    if effective_request_url:
        policy_spec = policy_spec.with_origins(_url_origin(effective_request_url))

    chosen_allowlist = local_allowlist
    if chosen_allowlist is None:
        chosen_allowlist = allowlist
    if chosen_allowlist is None:
        chosen_allowlist = allowlists if allowlists is not None else caller_allowlists
    approval_map = coerce_approvals(approvals)
    decisions: list[ResourceDecision] = []
    mismatches: list[ApprovalMismatch] = []

    for resource in snapshot.resources:
        selected_allowlist = _select_allowlist(chosen_allowlist, caller, resource)
        decision = _evaluate(resource, policy_spec, selected_allowlist)
        approved = _approval_for(resource, approval_map)
        if approved is not None and approved.purpose:
            approved_purpose = _purpose_name(approved.purpose)
            actual_purpose = _purpose_name(resource.purpose)
            reason = ""
            if approved_purpose != actual_purpose:
                reason = "stale-purpose"
            elif approved.directive and _normalise_name(approved.directive) not in {
                _normalise_name(decision.resolution.requested),
                _normalise_name(decision.resolution.effective or ""),
            }:
                reason = "directive-mismatch"
            elif approved.allowed is False and decision.allowed:
                reason = "approval-was-blocked"
            if reason:
                mismatch = ApprovalMismatch(
                    resource=resource,
                    approved=approved,
                    actual_purpose=resource.purpose,
                    reason=reason,
                )
                mismatches.append(mismatch)
                decision = replace(decision, approval=approved)
        decisions.append(decision)

    return InventoryReport(
        snapshot=snapshot,
        policy=policy_spec,
        decisions=tuple(decisions),
        approvals=approval_map,
        mismatches=tuple(mismatches),
        role=role or ("observation" if report_only else "release"),
    )


def audit_template(
    template: TemplateSnapshot | str | None = None,
    policy: str | Mapping[str, Any] | PolicySpec | None = None,
    **kwargs: Any,
) -> InventoryReport:
    if template is None:
        template = kwargs.pop("html", kwargs.pop("snapshot", None))
    if template is None:
        raise TypeError("audit_template requires a template, html, or snapshot")
    return audit_snapshot(template, policy, **kwargs)


def build_inventory(
    template: TemplateSnapshot | str | None = None,
    policy: str | Mapping[str, Any] | PolicySpec | None = None,
    **kwargs: Any,
) -> InventoryReport:
    if template is None:
        template = kwargs.pop("html", kwargs.pop("snapshot", None))
    if template is None:
        raise TypeError("build_inventory requires a template, html, or snapshot")
    return audit_snapshot(template, policy, **kwargs)


def inventory_template(
    template: TemplateSnapshot | str | None = None,
    policy: str | Mapping[str, Any] | PolicySpec | None = None,
    **kwargs: Any,
) -> InventoryReport:
    if template is None:
        template = kwargs.pop("html", kwargs.pop("snapshot", None))
    if template is None:
        raise TypeError("inventory_template requires a template, html, or snapshot")
    return audit_snapshot(template, policy, **kwargs)


def extract_resources(template: str, *, request_url: str | None = None) -> tuple[Resource, ...]:
    return parse_template(template, request_url=request_url)


def audit_observation_and_release(
    template: TemplateSnapshot | str | None = None,
    *,
    html: str | None = None,
    observation_policy: str | Mapping[str, Any] | PolicySpec | None = None,
    release_policy: str | Mapping[str, Any] | PolicySpec | None = None,
    self_origins: Iterable[str] = (),
    local_allowlist: Any = None,
    caller: Any = None,
    approvals: Any = None,
    request_url: str | None = None,
    **kwargs: Any,
) -> PolicyObservation:
    """Evaluate report-only observation and enforced release from one snapshot."""
    template = template if template is not None else html
    if template is None:
        raise TypeError("audit_observation_and_release requires a template or html")
    if not isinstance(template, TemplateSnapshot):
        template = TemplateSnapshot(template, request_url=request_url, self_origins=self_origins)

    common = {
        "self_origins": self_origins,
        "local_allowlist": local_allowlist,
        "caller": caller,
        "approvals": approvals,
        **kwargs,
    }
    observation = (
        audit_snapshot(template, observation_policy, report_only=True, role="observation", **common) if observation_policy is not None else None
    )
    release = audit_snapshot(template, release_policy, report_only=False, role="release", **common) if release_policy is not None else None
    return PolicyObservation(snapshot=template, observation=observation, release=release)


def audit_policies(
    template: TemplateSnapshot | str,
    *,
    observation_policy: str | Mapping[str, Any] | PolicySpec | None = None,
    release_policy: str | Mapping[str, Any] | PolicySpec | None = None,
    **kwargs: Any,
) -> PolicyObservation:
    return audit_observation_and_release(
        template,
        observation_policy=observation_policy,
        release_policy=release_policy,
        **kwargs,
    )


def response_policy(response: Any, *, report_only: bool = False) -> str | None:
    header = HEADER_REPORT_ONLY if report_only else HEADER
    return response.headers.get(header)


def snapshot_from_response(
    response: Any,
    template: str | None = None,
    *,
    report_only: bool = False,
    self_origins: Iterable[str] = (),
    request_url: str | None = None,
) -> tuple[TemplateSnapshot, str | None]:
    if template is None:
        content = getattr(response, "content", b"")
        template = content.decode("utf-8") if isinstance(content, bytes) else str(content)
    policy = response_policy(response, report_only=report_only)
    return TemplateSnapshot(template, request_url=request_url, self_origins=self_origins), policy


def audit_response(
    response: Any,
    template: str | None = None,
    *,
    report_only: bool = False,
    **kwargs: Any,
) -> InventoryReport:
    self_origins = kwargs.pop("self_origins", ())
    request_url = kwargs.pop("request_url", None)
    request = kwargs.pop("request", None)
    kwargs.pop("use_settings", None)
    if request is not None:
        request_url = request_url or _request_url(request)
        if not self_origins:
            host = getattr(request, "get_host", lambda: None)()
            scheme = getattr(request, "scheme", "http") or "http"
            if host:
                self_origins = (f"{scheme}://{host}",)
    snapshot, policy = snapshot_from_response(
        response,
        template,
        report_only=report_only,
        self_origins=self_origins,
        request_url=request_url,
    )
    return audit_snapshot(
        snapshot,
        policy,
        self_origins=self_origins,
        report_only=report_only,
        request_url=request_url,
        use_settings=False,
        **kwargs,
    )


audit = audit_template
inventory = build_inventory
resource_inventory = build_inventory
check_template = audit_template
check_resources = audit_template
audit_resources = audit_template
inventory_from_template = audit_template
build_resource_inventory = build_inventory
parse_template_resources = parse_template
resources_from_template = parse_template
parse_header = parse_policy
parse_response_policy = parse_policy
resolve_effective_directive = resolve_directive
ResourceInventory = InventoryReport
TemplateInventory = InventoryReport
AuditReport = InventoryReport
EffectiveDirective = DirectiveResolution
InventoryEntry = Resource
InventoryDecision = ResourceDecision
PolicyInventory = PolicySpec
Policy = PolicySpec
Snapshot = TemplateSnapshot
ApprovalRecord = ApprovedResource
Approval = ApprovedResource


__all__ = [
    "DIRECTIVE_FALLBACKS",
    "FALLBACK_DIRECTIVES",
    "PURPOSE_DIRECTIVES",
    "RESOURCE_DIRECTIVES",
    "ApprovalMismatch",
    "Approval",
    "ApprovalRecord",
    "ApprovedResource",
    "AuditReport",
    "CategoryReview",
    "DirectiveResolution",
    "EffectiveDirective",
    "InventoryDecision",
    "InventoryEntry",
    "InventoryReport",
    "PolicyObservation",
    "PolicyInventory",
    "Policy",
    "PolicySpec",
    "Resource",
    "ResourceDecision",
    "ResourceInventory",
    "TemplateSnapshot",
    "TemplateInventory",
    "Snapshot",
    "audit",
    "audit_resources",
    "audit_observation_and_release",
    "audit_policies",
    "audit_response",
    "audit_snapshot",
    "audit_template",
    "build_inventory",
    "build_resource_inventory",
    "canonical_policy",
    "coerce_approvals",
    "effective_directive",
    "extract_resources",
    "fallback_chain",
    "inventory_template",
    "inventory",
    "inventory_from_template",
    "normalize_config",
    "parse_policy",
    "parse_header",
    "parse_response_policy",
    "parse_template",
    "parse_template_resources",
    "policy_identity",
    "purpose_category",
    "resolve_directive",
    "resolve_effective_directive",
    "resource_directive",
    "response_policy",
    "snapshot_from_response",
    "snapshot_template",
    "check_template",
    "check_resources",
    "resource_inventory",
    "resources_from_template",
]
