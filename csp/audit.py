from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.http import HttpResponse
from django.test import RequestFactory

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.middleware import CSPMiddleware

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

    ViewFunc = Callable[[HttpRequest], HttpResponseBase]

# View decorator attributes that act as rule sources on a response.
_VIEW_SOURCE_ATTRS = (
    ("_csp_config", "view:csp"),
    ("_csp_update", "view:csp_update"),
    ("_csp_replace", "view:csp_replace"),
)


def parse_policy(policy: str) -> dict[str, tuple[str, ...]]:
    """Parse a CSP header string into a normalized, order-independent mapping."""
    directives: dict[str, tuple[str, ...]] = {}
    for chunk in policy.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, _, values = chunk.partition(" ")
        directives[name.strip().lower()] = tuple(sorted(values.split()))
    return directives


def normalize_config(config: Mapping[str, Any] | None) -> dict[str, tuple[str, ...]]:
    """Normalize a DIRECTIVES-style config mapping into the canonical parsed form."""
    directives: dict[str, tuple[str, ...]] = {}
    if not config:
        return directives
    for key, value in config.items():
        if value is None:
            continue
        if isinstance(value, bool):
            if value:
                directives[str(key).lower()] = ()
            continue
        if isinstance(value, str):
            values = (value,)
        else:
            values = tuple(str(item) for item in value)
        directives[str(key).lower()] = tuple(sorted(values))
    return directives


def canonical_policy(directives: Mapping[str, tuple[str, ...]]) -> str:
    """Serialize normalized directives into a canonical, order-independent string."""
    return "; ".join(f"{name} {' '.join(values)}".strip() for name, values in sorted(directives.items()))


def policy_identity(directives: Mapping[str, tuple[str, ...]]) -> str:
    """Stable fingerprint of the parsed rules, never of the raw response string."""
    return hashlib.sha256(canonical_policy(directives).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PolicyReview:
    """An approval-ready review record of an effective policy."""

    identity: str
    directives: dict[str, tuple[str, ...]]
    sources: tuple[str, ...] = ()

    def matches(self, other: PolicyReview) -> bool:
        return self.identity == other.identity


def _response_sources(response: HttpResponseBase, report_only: bool) -> tuple[str, ...]:
    sources = []
    setting_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
    if getattr(settings, setting_name, None):
        sources.append(f"settings:{setting_name}")
    suffix = "_ro" if report_only else ""
    for attr, label in _VIEW_SOURCE_ATTRS:
        if getattr(response, f"{attr}{suffix}", None) is not None:
            sources.append(label)
    return tuple(sources)


def review_response(response: HttpResponseBase, report_only: bool = False) -> PolicyReview | None:
    """Build a review record from the parsed policy on a response."""
    header = HEADER_REPORT_ONLY if report_only else HEADER
    policy = response.headers.get(header)
    if not policy:
        return None
    directives = parse_policy(policy)
    return PolicyReview(
        identity=policy_identity(directives),
        directives=directives,
        sources=_response_sources(response, report_only),
    )


@dataclass(frozen=True)
class ReviewComparison:
    """Directive-level diff between an approved record and a current review."""

    approved: PolicyReview
    current: PolicyReview

    @property
    def changed(self) -> bool:
        return self.approved.identity != self.current.identity

    @property
    def added(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.current.directives) - set(self.approved.directives)))

    @property
    def removed(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.approved.directives) - set(self.current.directives)))

    @property
    def altered(self) -> tuple[str, ...]:
        common = set(self.approved.directives) & set(self.current.directives)
        return tuple(sorted(k for k in common if self.approved.directives[k] != self.current.directives[k]))


def compare_reviews(approved: PolicyReview, current: PolicyReview) -> ReviewComparison:
    return ReviewComparison(approved=approved, current=current)


def _run_view(view: ViewFunc, middleware: CSPMiddleware | None = None) -> HttpResponseBase:
    mw = middleware or CSPMiddleware(lambda request: HttpResponse())
    request = RequestFactory().get("/")
    mw.process_request(request)
    response = view(request)
    return mw.process_response(request, response)


def approve_view(view: ViewFunc, report_only: bool = False, middleware: CSPMiddleware | None = None) -> PolicyReview:
    """Record an approval review for the effective policy a view currently emits."""
    review = review_response(_run_view(view, middleware=middleware), report_only=report_only)
    if review is None:
        msg = "View did not produce a CSP header to approve."
        raise ValueError(msg)
    return review


@dataclass(frozen=True)
class ViewCheck:
    """The outcome of checking one view against its approval record."""

    name: str
    review: PolicyReview | None
    approved: PolicyReview | None

    @property
    def comparison(self) -> ReviewComparison | None:
        if self.review is None or self.approved is None:
            return None
        return compare_reviews(self.approved, self.review)

    @property
    def changed(self) -> bool:
        if self.approved is None:
            return False
        if self.review is None:
            return True
        return not self.approved.matches(self.review)

    @property
    def upheld(self) -> bool:
        return self.approved is not None and self.review is not None and not self.changed


@dataclass(frozen=True)
class ReviewReport:
    """The result of checking a set of views against their approval records."""

    checks: dict[str, ViewCheck]

    @property
    def changed(self) -> list[str]:
        return [name for name, check in self.checks.items() if check.changed]

    @property
    def upheld(self) -> list[str]:
        return [name for name, check in self.checks.items() if check.upheld]

    @property
    def unreviewed(self) -> list[str]:
        return [name for name, check in self.checks.items() if check.approved is None]


def check_views(
    views: Mapping[str, ViewFunc],
    approvals: Mapping[str, PolicyReview] | None = None,
    report_only: bool = False,
    middleware: CSPMiddleware | None = None,
) -> ReviewReport:
    """Check views against their approval records and report effective changes."""
    approvals = approvals or {}
    checks = {}
    for name, view in views.items():
        response = _run_view(view, middleware=middleware)
        review = review_response(response, report_only=report_only)
        checks[name] = ViewCheck(name=name, review=review, approved=approvals.get(name))
    return ReviewReport(checks=checks)
