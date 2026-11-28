from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.audit import (
    approve_view,
    canonical_policy,
    check_views,
    normalize_config,
    parse_policy,
    policy_identity,
    review_response,
)
from csp.constants import HEADER, SELF
from csp.decorators import csp_replace, csp_update
from csp.middleware import CSPMiddleware

APPROVED_DIRECTIVES = {
    "default-src": [SELF],
    "script-src": [SELF, "cdn.example.com"],
    "img-src": [SELF, "img.example.com"],
}


def view_one(request):
    return HttpResponse()


def view_two(request):
    return HttpResponse()


def view_three(request):
    return HttpResponse()


def test_parse_policy_is_order_independent() -> None:
    a = parse_policy("default-src 'self'; script-src 'self' cdn.example.com")
    b = parse_policy("script-src cdn.example.com 'self'; default-src 'self'")
    assert a == b
    assert canonical_policy(a) == canonical_policy(b)
    assert policy_identity(a) == policy_identity(b)


def test_normalize_config() -> None:
    config = {
        "default-src": SELF,
        "script-src": {"cdn.example.com", SELF},
        "upgrade-insecure-requests": True,
        "block-all-mixed-content": False,
        "img-src": None,
    }
    assert normalize_config(config) == {
        "default-src": (SELF,),
        "script-src": (SELF, "cdn.example.com"),
        "upgrade-insecure-requests": (),
    }


def test_identity_comes_from_parsed_rules_not_raw_string() -> None:
    mw = CSPMiddleware(lambda request: HttpResponse())
    request = RequestFactory().get("/")
    mw.process_request(request)
    with override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": APPROVED_DIRECTIVES}):
        response = mw.process_response(request, view_one(request))
    raw = response.headers[HEADER]
    review = review_response(response)
    assert review is not None
    assert review.identity != raw
    assert review.identity == policy_identity(parse_policy(raw))


def test_review_response_records_settings_and_view_sources() -> None:
    @csp_update({"img-src": ["img.example.com"]})
    def view(request):
        return HttpResponse()

    with override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}}):
        review = approve_view(view)
    assert review.sources == ("settings:CONTENT_SECURITY_POLICY", "view:csp_update")


def test_check_views_reports_only_true_changes() -> None:
    # Two policies approved as they were.
    with override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": APPROVED_DIRECTIVES}):
        approvals = {
            "view_one": approve_view(view_one),
            "view_two": approve_view(view_two),
        }

    # Same rules, only the declaration order was adjusted.
    reordered = {
        "img-src": ["img.example.com", SELF],
        "default-src": [SELF],
        "script-src": ["cdn.example.com", SELF],
    }
    # The other view swapped its rule source at the view level.
    changed_view_two = csp_replace({"default-src": [SELF], "script-src": ["cdn.evil.example.com"]})(view_two)

    with override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": reordered}):
        report = check_views(
            {"view_one": view_one, "view_two": changed_view_two, "view_three": view_three},
            approvals,
        )

    # Only the view that truly changed its effective configuration is reported.
    assert report.changed == ["view_two"]
    # The reordered policy still corresponds to the original approval record.
    assert report.upheld == ["view_one"]
    assert report.checks["view_one"].review is not None
    assert report.checks["view_one"].review.identity == approvals["view_one"].identity
    # The third view was never approved.
    assert report.unreviewed == ["view_three"]

    comparison = report.checks["view_two"].comparison
    assert comparison is not None
    assert comparison.changed
    assert comparison.altered == ("script-src",)
    assert comparison.added == ()
    assert comparison.removed == ()
    assert report.checks["view_two"].review is not None
    assert "view:csp_replace" in report.checks["view_two"].review.sources
