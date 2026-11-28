from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.constants import NONCE, NONE, SELF, UNSAFE_INLINE
from csp.inventory import (
    TemplateSnapshot,
    audit_observation_and_release,
    audit_response,
    audit_snapshot,
    effective_directive,
    parse_template,
)
from csp.middleware import CSPMiddleware


def test_one_snapshot_explains_style_pass_without_script_release() -> None:
    snapshot = TemplateSnapshot("<style>.badge { color: red; }</style><script>document.querySelector('.badge').hidden = true;</script>")
    policy = {
        "default-src": [SELF],
        "style-src": [UNSAFE_INLINE],
        "script-src": [NONE],
    }

    script = next(resource for resource in snapshot.resources if resource.purpose == "script")
    report = audit_snapshot(snapshot, policy, approvals={script.content_key: "style"})

    assert report.style_observation.allowed
    assert not report.script_release.allowed
    assert not report.can_release("script")
    assert report.script_release.decisions[0].resolution.effective == "script-src"
    assert report.script_release.decisions[0].resolution.inherited
    assert report.stale_approvals[0].actual_purpose == "script"
    assert report.stale_approvals[0].approved.purpose == "style"
    assert "cannot approve a script release" in report.explain()
    assert "script-src-elem -> script-src" in report.explain()


def test_default_src_and_explicit_empty_are_distinct() -> None:
    template = '<script src="/static/app.js"></script><style>.x{color:red}</style>'
    snapshot = TemplateSnapshot(template, request_url="https://app.example/page")

    inherited = audit_snapshot(snapshot, {"default-src": [SELF]})
    assert inherited.script_release.allowed
    assert not inherited.style_observation.allowed
    assert inherited.script_release.decisions[0].resolution.effective == "default-src"
    assert effective_directive({"default-src": [SELF]}, "script") == "default-src"

    explicit = audit_snapshot(
        snapshot,
        {"default-src": [SELF], "script-src": [], "style-src": []},
    )
    assert not explicit.script_release.allowed
    assert not explicit.style_observation.allowed
    assert explicit.script_release.decisions[0].resolution.explicit_empty
    assert explicit.script_release.decisions[0].resolution.effective == "script-src"


def test_caller_scoped_local_allowlist_does_not_leak_between_callers() -> None:
    snapshot = TemplateSnapshot('<script src="/static/partner.js"></script>')
    policy = {"script-src": [NONE]}
    allowlists = {"alice": ["/static/partner.js"], "bob": ["/static/other.js"]}

    alice = audit_snapshot(snapshot, policy, caller="alice", local_allowlist=allowlists)
    bob = audit_snapshot(snapshot, policy, caller="bob", local_allowlist=allowlists)

    assert alice.script_release.allowed
    assert alice.script_release.decisions[0].matched == "/static/partner.js"
    assert not bob.script_release.allowed


def test_remote_resource_requires_a_caller_qualified_self_origin() -> None:
    snapshot = TemplateSnapshot('<script src="https://cdn.example/app.js"></script>')
    policy = {"default-src": [SELF]}

    blocked = audit_snapshot(snapshot, policy)
    allowed = audit_snapshot(snapshot, policy, self_origins=["https://cdn.example"])

    assert not blocked.script_release.allowed
    assert allowed.script_release.allowed
    assert allowed.script_release.decisions[0].matched == SELF


def test_relative_host_source_uses_the_callers_document_origin() -> None:
    snapshot = TemplateSnapshot('<script src="/static/app.js"></script>')
    policy = {"script-src": ["app.example"]}

    without_origin = audit_snapshot(snapshot, policy)
    with_origin = audit_snapshot(snapshot, policy, request_url="https://app.example/page")

    assert not without_origin.script_release.allowed
    assert with_origin.script_release.allowed
    assert with_origin.script_release.decisions[0].matched == "app.example"


def test_observation_and_release_use_separate_effective_policies() -> None:
    snapshot = TemplateSnapshot("<style>.x{color:red}</style><script>go()</script>")
    result = audit_observation_and_release(
        snapshot,
        observation_policy={"style-src": [UNSAFE_INLINE], "script-src": [UNSAFE_INLINE]},
        release_policy={"style-src": [UNSAFE_INLINE], "script-src": [NONE]},
    )

    assert result.style_observation.allowed
    assert not result.can_release("script")
    assert "Style observation" in result.explain()
    assert "cannot approve a script release" in result.explain()


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF], "style-src": [UNSAFE_INLINE], "script-src": [NONE]}})
def test_response_inventory_uses_the_actual_header() -> None:
    request = RequestFactory().get("/")
    middleware = CSPMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    response = middleware.process_response(
        request,
        HttpResponse("<style>.x{color:red}</style><script>go()</script>"),
    )

    report = audit_response(response)

    assert report.style_observation.allowed
    assert not report.script_release.allowed
    assert report.policy.source == "inline"


def test_inline_script_and_style_attributes_have_their_own_directives() -> None:
    resources = parse_template('<button style="color:red" onclick="go()">go</button>')
    by_purpose = {resource.purpose: resource for resource in resources}

    assert by_purpose["style-attribute"].directive == "style-src-attr"
    assert by_purpose["script-attribute"].directive == "script-src-attr"


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"script-src": [NONE]}})
def test_settings_policy_inherits_the_django_default_src() -> None:
    report = audit_snapshot("<style>.x{color:red}</style>", None)

    assert report.policy.directives["default-src"] == (SELF,)
    assert report.policy.source == "settings:CONTENT_SECURITY_POLICY"
    assert report.style_observation.decisions[0].resolution.effective == "default-src"


def test_nonce_sentinel_uses_the_template_elements_nonce() -> None:
    report = audit_snapshot(
        '<script nonce="abc123">go()</script>',
        {"script-src": [NONCE]},
    )

    assert report.script_release.allowed
    assert report.script_release.decisions[0].matched == str(NONCE)


def test_style_nonce_cannot_authorize_the_moved_script_snippet() -> None:
    snapshot = TemplateSnapshot('<style nonce="same-nonce">.x{color:red}</style><script nonce="same-nonce">go()</script>')
    script = next(resource for resource in snapshot.resources if resource.purpose == "script")
    report = audit_snapshot(
        snapshot,
        {"default-src": [SELF], "style-src": [NONCE]},
        approvals={script.content_key: "style"},
    )

    assert report.style_observation.allowed
    assert not report.script_release.allowed
    assert report.script_release.decisions[0].resolution.effective == "default-src"
    assert report.stale_approvals[0].stale
