.. _inventory-chapter:

==============================
Offline CSP resource inventory
==============================

``csp.inventory`` answers a narrow release question without starting a server or a browser: for a
rendered template snapshot, which resources are declared, which CSP directive actually applies to
each one, and what did the response allow?

The inventory keeps the template classification, the effective policy, and the CSP fallback chain
together. That is important when a snippet moves from a ``<style>`` element to a ``<script>``
element: the browser now evaluates ``script-src-elem``, then ``script-src``, then ``default-src``.
A successful style observation says nothing about that script release.


Inspecting a snapshot
=====================

.. code-block:: python

    from csp.constants import NONE, SELF, UNSAFE_INLINE
    from csp.inventory import TemplateSnapshot, audit_snapshot

    snapshot = TemplateSnapshot(
        "<style>.badge { color: red; }</style>"
        "<script>document.querySelector('.badge').hidden = true;</script>"
    )
    report = audit_snapshot(
        snapshot,
        {
            "default-src": [SELF],
            "style-src": [UNSAFE_INLINE],
            "script-src": [NONE],
        },
    )

    assert report.style_observation.allowed
    assert not report.script_release.allowed
    assert not report.can_release("script")
    print(report.explain())

Each decision records the requested directive (for example ``script-src-elem``), the directive that
actually applied (for example ``script-src``), the fallback chain, the matched source, and the
reason. An explicitly empty directive is kept as present, so it blocks resources and does not fall
through to ``default-src``.


Caller-scoped local sources
===========================

``'self'`` is relative to the document origin, not to the machine running the check. Pass
``request_url`` or ``self_origins`` when a policy source or a relative URL needs that context. A
``local_allowlist`` is also caller-scoped: when it is a mapping keyed by caller, a lookup for one
caller never borrows another caller's entries.

.. code-block:: python

    report = audit_snapshot(
        '<script src="/static/partner.js"></script>',
        {"script-src": [NONE]},
        caller="alice",
        local_allowlist={"alice": ["/static/partner.js"], "bob": []},
    )
    assert report.script_release.allowed


Approval records
================

An approval record may still label a moved snippet as a style resource. Pass that record as
``approvals``; the inventory compares the recorded purpose with the purpose declared by the actual
snapshot. A stale purpose is reported as an ``ApprovalMismatch`` and prevents the matching category
from being approved for release.

When both a report-only policy and the enforced policy are available, use
``audit_observation_and_release``. The two results share the same ``TemplateSnapshot`` but are
evaluated against their own effective policies, so a report-only style pass cannot be reused as an
enforced script approval.

.. code-block:: python

    from csp.inventory import audit_observation_and_release

    result = audit_observation_and_release(
        snapshot,
        observation_policy={"style-src": [UNSAFE_INLINE], "script-src": [UNSAFE_INLINE]},
        release_policy={"style-src": [UNSAFE_INLINE], "script-src": [NONE]},
    )
    assert result.style_observation.allowed
    assert not result.can_release("script")

The response-based helpers ``audit_response``, ``snapshot_from_response``, and
``CSPMiddleware.audit_template`` read the policy from the actual ``Content-Security-Policy`` or
``Content-Security-Policy-Report-Only`` header, including directives added by the middleware.
