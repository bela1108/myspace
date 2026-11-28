.. _audit:

Reviewing and auditing policies
===============================

django-csp ships an optional audit helper, :mod:`csp.audit`, for teams that
review and approve Content Security Policies before they ship. It builds a
stable *review identity* from the actually parsed rules of a policy, so purely
cosmetic changes, like reordering directive declarations, do not invalidate an
existing approval. The raw response header string is never used as the
identity.

Recording an approval
---------------------

Use :func:`~csp.audit.approve_view` to record the effective policy a view
currently emits. The returned :class:`~csp.audit.PolicyReview` keeps the
normalized directives alongside the rule sources (settings and any view
decorators) that produced them::

    from csp.audit import approve_view

    approvals = {
        "my_view": approve_view(my_view),
    }

Checking views against approvals
--------------------------------

:func:`~csp.audit.check_views` runs views through the middleware, reviews the
parsed policy on each response, and compares it against the stored approvals::

    from csp.audit import check_views

    report = check_views({"my_view": my_view}, approvals)
    report.changed     # views whose effective configuration really changed
    report.upheld      # views still matching their approval record
    report.unreviewed  # views without an approval record

Each entry in ``report.checks`` exposes a
:class:`~csp.audit.ReviewComparison` detailing ``added``, ``removed`` and
``altered`` directives when a policy drifted from its approval.

Lower-level helpers
-------------------

:func:`~csp.audit.parse_policy` and :func:`~csp.audit.normalize_config`
normalize header strings and ``DIRECTIVES``-style config mappings into the
same canonical form, :func:`~csp.audit.policy_identity` fingerprints it, and
:func:`~csp.audit.review_response` builds a :class:`~csp.audit.PolicyReview`
straight from a response.
