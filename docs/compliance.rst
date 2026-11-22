Compliance review
=================

Jinja templates can be reviewed statically before they are committed.  The
review answers one question: on every reachable rendering path that outputs a
managed section, is the one host-provided marker source also output?

The reviewer never renders a template.  It parses the AST, walks the reachable
``if``/``for``/``include``/``extends`` paths, and resolves block overrides.
Literal copies of the marker text in a template body are ignored.  A marker
must come from the configured host variable, host template, or host call.

Configuration
-------------

The caller lists the managed sections and the single accepted marker source.

.. code-block:: json

    {
      "managed_sections": [
        {"name": "incident", "blocks": ["incident"]},
        {"name": "impact", "variables": ["impact"]},
        {"name": "timeline", "literals": ["data-managed=timeline"]}
      ],
      "marker": {"kind": "template", "value": "_host_notice.html"},
      "templates": ["templates/incident.html"],
      "search_paths": ["templates"]
    }

A section may use one or more selectors:

``variables``
    Output expressions that load one of these names.
``blocks``
    Template blocks with one of these names.  The effective override is
    checked, not an unreachable parent default.
``literals``
    Static text fragments in template output.
``templates``
    Statically included templates that render the section.

The marker source kind is ``variable``, ``template``, or ``call``.  A literal
marker source is rejected: text in the template body never satisfies the
requirement.

The review handles plaintext templates and this layout surface:

* ``extends`` chains, blocks, defaults, overrides, and ``super()``
* static ``include`` references
* local and statically imported macros
* ``if`` and ``for`` paths, including loops that may run zero times

Dynamic ``extends``, ``include``, and ``import`` expressions, dynamic section
subscripts, and unresolved output calls produce manual-review findings.  A
dynamic include is treated as possibly containing the marker, so it does not
produce a false hard failure.

Command line
------------

.. code-block:: console

    python -m jinja2.compliance --config compliance.json
    python -m jinja2.compliance --config compliance.json --json

The command exits with ``0`` when every path passes, ``1`` when a path fails,
and ``2`` when manual review is needed or the configuration is invalid.

A pre-commit hook can run the same command:

.. code-block:: yaml

    - repo: local
      hooks:
        - id: incident-template-compliance
          name: incident template compliance
          entry: python -m jinja2.compliance --config compliance.json
          language: system
          pass_filenames: false

Python API
----------

.. code-block:: python

    from jinja2.compliance import ManagedSection
    from jinja2.compliance import MarkerSource
    from jinja2.compliance import review_file

    result = review_file(
        "templates/incident.html",
        managed_sections=[ManagedSection.block("incident")],
        marker=MarkerSource.template("_host_notice.html"),
        search_path="templates",
    )

    print(result.format_text())

``ReviewResult.findings`` contains errors and manual-review findings.  Each
missing-marker finding carries a tuple of reachable path conditions, so a
failure caused by an empty list includes ``items is empty`` in its output.

Acceptance counterexample
-------------------------

``examples/compliance`` contains a template whose ordinary preview has the
host marker, while the empty-list path omits it.  The review reports
``E_MISSING_MARKER`` and the reachable path ``items is empty``.
