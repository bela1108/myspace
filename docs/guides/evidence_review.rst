Evidence Review
===============

Some SOC rules depend on restricted telemetry (for example a payroll table or an
HR-only actor identifier), while an external department may only be told the public
fields that actually supported a conclusion.  ``sigma.evidence`` adds an offline
review step between conversion and the match output.  It does not execute a query and
does not mutate the rule or the match.

The review has three inputs:

* the conversion side, usually a :class:`~sigma.evidence.ConversionRecord` that keeps
  the processing pipeline field mappings next to the generated queries;
* the matching side, a :class:`~sigma.matching.SigmaMatch`;
* an :class:`~sigma.evidence.Audience` policy supplied by the caller.  The policy
  lists the fields the audience may see and the facts that may be projected into a
  public explanation.

Provenance
----------

Field aliases and derived fields are resolved transitively before an external
statement is released.  A conversion mapping such as ``payroll_table ->
data.table_name`` means a fact about ``data.table_name`` still depends on the
restricted ``payroll_table`` source.  A correlation alias is treated as the union of
the fields it maps to across the referenced rules.  A derived field registered with
:meth:`FieldProvenance.add_derived` requires *all* of its sources.

This is fail-closed: if one source is restricted, the statement is withheld for that
audience and its restricted source is recorded for internal review.  If a source is
not present in the matched telemetry, the statement is marked ``pending`` and the
report can suspend publication (controlled by ``suspend_on_insufficient``).

Reports
-------

Two views are available from an :class:`~sigma.evidence.EvidenceReport`:

* ``as_internal_dict()`` (or ``report.internal_report``) contains every finding,
  resolved source, missing telemetry field and restricted field.  This is the SOC
  audit trail.
* ``as_public_dict()`` (or ``report.external_report``) contains only independently
  confirmable conclusions.  Restricted field names and pending evidence are not
  disclosed.

The same match therefore produces different reports for different audiences without
re-evaluating the alert.

Example
-------

.. code-block:: python

   from sigma.evidence import (
       Audience,
       ConversionRecord,
       EvidenceClaim,
       EvidenceReviewer,
       FieldProvenance,
   )

   conversion = ConversionRecord.capture(backend, rule)
   provenance = FieldProvenance()
   provenance.add_derived("endpoint", ["host", "ip"])

   claims = [
       EvidenceClaim(
           id="restricted_export",
           statement="The restricted payroll table was exported",
           sources={"action", "data.table_name"},
       ),
       EvidenceClaim(
           id="export_observed",
           statement="An export action was observed",
           sources={"action"},
       ),
   ]

   reviewer = EvidenceReviewer(provenance=provenance)
   internal = reviewer.review(
       match, Audience.internal("soc-internal"), claims=claims, conversion=conversion
   )
   external = reviewer.review(
       match,
       Audience.external(
           "external-partner",
           {"action", "src_ip"},
           {
               "restricted_export": None,
               "export_observed": "An export action was observed.",
           },
       ),
       claims=claims,
       conversion=conversion,
   )

   print(internal.to_text())               # includes pending / restricted sources
   print(external.to_text(view="public"))  # confirmed conclusions only

A complete fictional-telemetry example is available in
``examples/evidence_audience_demo.py``.
