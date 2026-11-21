Rule Selection
==============

The selection module chooses a deliverable batch of Sigma rules under a field-cost budget.
It is intended for cases where a log platform only onboards a limited set of fields and the
detection team has a reviewed list of risks that must remain observable.

Example
-------

.. code-block:: python

   from sigma.selection import select_rules

   result = select_rules(
       rules,
       required_risks={"attack.t1059", "attack.t1105"},
       field_costs={"CommandLine": 4, "ParentImage": 2, "Image": 1},
       budget=6,
       groups=[["rule-a", "rule-b"]],
       available_collection_conditions={"sysmon", "dns"},
   )

   print(result.selected_keys)
   print(result.total_cost)
   for risk, reason in result.uncovered_risks.items():
       print(risk, reason)

Semantics
---------

* Field costs are charged once for the union of fields used by the selected rules. Fields
  that appear only in unreferenced detection blocks are not charged.
* Coverage is only credited to a rule with a usable log source, non-empty detection logic and a
  condition that resolves against that detection. A rule containing only tags and metadata is
  reported as invalid and can never cover a risk.
* Deprecated and unsupported rules are excluded by default. The same applies to rules with
  parsing errors or unpriced fields; pass ``unknown_field_cost`` to explicitly price unknown
  fields.
* Related rules can be grouped. A group is selected or rejected atomically, and its cost is the
  union of all fields required by its members.
* Collection requirements can be supplied per candidate. Rules requiring a missing collection
  capability are not deliverable. ``required_logsource_fields`` can be used to reject rules whose
  log source lacks a required attribute such as ``product`` or ``service``.
* The default ``exact`` algorithm uses branch-and-bound and maximises the number of required
  risks covered, then minimises cost and rule count. ``exhaustive`` enumerates all subsets for
  small catalogs and is useful as a reference. ``greedy`` is exposed for comparison and does not
  guarantee an optimum.

Result
------

``RuleSelection.selected`` contains the chosen :class:`~sigma.selection.RuleCandidate` objects.
``selected_keys`` identifies them, and ``covered_risks`` contains the required risks that are
covered. Every required risk that is not covered appears in ``uncovered_risks`` with a reason,
while ``diagnostics`` exposes the same information as structured
:class:`~sigma.selection.UncoveredRisk` values. Invalid, uncollectable and group-blocked rules
are listed in ``excluded_candidates``.

API Reference
-------------

.. autofunction:: sigma.selection.select_rules

.. autoclass:: sigma.selection.RuleCandidate
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.selection.RuleSelection
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.selection.UncoveredRisk
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.selection.SigmaRuleSelector
   :members:
   :undoc-members:
   :show-inheritance:

.. autofunction:: sigma.selection.select_rules_exact

.. autofunction:: sigma.selection.select_rules_exhaustive

.. autofunction:: sigma.selection.select_rules_greedy

