Sigma Filters
=============

Sigma filters remove known false positives from the results of one or more rules. A filter is
loaded from its own YAML document. The legacy ``rules`` field is still accepted and may be
``any``, a single rule ID/name, or a list of rule IDs/names. The same value can also be supplied
under ``scope``:

.. code-block:: yaml

   title: Exclude SYSTEM from process creation
   logsource:
     category: process_creation
     product: windows
   filter:
     rules:
       - 22222222-2222-2222-2222-222222222222
     selection:
       User: SYSTEM
     condition: not selection

The filter's ``selection`` belongs to the filter, even if an applied rule also has a detection
named ``selection``. Filter detections are copied into a namespace derived from the filter
material, and their condition is rewritten into that namespace. A filter condition therefore
cannot accidentally negate a same-named rule detection.

Inspecting applicability
------------------------

``SigmaFilter.filter_scope`` is an inspectable applicability contract. It contains the declared
rule references, the logsource, the condition and a resolution of every condition token against
the filter's own detections:

.. code-block:: python

   scope = sigma_filter.filter_scope
   scope.rule_references
   scope.resolve_detections()       # {"selection": ("selection",)}
   scope.resolve(rule_collection.rules)  # [(rule_object, reference), ...]
   sigma_filter.applies_to(rule)

``resolve()`` binds the declaration to the exact rule objects supplied by the caller. This uses
object identity and does not rely on looking a reference up in a collection, so two rules that
share a title, name or detection identifier remain distinguishable.

Provenance after conversion
---------------------------

Each application is recorded on the rule as a ``SigmaFilterApplication``. It keeps the filter
source location, the exact rule object, the matched reference, the allocated namespace and the
rewritten condition. Records survive ``SigmaCollection.merge`` and are appended for every
filter material, including negated filters.

After conversion, ``SigmaCollection.filter_report()`` pairs each rule's converted queries with
its filter applications. The following example has two rules that both define ``selection``;
only the second rule is targeted by the filter:

.. code-block:: python

   collection = SigmaCollection.load_ruleset([Path("materials")])
   queries = backend.convert(collection)

   for entry in collection.filter_report():
       print(entry["rule"]["title"], entry["conversion_result"])
       for application in entry["applications"]:
           print(application["source"], application["source_condition"])

The report shows that the first rule still alerts without an exception and that the second
rule's exception came from the filter file identified by ``application["source"]``. The same
information is available on a rule as ``rule.applied_filters``, ``rule.filter_applications`` or
``rule.get_filter_provenance()``.
