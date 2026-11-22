Offline Change Attribution
==========================

Before converting a rule collection, you can replay a small, explicit event set directly
against the rules with :mod:`sigma.matching` and compare which notification queues would
actually be reached.  This is an offline review: no backend query is generated and no
network resource is contacted.

The review is designed for changes that are easy to get wrong in a migration:

* a rule is archived or retired;
* conversion cannot cover a rule in the target environment;
* a rule keeps matching, but its notification level changes.

These effects are kept separate.  In particular, losing the phone queue while the
backend ticket queue still fires is a queue-level loss, not the loss of the whole alert.

Rule Changes
------------

A :class:`~sigma.matching.RuleChange` targets a rule by object, name, title, or UUID.
The three primary kinds are:

.. code-block:: python

   from sigma.matching import RuleChange

   changes = [
       RuleChange.archived("legacy_rule", label="archive-legacy"),
       RuleChange.conversion_unsupported("windows_rule", label="no-sysmon-pipeline"),
       RuleChange.level_changed("powershell_rule", "medium", label="downgrade-ps"),
   ]

Archive and conversion-coverage changes remove the rule from the reviewed candidate.
Level changes keep the rule in the candidate and only affect routing.

Routing Decisions
-----------------

Routing is supplied by the maintainer.  A :class:`~sigma.matching.RoutingDecision`
contributes one queue when its constraints match a rule.  Decisions are additive.

.. code-block:: python

   from sigma.matching import QueueKind, RoutingDecision, RoutingPolicy

   routing = RoutingPolicy([
       RoutingDecision("phone", min_level="high"),
       RoutingDecision("ticket", min_level="informational", kind=QueueKind.TICKET),
   ])

A compact mapping is also accepted.  Each key is a queue and each value describes the
levels that reach it:

.. code-block:: python

   routing = RoutingPolicy({
       "phone": ["high", "critical"],
       "ticket": ["informational", "low", "medium", "high", "critical"],
   })

Queue names such as ``ticket``, ``backend``, ``itsm``, and ``work_item`` are inferred as
``QueueKind.TICKET`` when no kind is supplied.  The severity-to-queue orientation is
accepted too:

.. code-block:: python

   routing = RoutingPolicy({
       "high": ["phone", "ticket"],
       "medium": ["ticket"],
   })

Replay Comparison
-----------------

For a quick check of actual delivery without a baseline, use
:func:`~sigma.matching.notified_queues`; it returns the queue set for each event in
order.

:func:`~sigma.matching.attribute_changes` consumes the baseline collection, the events,
the explicit changes, and the routing policy.  It returns an
:class:`~sigma.matching.AttributionReport`.

.. code-block:: python

   from datetime import datetime, timezone

   from sigma.collection import SigmaCollection
   from sigma.matching import Event, EventLogSource, attribute_changes

   collection = SigmaCollection.from_yaml(rules_yaml)
   events = [
       Event(
           timestamp=datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc),
           logsource=EventLogSource(category="process_creation", product="windows"),
           data={"CommandLine": "mimikatz.exe"},
       )
   ]

   report = attribute_changes(collection, events, changes, routing)
   print(report.summary())

Event mappings with ``timestamp``, ``logsource``, and ``data`` keys are accepted in place
of :class:`~sigma.matching.Event` objects, which makes JSON replay fixtures easy to load.

Each event result exposes:

* ``baseline_queues`` and ``candidate_queues`` — the queues actually notified before and
  after the changes;
* ``lost_queues`` and ``added_queues``;
* ``baseline_queue_sources`` and ``candidate_queue_sources`` — the rule names that kept
  each queue alive;
* ``status`` — for example ``notification_lost``, ``ticket_lost``, ``alert_lost``.

The ``alert_lost`` flag is true only when the candidate has no queues at all.  A missing
phone queue with a retained ticket queue therefore reports ``notification_lost`` and is
never collapsed into a complete alert loss.  ``report.losses`` is the per-queue view;
``report.alert_losses`` contains one event-level entry for each complete alert loss.

Minimal Combinations
--------------------

The report evaluates every single change and, by default, every pair.  A loss that needs
two changes together is reported as the smallest reproducible set:

.. code-block:: python

   report = attribute_changes(
       collection,
       events,
       [change_a, change_b],
       routing,
   )
   loss = report.losses[0]
   assert loss.queue == "phone"
   assert loss.requires_combination
   assert loss.minimal_causes == (("downgrade-a", "archive-b"),)

``report.minimal_combinations`` contains the same information in review-friendly form.
When an entire alert disappears, the entry has ``queue=None`` and
``alert_lost=True``.  Set ``max_combination_size=None`` to search combinations larger
than two; the search is capped by ``max_combination_replays``.

Replay Fixtures
---------------

The test data under ``tests/files/attribution/`` contains two replay controls:

* ``single_loss`` — each change loses a queue on its own;
* ``pair_loss`` — neither change loses the phone queue alone, but together they do.

Use :func:`~sigma.matching.compare_replay` when the candidate rule collection already
exists and no change list is needed.
