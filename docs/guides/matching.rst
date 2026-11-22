Matching Events Against Rules
==============================

The ``sigma.matching`` module allows you to evaluate log events directly against Sigma rules in
Python, without converting rules to a query language first. It is useful for testing, rapid
prototyping, and offline analysis where query-language conversion is not required.

.. admonition:: Performance Note

   pySigma's matching engine is **not designed for high-throughput production workloads**. It is a
   pure-Python interpreter optimised for correctness and ease of use. If your use case demands
   performant, production-grade event matching, consider the Rust-based Sigma engine
   `rsigma <https://github.com/timescale/rsigma>`_, which is purpose-built for speed.

Overview
--------

The matching pipeline has three layers:

1. **Event** — wraps a raw log record with a timestamp and logsource descriptor.
2. **SigmaMatcher** — orchestrates matching: routes events to the right rules and handles
   correlation rule state.
3. **SigmaMatch** — the result returned when a rule fires.

Quick Start
-----------

Load a rule collection, construct a :class:`~sigma.matching.SigmaMatcher`, and call
:meth:`~sigma.matching.SigmaMatcher.match` for each incoming event:

.. code-block:: python

    from datetime import datetime, timezone
    from sigma.collection import SigmaCollection
    from sigma.matching import Event, EventLogSource, SigmaMatcher

    rules_yaml = """
    title: Suspicious PowerShell Encoded Command
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains: '-EncodedCommand'
        condition: selection
    """

    collection = SigmaCollection.from_yaml(rules_yaml)
    matcher = SigmaMatcher(collection)

    event = Event(
        timestamp=datetime.now(timezone.utc),
        logsource=EventLogSource(category="process_creation", product="windows"),
        data={
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand dABlAHMAdAA=",
        },
    )

    matches = matcher.match(event)
    for m in matches:
        print(f"Rule fired: {m.rule.title}")

Creating Events
---------------

An :class:`~sigma.matching.Event` carries three required fields:

* ``timestamp`` — a timezone-aware :class:`datetime` indicating when the event occurred.
* ``logsource`` — an :class:`~sigma.matching.EventLogSource` with optional ``category``,
  ``product``, and ``service`` fields that mirror the Sigma rule ``logsource`` block.
* ``data`` — a flat ``dict[str, Any]`` containing the parsed event fields.

An optional ``raw`` string can be supplied when keyword (field-less) detection items need to
search the raw log text:

.. code-block:: python

    event = Event(
        timestamp=datetime.now(timezone.utc),
        logsource=EventLogSource(product="windows", service="security"),
        data={"EventID": 4625, "TargetUserName": "Administrator"},
        raw="...original log line...",
    )

If ``raw`` is omitted, the matcher falls back to a JSON serialisation of ``data`` for keyword
searches.

Logsource Routing
-----------------

:class:`~sigma.matching.SigmaMatcher` dispatches each event only to rules whose ``logsource``
block is *contained by* the event's logsource. This mirrors how Sigma logsource matching works:
a rule with ``product: windows`` will fire for an event with both ``product: windows`` and
``service: security``, but not the other way around.

.. code-block:: python

    # This event matches rules that require only `product: windows`
    # as well as rules that require both `product: windows, service: security`.
    event = Event(
        timestamp=datetime.now(timezone.utc),
        logsource=EventLogSource(product="windows", service="security"),
        data={"EventID": 4624},
    )

Applying a Processing Pipeline
-------------------------------

Pass a :class:`~sigma.processing.pipeline.ProcessingPipeline` to
:class:`~sigma.matching.SigmaMatcher` to apply field-name mappings or other transformations
before matching:

.. code-block:: python

    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation
    from sigma.processing.conditions import LogsourceCondition

    pipeline = ProcessingPipeline(
        transformations=[
            FieldMappingTransformation({"CommandLine": "process.command_line"}),
        ]
    )

    matcher = SigmaMatcher(collection, pipeline=pipeline)

    event = Event(
        timestamp=datetime.now(timezone.utc),
        logsource=EventLogSource(category="process_creation", product="windows"),
        data={"process.command_line": "powershell.exe -EncodedCommand dABlAHMAdAA="},
    )

    matches = matcher.match(event)

Bulk Matching
-------------

When processing a stream or batch of events, use
:meth:`~sigma.matching.SigmaMatcher.bulk_match` to iterate over all events and collect every
:class:`~sigma.matching.SigmaMatch` in one call:

.. code-block:: python

    events = [
        Event(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            logsource=EventLogSource(category="process_creation", product="windows"),
            data={"CommandLine": "cmd.exe /c whoami"},
        ),
        Event(
            timestamp=datetime(2024, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
            logsource=EventLogSource(category="process_creation", product="windows"),
            data={"CommandLine": "powershell.exe -EncodedCommand dABlAHMAdAA="},
        ),
    ]

    all_matches = matcher.bulk_match(events)
    print(f"{len(all_matches)} match(es) found")

Working with Matches
--------------------

Each :class:`~sigma.matching.SigmaMatch` exposes:

* ``rule`` — the :class:`~sigma.rule.rule.SigmaRule` (or correlation rule) that fired.
* ``events`` — the list of :class:`~sigma.matching.Event` objects that caused the match.
* ``timestamp`` — the timestamp of the triggering event.
* ``group_values`` — for correlation rules, the ``group-by`` field values that formed the
  matching group (``None`` for plain rules).

.. code-block:: python

    for m in matches:
        print(f"Rule   : {m.rule.title}")
        print(f"At     : {m.timestamp}")
        print(f"Events : {len(m.events)}")
        if m.group_values:
            print(f"Group  : {m.group_values}")

Using as a Context Manager
--------------------------

:class:`~sigma.matching.SigmaMatcher` implements the context manager protocol, which is useful
when integrating with resource-managed environments:

.. code-block:: python

    with SigmaMatcher(collection) as matcher:
        for event in event_stream:
            for m in matcher.match(event):
                handle_match(m)

Correlation Rules
-----------------

Correlation rules are handled transparently. When a base rule fires, the resulting
:class:`~sigma.matching.SigmaMatch` is forwarded internally to any
:class:`~sigma.matching.SigmaCorrelationRuleMatcher` that references that base rule by name.
The correlation matcher maintains a sliding time window and emits a new
:class:`~sigma.matching.SigmaMatch` whenever its condition is satisfied.

.. code-block:: python

    rules_yaml = """
    ---
    title: Failed Logon
    name: failed_logon
    status: test
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4625
        condition: selection
    ---
    title: Brute Force Detection
    name: brute_force
    status: test
    type: event_count
    rules:
        failed_logon: '*'
    group-by:
        - TargetUserName
    timespan: 5m
    condition:
        gte: 10
    """

    collection = SigmaCollection.from_yaml(rules_yaml)
    matcher = SigmaMatcher(collection)

    for event in event_stream:
        for m in matcher.match(event):
            if m.rule.name == "brute_force":
                print(f"Brute force against: {m.group_values}")

Two constructor parameters control memory use for correlation state:

* ``max_events_per_match`` (default ``100``) — caps the number of events stored per
  correlation match to avoid unbounded memory growth on high-cardinality rules.
* ``max_correlation_state`` (default ``None``, unlimited) — limits the total number of
  entries retained in the sliding window per group key.

Offline Release-Order Verification
----------------------------------

When a correlation rule is migrated from one set of base rules to another, deploying the
correlation rule before its new base rules creates a window in which the signal cannot be
decided at all. :class:`~sigma.matching.ReleaseOrderVerifier` compares the two possible
rollout orders offline and renders an effectiveness table for the switch hour:

.. code-block:: python

    from datetime import datetime, timedelta, timezone
    from sigma.matching import (
        Event,
        EventLogSource,
        MarkerEvent,
        ReleaseOrderVerifier,
    )

    old_rules = "... YAML with login_old, access_old and demo_signal ..."
    new_rules = "... YAML with login_new, access_new and demo_signal ..."
    effective_at = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
    logsource = EventLogSource(category="auth", product="test")

    markers = [
        MarkerEvent(
            "login_marker",
            Event(
                effective_at + timedelta(minutes=1),
                logsource,
                {"event": "login", "user": "alice"},
            ),
        ),
        MarkerEvent(
            "access_marker",
            Event(
                effective_at + timedelta(minutes=1, seconds=30),
                logsource,
                {"event": "access", "user": "alice"},
            ),
        ),
    ]

    report = ReleaseOrderVerifier(
        old_rules,
        new_rules,
        effective_at,
        markers,
        rollout_minutes=60,
        phase_minutes=30,
    ).verify()
    print(report.to_table())

The table lists both orders. ``BASE_FIRST`` installs new base rules while the old correlation
is still active, switches the correlation afterwards and retires the old rules at the end.
``CORRELATION_FIRST`` switches the correlation before the new base rules exist; the affected
signal is shown as ``GAP`` and the summary reports the first minute at which it is lost.

The separate ``compile`` column makes the distinction explicit: a stage can compile cleanly and
still show ``GAP`` for a signal whose base-rule dependency is undeployed.

The status of each signal is one of:

* ``OK`` — all dependencies are present and the marker events produce the signal.
* ``NO FIRE`` — dependencies are complete, but the marker events do not produce the signal.
* ``GAP`` — a referenced base rule is undeployed, so the signal cannot be fully decided even
  though every deployed rule compiles.
* ``MISSING`` — the correlation rule itself is not deployed in this stage.
* ``ERR`` — a deployed rule fails to compile.

The marker events are replayed against each stage snapshot with the normal
:class:`~sigma.matching.SigmaMatcher`, so dependency findings and observed signal behaviour
come from the same parser and matching engine as production checks.
