CVSS
====

This Python package contains CVSS v2, v3 and v4 computation utilities and
interactive calculator (for v2 and v3 only) compatible with Python 3. CVSS
(Common Vulnerability Scoring System) is an standardized method for rating
the severity of security issues on a scale from 0 (no impact) to 10 (critical).

The library is tested on all currently-supported Python versions available
via GitHub Actions but it is simple enough to run on even older versions.

Installation
------------

::

    # pip install cvss

Usage
-----

Library
~~~~~~~

.. code-block:: python

    from cvss import CVSS2, CVSS3, CVSS4


    vector = 'AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M'
    c = CVSS2(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())
    print(c.severities())

    print()

    vector = 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'
    c = CVSS3(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())
    print(c.severities())

    print()

    vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N'
    c = CVSS4(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())
    print(c.severities())

Sample output:

::

   AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M
   AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/CDP:L/TD:H/AR:M
   (5.0, 4.0, 4.6)
   ('Medium', 'Medium', 'Medium')

   CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X
   CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L
   (6.5, 6.0, 5.3)
   ('Medium', 'Medium', 'Medium')

   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N
   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N
   (9.9,)
   ('Critical',)

Remediation planning
~~~~~~~~~~~~~~~~~~~~

The CVSS4 scorer includes an in-memory planner for choosing a small set of
remediations under a maintenance-window limit. Actions describe metric
transformations, a cost, and the actions they conflict with. Every feasible
subset is turned into a CVSS4 vector and scored by the normal CVSS4 kernel, so
non-additive metric interactions are reflected in the result.

.. code-block:: python

    from cvss import CVSS4, CVSS4Action, CVSS4Planner

    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    actions = [
        CVSS4Action("network", {"AV": "A"}, cost=3, conflicts=["crypto"]),
        CVSS4Action("mfa", {"PR": "H"}, cost=2),
        CVSS4Action("crypto", {"VC": "L"}, cost=4),
        CVSS4Action("integrity", {"VI": "L"}, cost=3),
    ]
    planner = CVSS4Planner(
        base,
        actions,
        max_actions=2,
        fixed_metrics={"SC": "H", "SI": "H", "SA": "H"},
        release_threshold=9.0,
    )
    for plan in planner.plan():
        print(plan["id"], plan["score"], plan["cost"])
        print(plan["objective_vector"], CVSS4(plan["vector"]).base_score)

The objectives are ``(residual score, cost)``, both minimised. A plan is
non-dominated only when no feasible plan is at least as good on both objectives
and strictly better on one. Each plan includes ``vector``, ``score``, ``cost``,
``objectives``, ``objective_vector``, ``rationale``, and ``dominated_by``.
``plan.recompute_objectives()`` re-runs the scoring kernel on
``plan["vector"]``, so the objective vector is always reproducible.

If a release threshold is supplied, ``planner.best()`` restricts its choice to
compliant plans when any exist. ``planner.all_plans`` holds every feasible
candidate and ``planner.pareto_front`` is the frontier. Use ``min_actions=2``
(or ``exact_actions=2``) when all plans must fill the window with two changes.
Fixed metrics may be
supplied as a sequence of names or as a mapping of names to their required
effective values; actions that attempt to change them are reported in
``planner.rejected_actions``.

Interactive calculator
~~~~~~~~~~~~~~~~~~~~~~

For interactive calculator run the following:

::

    $ cvss_calculator

For help on the calculator options run:

::

    $ cvss_calculator --help

Testing
-------

For extensive testing, the test vectors were generated using official
JavaScript generators and `cvsslib <https://github.com/ctxis/cvsslib>`_.

To run all tests using all supported versions of Python 2 and Python 3 installed:

::

    $ tox
    $ tox -e py311   # Run tests using a specific version of Python
