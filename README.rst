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

Interactive calculator
~~~~~~~~~~~~~~~~~~~~~~

For interactive calculator run the following:

::

    $ cvss_calculator

For help on the calculator options run:

::

    $ cvss_calculator --help

Offline queue audit
~~~~~~~~~~~~~~~~~~~

The `cvss.queue_audit` module audits a queue of CVSS-scored tickets
offline. It keeps the submission-time version and vector of every ticket,
derives a service priority from configurable tiers that are comparable
across CVSS versions, and logs every queue movement with its reason.

.. code-block:: python

    from datetime import datetime, timedelta

    from cvss.queue_audit import QueueAudit

    tiers = [
        {"name": "P1-critical", "min_score": 9.0, "max_score": 10.0,
         "versions": ["3.0", "3.1", "4.0"]},
        {"name": "P2-high", "min_score": 7.0, "max_score": 8.9,
         "versions": ["3.0", "3.1", "4.0"]},
        # ... CVSS 2.0 omitted: legacy v2-only tickets are held in a
        # manual-handling slot outside the automatic queue.
    ]
    now = datetime(2026, 11, 26, 9, 0, 0)
    audit = QueueAudit(tiers, clock=lambda: now)  # fixed clock for replays

    audit.submit("T1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    audit.submit("T2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    audit.correct("T2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    audit.pin("T2", approver="handler-alice",
              expires_at=now + timedelta(hours=2))
    print(audit.queue())
    print(audit.report())

Only corrections that genuinely cross a tier boundary reorder the queue;
within a tier, equal scores keep the existing queue order. Approved
short-term jumps (pins) expire against the supplied clock and the ticket
then returns to its natural position.

Testing
-------

For extensive testing, the test vectors were generated using official
JavaScript generators and `cvsslib <https://github.com/ctxis/cvsslib>`_.

To run all tests using all supported versions of Python 2 and Python 3 installed:

::

    $ tox
    $ tox -e py311   # Run tests using a specific version of Python
