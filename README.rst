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

Review backend
~~~~~~~~~~~~~~

The ``cvss.review`` module adds a review layer on top of the library. It
accepts a vector together with per-metric provenance (source trust levels:
``unverified``, ``upstream_default``, ``confirmed``) and decides, driven by
an explicit ``ReviewPolicy``, whether the record can be published directly
and which evidence is still missing. Inherited environmental metrics report
the default values that apply to them, and CVSS 3.x and CVSS 4.0 metric sets
are explained with their own version-specific fields.

.. code-block:: python

    from cvss import ReviewPolicy, review_vector


    policy = ReviewPolicy(
        required_trust={"base": "confirmed", "environmental": "upstream_default"},
        default_trust="unverified",
    )
    report = review_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        {"AV": "confirmed", "AC": "upstream_default"},
    )
    print(report.decision)           # "hold"
    print(report.missing_evidence)   # metrics that still need evidence
    print(report.explain())          # human-readable review sheet

See ``review_sample.py`` for a full example reviewing two same-score
incidents with different metric provenance.

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
