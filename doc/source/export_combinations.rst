Export label combinations
=========================

The export-combination review is opt-in.  The caller supplies one or more
label pairs that must not reach the same outbound recipient together.  Bandit
then evaluates finite Python expressions at export calls, including static
tuples, unpacking, bounded same-module return values, and several submissions.

Run the dedicated report with::

    bandit-export-combinations --protect A,B --protect C,D report.py

The same check is available as the ``B616`` plugin.  Supply the protected
pairs in the Bandit configuration::

    export_combinations:
      protected:
        - [A, B]

A result is ``co-executable`` only when both labels can reach an overlapping
recipient from export points that can run together.  Opposite branches of one
condition are ``mutually-exclusive``, disjoint recipients are reported as
``independent-recipients``, and unresolved values remain ``unprovable`` with
the reason attached.

See ``examples/export-combinations-*.py`` for the three judgments.
