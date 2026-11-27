----------------------------------------
B616: sensitive_comparison
----------------------------------------

This plugin detects ordinary equality comparisons (==) involving sensitive
function parameters.  Ordinary equality short-circuits when a difference is
found, which can expose a timing side channel (CWE-208).

The check follows local assignments and tuple/list unpacking, checks each
equality in a chained comparison, and finds comparisons embedded in
short-circuit boolean expressions.  Sources that can be resolved to a
configured sensitive parameter are reported as *definite*; other unresolved
operands are reported separately as *unknown*.

**Config Options:**

.. code-block:: yaml

    sensitive_comparison:
        sensitive_parameters:
            - password
            - token
            - api_key
        allowed_comparison_functions:
            - hmac.compare_digest
            - secrets.compare_digest

No sensitive parameters are enabled by default.  A project must opt in by
naming the formal parameters that hold secrets.  Constants are placeholder
text in the examples; the plugin does not need or include real credentials.

:Example:

.. code-block:: none

    >> Issue: Ordinary equality comparison involving sensitive data:
       definite source(s): secret; unknown source(s): candidate.
       Severity: Medium   Confidence: High
       CWE: CWE-208 (https://cwe.mitre.org/data/definitions/208.html)
       Location: examples/sensitive-comparison.py:8
    7    def direct_short_circuit(secret, candidate, ready):
    8        if ready and secret == candidate:
    9            return True

.. seealso::

    - https://cwe.mitre.org/data/definitions/208.html
    - https://docs.python.org/3/library/hmac.html#hmac.compare_digest

.. versionadded:: 1.8.7
