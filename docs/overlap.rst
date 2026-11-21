Rule overlap checking
=====================

The name matching API answers whether a candidate CPE Name matches a known
CPE Name.  Catalog merging and policy exceptions need the neighbouring
question: can two patterns match the same asset?

``cpe.overlap`` answers that question over a caller-supplied, finite attribute
domain.  It deliberately keeps the CPE logical values distinct:

* ``ANY`` is an explicit wildcard (``*`` / ``ANY``).
* ``NA`` is the CPE not-applicable value (``-`` / ``NA``).
* ``MISSING`` means the attribute was not supplied.  It is not silently
  treated as ``ANY``; a result that depends on it is sent to manual review.

A domain can be a mapping of attribute values (the Cartesian product) or a
list of concrete asset mappings when the attributes are correlated::

    >>> from cpe.overlap import ANY, NA, MISSING, check_overlap
    >>> domain = {
    ...     "vendor": ["acme", "globex"],
    ...     "product": ["gateway", "client"],
    ...     "version": ["1.0", "1.0.0", "2.0"],
    ...     "edition": ["standard", "enterprise"],
    ... }

Spelling variants are different CPE strings
-------------------------------------------

::

    >>> spelling = (
    ...     {"vendor": "acme", "product": "gateway",
    ...      "version": "1.0", "edition": "standard"},
    ...     {"vendor": "acme", "product": "gateway",
    ...      "version": "1.0.0", "edition": "standard"},
    ... )
    >>> result = check_overlap(spelling[0], spelling[1], domain)
    >>> result.status
    'disjoint'
    >>> result.requires_decision
    False

The version attribute is a literal string in CPE.  ``1.0`` and ``1.0.0`` do
not denote the same version for matching purposes, so no concrete witness
exists and the pair can be resolved without a policy decision.

A substantive overlap has a witness
-----------------------------------

::

    >>> left = {"vendor": "acme", "product": "gateway",
    ...         "version": ANY, "edition": ANY}
    >>> right = {"vendor": "acme", "product": "gateway",
    ...          "version": "1.0", "edition": "standard"}
    >>> result = check_overlap(left, right, domain)
    >>> result.status
    'overlap'
    >>> result.witness_display["version"]
    '1.0'
    >>> result.requires_decision
    True

Both rules match the reported witness.  Because they describe contradictory
exceptions, a human must decide which rule takes precedence.

If no witness exists and an attribute cannot be decided (for example a
missing rule value, an empty attribute domain, or a wildcard in an unsupported
position), the status is ``review``.  The result records the unresolved
attributes and an explanation; callers must not turn that result into
``disjoint``.

The main entry points are ``check_overlap``, ``rules_overlap``,
``find_witness`` and ``RuleOverlapChecker``.  A runnable pair of examples is
available in ``examples/rule_overlap_demo.py``.
