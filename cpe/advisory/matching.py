# -*- coding: utf-8 -*-

"""
CPE 2.3 name-matching helpers used by the slot advisory engine.

The CPE package already implements the official 2.3 superset relation.  This
module keeps the advisory layer on that implementation instead of comparing
version strings by hand.  It also normalises every bound name to WFN before
matching so URI, formatted-string and WFN inputs behave the same way.
"""

from cpe.cpe import CPE
from cpe.cpe2_3_wfn import CPE2_3_WFN
from cpe.cpeset2_3 import CPESet2_3


_WFN_CACHE = {}


def as_wfn(cpe_string):
    """Return a cached ``CPE2_3_WFN`` for any supported bound CPE name."""

    if not isinstance(cpe_string, str):
        raise TypeError("CPE name must be a string")

    key = cpe_string.strip()
    cached = _WFN_CACHE.get(key)
    if cached is not None:
        return cached

    parsed = CPE(key)
    wfn = CPE2_3_WFN(parsed.as_wfn())
    _WFN_CACHE[key] = wfn
    return wfn


def canonical(cpe_string):
    """Return the canonical WFN string for a bound CPE name."""

    return as_wfn(cpe_string).cpe_str


def cpe_equal(left, right):
    """True when two bound CPE names denote the same WFN."""

    return CPESet2_3.cpe_equal(as_wfn(left), as_wfn(right))


def condition_matches(condition_cpe, component_cpe):
    """
    True when the advisory condition (source) is a superset of the component.

    This is the same orientation used by ``CPELanguage2_3._fact_ref_eval``:
    the condition is the pattern and the inventory component is the known
    instance.
    """

    return CPESet2_3.cpe_superset(
        as_wfn(condition_cpe), as_wfn(component_cpe))
