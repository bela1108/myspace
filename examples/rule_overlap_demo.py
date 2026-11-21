#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Demonstrate finite-domain CPE rule overlap checking."""

from __future__ import print_function

from cpe.overlap import ANY, check_overlap


DOMAIN = {
    "vendor": ["acme", "globex"],
    "product": ["gateway", "client"],
    "version": ["1.0", "1.0.0", "2.0"],
    "edition": ["standard", "enterprise"],
}


SPELLING_VARIANTS = (
    {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": "standard",
    },
    {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0.0",
        "edition": "standard",
    },
)


SUBSTANTIVE_OVERLAP = (
    {
        "vendor": "acme",
        "product": "gateway",
        "version": ANY,
        "edition": ANY,
    },
    {
        "vendor": "acme",
        "product": "gateway",
        "version": "1.0",
        "edition": "standard",
    },
)


def show(title, pair):
    result = check_overlap(pair[0], pair[1], DOMAIN)
    print(title)
    print("  status:             {0}".format(result.status))
    print("  witness:            {0}".format(result.witness_display))
    print("  requires decision:  {0}".format(result.requires_decision))
    print("  needs review:       {0}".format(result.needs_review))
    print("  explanation:        {0}".format(result.explanation))
    print()


if __name__ == "__main__":
    show("Pair 1: version spelling only (1.0 vs 1.0.0)",
         SPELLING_VARIANTS)
    show("Pair 2: substantive overlap", SUBSTANTIVE_OVERLAP)
