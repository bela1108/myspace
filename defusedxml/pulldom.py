# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.dom.pulldom
"""
from __future__ import print_function, absolute_import

from xml.dom.pulldom import parse as _parse
from xml.dom.pulldom import parseString as _parseString

from .sax import make_parser
from .policy import BACKEND_PULLDOM, BudgetPolicy

__origin__ = "xml.dom.pulldom"


def _prepare_parser(
    parser,
    policy,
    budget,
    max_expansions,
    max_depth,
    max_bytes,
    max_unparsed_entities,
    forbid_dtd,
    forbid_entities,
    forbid_external,
):
    policy_obj = BudgetPolicy.from_value(
        policy,
        budget,
        max_expansions=max_expansions,
        max_depth=max_depth,
        max_bytes=max_bytes,
        max_unparsed_entities=max_unparsed_entities,
    )
    if parser is None:
        parser = make_parser(policy=policy_obj)
    elif policy_obj is not None:
        parser.policy = policy_obj

    active_policy = getattr(parser, "policy", None)
    if active_policy is not None:
        parser.policy_backend = BACKEND_PULLDOM
    if forbid_entities is None:
        forbid_entities = active_policy is None

    parser.forbid_dtd = forbid_dtd
    parser.forbid_entities = forbid_entities
    parser.forbid_external = forbid_external
    return parser


def parse(
    stream_or_string,
    parser=None,
    bufsize=None,
    forbid_dtd=False,
    forbid_entities=None,
    forbid_external=True,
    policy=None,
    budget=None,
    max_expansions=None,
    max_depth=None,
    max_bytes=None,
    max_unparsed_entities=None,
):
    parser = _prepare_parser(
        parser,
        policy,
        budget,
        max_expansions,
        max_depth,
        max_bytes,
        max_unparsed_entities,
        forbid_dtd,
        forbid_entities,
        forbid_external,
    )
    return _parse(stream_or_string, parser, bufsize)


def parseString(
    string,
    parser=None,
    forbid_dtd=False,
    forbid_entities=None,
    forbid_external=True,
    policy=None,
    budget=None,
    max_expansions=None,
    max_depth=None,
    max_bytes=None,
    max_unparsed_entities=None,
):
    parser = _prepare_parser(
        parser,
        policy,
        budget,
        max_expansions,
        max_depth,
        max_bytes,
        max_unparsed_entities,
        forbid_dtd,
        forbid_entities,
        forbid_external,
    )
    return _parseString(string, parser)
