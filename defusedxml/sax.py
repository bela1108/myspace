# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax
"""
from __future__ import print_function, absolute_import

from xml.sax import InputSource as _InputSource
from xml.sax import ErrorHandler as _ErrorHandler

from . import expatreader

__origin__ = "xml.sax"


def parse(
    source,
    handler,
    errorHandler=_ErrorHandler(),
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
    parser = make_parser(
        policy=policy,
        budget=budget,
        max_expansions=max_expansions,
        max_depth=max_depth,
        max_bytes=max_bytes,
        max_unparsed_entities=max_unparsed_entities,
    )
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    parser.forbid_dtd = forbid_dtd
    parser.forbid_entities = (
        parser.policy is None if forbid_entities is None else forbid_entities
    )
    parser.forbid_external = forbid_external
    parser.parse(source)


def parseString(
    string,
    handler,
    errorHandler=_ErrorHandler(),
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
    from io import BytesIO

    if errorHandler is None:
        errorHandler = _ErrorHandler()
    parser = make_parser(
        policy=policy,
        budget=budget,
        max_expansions=max_expansions,
        max_depth=max_depth,
        max_bytes=max_bytes,
        max_unparsed_entities=max_unparsed_entities,
    )
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    parser.forbid_dtd = forbid_dtd
    parser.forbid_entities = (
        parser.policy is None if forbid_entities is None else forbid_entities
    )
    parser.forbid_external = forbid_external

    inpsrc = _InputSource()
    inpsrc.setByteStream(BytesIO(string))
    parser.parse(inpsrc)


def make_parser(parser_list=[], **kwargs):
    return expatreader.create_parser(**kwargs)
