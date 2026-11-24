# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax.expatreader
"""
from __future__ import print_function, absolute_import

from xml.sax.expatreader import ExpatParser as _ExpatParser

from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from .policy import (
    BACKEND_SAX,
    BudgetPolicy,
    PolicyRejected,
    install_expat_policy,
)

__origin__ = "xml.sax.expatreader"


class DefusedExpatParser(_ExpatParser):
    """Defused SAX driver for the pyexpat C module."""

    def __init__(
        self,
        namespaceHandling=0,
        bufsize=2**16 - 20,
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
        super().__init__(namespaceHandling, bufsize)
        self.policy = BudgetPolicy.from_value(
            policy,
            budget,
            max_expansions=max_expansions,
            max_depth=max_depth,
            max_bytes=max_bytes,
            max_unparsed_entities=max_unparsed_entities,
        )
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = (
            self.policy is None if forbid_entities is None else bool(forbid_entities)
        )
        self.forbid_external = forbid_external

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise DTDForbidden(name, sysid, pubid)

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)  # pragma: no cover

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        raise ExternalReferenceForbidden(context, base, sysid, pubid)

    def feed(self, data, isFinal=False):
        if self.policy is not None and not isFinal:
            backend = getattr(self, "policy_backend", None) or BACKEND_SAX
            self.policy.observe_data(data, backend=backend)
        try:
            return super().feed(data, isFinal=isFinal)
        except Exception as exc:
            if self.policy is not None and isinstance(exc, PolicyRejected):
                if exc.backend is None:
                    exc.backend = getattr(self, "policy_backend", None) or BACKEND_SAX
            raise

    def reset(self):
        super().reset()
        parser = self._parser
        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.forbid_entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler
        if self.policy is not None:
            backend = getattr(self, "policy_backend", None) or BACKEND_SAX
            install_expat_policy(parser, self.policy, backend)


def create_parser(*args, **kwargs):
    return DefusedExpatParser(*args, **kwargs)
