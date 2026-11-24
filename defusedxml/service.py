"""Chunked XML parsing service with one shared document policy.

The service is intentionally small: it feeds the same segment boundaries to
ElementTree, SAX, and pulldom and converts backend-specific failures into
:class:`~defusedxml.policy.PolicyRejected`.
"""
from __future__ import absolute_import, division, print_function

from io import IOBase

from . import ElementTree as _ElementTree
from . import expatreader, pulldom, sax
from .policy import (
    BACKEND_ELEMENTTREE,
    BACKEND_PULLDOM,
    BACKEND_SAX,
    BudgetPolicy,
    PolicyRejected,
    RejectionReason,
)


BACKEND_ALIASES = {
    "elementtree": BACKEND_ELEMENTTREE,
    "element_tree": BACKEND_ELEMENTTREE,
    "et": BACKEND_ELEMENTTREE,
    "xml.etree.elementtree": BACKEND_ELEMENTTREE,
    BACKEND_ELEMENTTREE.lower(): BACKEND_ELEMENTTREE,
    "sax": BACKEND_SAX,
    "xml.sax": BACKEND_SAX,
    BACKEND_SAX.lower(): BACKEND_SAX,
    "pulldom": BACKEND_PULLDOM,
    "xml.dom.pulldom": BACKEND_PULLDOM,
}


class ChunkStream(IOBase):
    """A file-like object that returns one prepared segment per read."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.index = 0

    def readable(self):
        return True

    def read(self, size=-1):
        if self.index >= len(self.chunks):
            first_type = type(self.chunks[0]) if self.chunks else bytes
            return b"" if first_type is bytes else ""
        chunk = self.chunks[self.index]
        self.index += 1
        return chunk

    def close(self):
        self.index = len(self.chunks)


ChunkReader = ChunkStream


SegmentReader = ChunkStream


def chunk_document(document, chunk_size=1):
    """Split ``document`` into fixed-size character/byte segments."""
    if chunk_size is None or chunk_size <= 0:
        return [document]
    return [
        document[start : start + chunk_size]
        for start in range(0, len(document), chunk_size)
    ]


def normalize_backend(backend):
    if hasattr(backend, "__name__"):
        name = getattr(backend, "__name__", "")
        if name == "ElementTree":
            return BACKEND_ELEMENTTREE
    key = str(backend).strip().lower().replace("_", "")
    compact_aliases = {
        "elementtree": BACKEND_ELEMENTTREE,
        "et": BACKEND_ELEMENTTREE,
        "sax": BACKEND_SAX,
        "pulldom": BACKEND_PULLDOM,
    }
    if key in compact_aliases:
        return compact_aliases[key]
    return BACKEND_ALIASES.get(str(backend).strip().lower(), str(backend))


def _chunks(source, chunk_size):
    if isinstance(source, (bytes, str)):
        return chunk_document(source, chunk_size)
    chunks = list(source)
    if chunk_size:
        expanded = []
        for chunk in chunks:
            expanded.extend(chunk_document(chunk, chunk_size))
        return expanded
    return chunks


def rejection_for_backend(exc, backend, policy=None):
    """Return a controlled rejection carrying backend-specific detail."""
    backend = normalize_backend(backend)
    if isinstance(exc, PolicyRejected):
        if exc.backend is None:
            exc.backend = backend
        if policy is not None and not exc.counts:
            exc.counts = policy._counts()
        return exc

    counts = policy._counts() if policy is not None else None
    detail = "backend raised " + type(exc).__module__ + "." + type(exc).__name__
    return PolicyRejected(
        RejectionReason.BACKEND,
        backend=backend,
        detail=detail,
        native_error=exc,
        counts=counts,
    )


class BackendResult(object):
    def __init__(self, backend, value, policy, chunks):
        self.backend = normalize_backend(backend)
        self.value = value
        self.policy = policy
        self.chunks = list(chunks)
        self.usage = policy.snapshot() if policy is not None else None

    def __iter__(self):
        yield self.backend
        yield self.value

    def __repr__(self):
        return "BackendResult(backend=%r, usage=%r)" % (self.backend, self.usage)


class XMLSegmentService(object):
    """Parse identical segments through interchangeable XML backends."""

    backends = (BACKEND_ELEMENTTREE, BACKEND_SAX, BACKEND_PULLDOM)

    def __init__(self, policy=None, **limits):
        if isinstance(policy, BudgetPolicy):
            self.policy = policy
        else:
            self.policy = BudgetPolicy.from_value(policy, **limits)

    def _policy_for(self, backend, fresh):
        if self.policy is None:
            return None
        if fresh:
            return self.policy.clone(backend=normalize_backend(backend))
        self.policy.backend = normalize_backend(backend)
        return self.policy

    def parse(
        self,
        source,
        backend=BACKEND_ELEMENTTREE,
        chunk_size=1,
        policy=None,
        fresh_policy=True,
        handler=None,
        forbid_dtd=False,
        forbid_entities=False,
        forbid_external=True,
        normalize=True,
    ):
        backend_name = normalize_backend(backend)
        chunks = _chunks(source, chunk_size)
        active_policy = policy if policy is not None else self._policy_for(backend_name, fresh_policy)
        try:
            if backend_name == BACKEND_ELEMENTTREE:
                value = _parse_elementtree(
                    chunks, active_policy, forbid_dtd, forbid_entities, forbid_external
                )
            elif backend_name == BACKEND_SAX:
                value = _parse_sax(
                    chunks,
                    active_policy,
                    forbid_dtd,
                    forbid_entities,
                    forbid_external,
                    handler=handler,
                )
            elif backend_name == BACKEND_PULLDOM:
                value = _parse_pulldom(
                    chunks, active_policy, forbid_dtd, forbid_entities, forbid_external
                )
            else:
                raise ValueError("Unknown XML backend: " + repr(backend))
        except Exception as exc:
            rejection = rejection_for_backend(exc, backend_name, active_policy)
            if normalize and rejection is not exc:
                raise rejection from exc
            if isinstance(rejection, PolicyRejected):
                raise rejection
            raise
        return BackendResult(backend_name, value, active_policy, chunks)

    def parse_all(self, source, chunk_size=1, backends=None, **kwargs):
        prepared_chunks = _chunks(source, chunk_size)
        results = {}
        for backend in backends or self.backends:
            results[normalize_backend(backend)] = self.parse(
                prepared_chunks, backend=backend, chunk_size=None, **kwargs
            )
        return results


def _parse_elementtree(chunks, policy, forbid_dtd, forbid_entities, forbid_external):
    parser = _ElementTree.DefusedXMLParser(
        policy=policy,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    for chunk in chunks:
        parser.feed(chunk)
    return parser.close()


def _parse_sax(chunks, policy, forbid_dtd, forbid_entities, forbid_external, handler=None):
    parser = expatreader.create_parser(
        policy=policy,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    if handler is not None:
        parser.setContentHandler(handler)
    for chunk in chunks:
        parser.feed(chunk)
    parser.close()
    return handler


def _parse_pulldom(chunks, policy, forbid_dtd, forbid_entities, forbid_external):
    stream = ChunkStream(chunks)
    events = pulldom.parse(
        stream,
        policy=policy,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    return list(events)


def parse_segments(source, backend=BACKEND_ELEMENTTREE, chunk_size=1, policy=None, **kwargs):
    """Functional wrapper around :class:`XMLSegmentService`."""
    service = XMLSegmentService(policy)
    result = service.parse(source, backend=backend, chunk_size=chunk_size, **kwargs)
    return result


def parse_all_backends(source, chunk_size=1, policy=None, **kwargs):
    service = XMLSegmentService(policy)
    return service.parse_all(source, chunk_size=chunk_size, **kwargs)


__all__ = [
    "BackendResult",
    "ChunkStream",
    "XMLSegmentService",
    "chunk_document",
    "normalize_backend",
    "parse_all_backends",
    "parse_segments",
    "rejection_for_backend",
]
