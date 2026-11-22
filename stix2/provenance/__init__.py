"""Local source-independence checks over STIX 2 content.

The package reconstructs collection provenance from observations,
self-declared citations, and caller-registered collection relationships.
Observations which are connected directly or transitively -- including mutual
citation cycles -- are one independent source.  References which cannot be
resolved in the visible graph are reported as reference gaps.

The public view removes observations carrying a custodian-only marking.  It
never exposes their identifiers, names, or whether they exist: a restricted
target and a missing target both become the same redacted gap.  The public
result therefore gives a lower bound, while the custodian view gives the exact
local component count.

.. autosummary::
   :toctree: provenance

   independence
"""

from .independence import (
    CALLER_RELATION,
    COLLECTION_RELATIONSHIP,
    CUSTODIAN_VIEW,
    DEFAULT_CITATION_PROPERTIES,
    DEFAULT_COLLECTION_RELATIONSHIP_TYPES,
    DEFAULT_RESTRICTED_MARKING_NAME_PATTERNS,
    DEFAULT_SOURCE_TYPES,
    GAP_RESTRICTED,
    GAP_UNRESOLVED,
    PUBLIC_VIEW,
    SELF_CITATION,
    IndependenceChecker,
    IndependenceReport,
    ProvenanceEdge,
    ProvenanceResult,
    ReferenceGap,
    SourceComponent,
    check_independence,
    check_source_independence,
)

__all__ = [
    "CALLER_RELATION",
    "COLLECTION_RELATIONSHIP",
    "CUSTODIAN_VIEW",
    "DEFAULT_CITATION_PROPERTIES",
    "DEFAULT_COLLECTION_RELATIONSHIP_TYPES",
    "DEFAULT_RESTRICTED_MARKING_NAME_PATTERNS",
    "DEFAULT_SOURCE_TYPES",
    "GAP_RESTRICTED",
    "GAP_UNRESOLVED",
    "PUBLIC_VIEW",
    "SELF_CITATION",
    "IndependenceChecker",
    "IndependenceReport",
    "ProvenanceEdge",
    "ProvenanceResult",
    "ReferenceGap",
    "SourceComponent",
    "check_independence",
    "check_source_independence",
]
