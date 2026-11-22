"""Local source-independence checks over STIX 2 content.

The helpers in this package reconstruct collection provenance from three
kinds of local evidence:

* observed-data objects, which represent the observations themselves;
* self-declared citations, read from configurable STIX properties on an
  observation (for example a custom citation_refs list or
  external_references entries whose external_id is a STIX ID);
* caller-registered collection relationships, read from SROs such as
  derived-from.

Observations connected directly or transitively, including mutual citation
cycles, are treated as one independent source. Citations that point at an
identifier that cannot be resolved are reported as reference gaps.

Two views are supported. The custodian view sees every object, including
observations restricted by a data marking. The public view never reveals a
restricted observation identifier or name, or even whether such an
observation exists: references that resolve to a restricted object appear as
unresolved gaps without identifying information, and the public result offers
a lower bound on the number of independent sources rather than an exact count.

.. autosummary::
   :toctree: provenance

   independence
"""

from .independence import (
    CUSTODIAN_VIEW,
    DEFAULT_CITATION_PROPERTIES,
    DEFAULT_COLLECTION_RELATIONSHIPS,
    PUBLIC_VIEW,
    ProvenanceEdge,
    ProvenanceResult,
    ReferenceGap,
    SourceComponent,
    check_independence,
)

__all__ = [
    'CUSTODIAN_VIEW',
    'DEFAULT_CITATION_PROPERTIES',
    'DEFAULT_COLLECTION_RELATIONSHIPS',
    'PUBLIC_VIEW',
    'ProvenanceEdge',
    'ProvenanceResult',
    'ReferenceGap',
    'SourceComponent',
    'check_independence',
]
