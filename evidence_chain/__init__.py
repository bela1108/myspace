"""Evidence-chain audit for offline managed (.NET) artifacts.

This package implements a read-only compliance audit: a vendor submits
supplemental read-only metadata records for a batch of offline hosted
managed artifacts, and each submission is classified against the external
archive chain (the original release manifest plus its recognized module
generations).

The generation identifier of every parseable ("normal") sample is consumed
with dnfile's Module metadata table and the existing heap parsing
(#Strings for the module name, #GUID for the Mvid).
"""

from evidence_chain.generation import (
    GenerationUnreadable,
    ModuleIdentity,
    normalize_mvid,
    read_module_identity,
)
from evidence_chain.audit import (
    Classification,
    audit,
    load_manifest,
    load_records,
)

__all__ = [
    "Classification",
    "GenerationUnreadable",
    "ModuleIdentity",
    "audit",
    "load_manifest",
    "load_records",
    "normalize_mvid",
    "read_module_identity",
]
