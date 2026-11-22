"""Artifact resolver API.

Extensible interface to hash artifacts based on URIs.

Example usage::

    from in_toto.resolver import Resolver, RESOLVER_FOR_URI_SCHEME

    # Register resolver instances for schemes
    RESOLVER_FOR_URI_SCHEME["myscheme"] = MyResolver()

    # Resolve arbitrary URIs with registered resolvers
    resolver = Resolver.for_uri(uri)
    artifact_hashes = resolver.hash_artifacts(uris)

"""

from in_toto.resolver._resolver import (
    RESOLVER_FOR_URI_SCHEME,
    DirectoryResolver,
    FileResolver,
    OSTreeResolver,
    Resolver,
)
from in_toto.resolver.evidence import (
    CHANGED,
    CONSISTENT,
    UNVERIFIED,
    ArtifactEvidence,
    ArtifactEvidenceReport,
    ArtifactIdentity,
    ArtifactSource,
    ConsistencyReport,
    Evidence,
    EvidenceConsistencyReport,
    EvidenceEntries,
    EvidenceEntry,
    EvidenceReport,
    MaterialEvidence,
    MaterialEvidenceReport,
    MaterialReport,
    MaterialsReport,
    ResolutionEvidence,
    ResolutionReport,
    ResolverEvidence,
    SnapshotIdentity,
    SourceIdentity,
    affected_resolvers,
    as_report,
    check_evidence_consistency,
    consistency_report,
    evidence_from_hashes,
    find_affected_entries,
    find_entries_for_resolver,
    report_from_hashes,
    resolver_for_entry,
    verify_evidence_consistency,
)
