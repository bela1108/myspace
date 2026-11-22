"""Offline lineage reconstruction from DistributedLinkTracker blocks.

This module correlates the *current* (droid) and *original* (birth droid)
identifiers stored in the ``DISTRIBUTED_LINK_TRACKER_BLOCK`` of several LNK
samples and combines them with caller-supplied context (collection order and
hardware generation) to propose a traceable migration/copy lineage.

Design principles:

* Identifier matches are the only evidence that *creates* a candidate edge.
* Collection order, hardware generation and header timestamps only *constrain*
  (prune) candidates, they never create them.
* Shared identifiers may stem from snapshot reuse, so when a node ends up
  with several equally supported predecessors all branches are kept.
* Every exported edge carries its provenance so a reviewer can judge which
  links are continuations and which may just be backups.
"""

import json
import warnings
from dataclasses import dataclass
from dataclasses import field

from LnkParse3.extra.distributed_tracker import DistributedTracker
from LnkParse3.lnk_file import LnkFile


TRACKER_BLOCK_NAME = "DISTRIBUTED_LINK_TRACKER_BLOCK"

# Edge kinds.
KIND_DUPLICATE = "duplicate_recollection"
KIND_MIGRATION = "migration_or_copy"
KIND_SNAPSHOT = "snapshot_reuse_possible"

# Support scores for identifier evidence. Higher means stronger support.
SUPPORT_DUPLICATE = 3
SUPPORT_CONTINUATION = 2
SUPPORT_SHARED_BIRTH = 1


@dataclass
class TrackerIdentity:
    """Identifiers and constraints extracted from a single LNK sample.

    ``collection_order`` and ``hardware_generation`` are caller-supplied
    context: the parser cannot know in which order backups were collected or
    which hardware generation a machine belongs to.
    """

    sample: str
    machine_id: str
    volume_id: str
    file_id: str
    birth_volume_id: str
    birth_file_id: str
    collection_order: int = None
    hardware_generation: int = None
    creation_time: object = None
    write_time: object = None
    access_time: object = None
    source: str = None

    @property
    def current_ids(self):
        """Current (droid) identity: volume + file identifier."""
        return (self.volume_id, self.file_id)

    @property
    def birth_ids(self):
        """Original (birth droid) identity: volume + file identifier."""
        return (self.birth_volume_id, self.birth_file_id)


@dataclass
class LineageEdge:
    """A directed predecessor -> successor relation with provenance."""

    source: str
    target: str
    kind: str
    support: int
    evidence: list = field(default_factory=list)
    constraints: dict = field(default_factory=dict)

    def as_dict(self):
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "support": self.support,
            "evidence": self.evidence,
            "constraints": self.constraints,
        }


@dataclass
class RejectedCandidate:
    """A candidate edge pruned by a constraint, kept for traceability."""

    source: str
    target: str
    kind: str
    reason: str

    def as_dict(self):
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "rejected_because": self.reason,
        }


def _find_tracker(lnk):
    for extra in lnk.extras:
        if isinstance(extra, DistributedTracker):
            return extra
    return None


def extract_identity(
    indata=None,
    path=None,
    sample=None,
    collection_order=None,
    hardware_generation=None,
):
    """Extract a :class:`TrackerIdentity` from one LNK sample.

    The sample can be given as raw bytes (``indata``) or as a file ``path``.
    ``collection_order`` and ``hardware_generation`` are caller-supplied
    context used later to constrain candidate edges. Returns ``None`` (with a
    warning) when the sample carries no DistributedLinkTracker block.
    """
    if path is not None:
        with open(path, "rb") as fp:
            indata = fp.read()
        if sample is None:
            sample = str(path)
    if sample is None:
        sample = "<memory>"

    lnk = LnkFile(indata=indata)
    tracker = _find_tracker(lnk)
    if tracker is None:
        warnings.warn(f"sample {sample!r} has no {TRACKER_BLOCK_NAME}")
        return None

    return TrackerIdentity(
        sample=sample,
        machine_id=tracker.machine_id(),
        volume_id=tracker.droid_volume_id(),
        file_id=tracker.droid_file_id(),
        birth_volume_id=tracker.droid_birth_volume_id(),
        birth_file_id=tracker.droid_birth_file_id(),
        collection_order=collection_order,
        hardware_generation=hardware_generation,
        creation_time=lnk.header.creation_time(),
        write_time=lnk.header.write_time(),
        access_time=lnk.header.access_time(),
        source=sample,
    )


def _match_evidence(pred, succ):
    """Return (kind, support, evidence) for identifier matches, or None.

    Only identifier equality creates a candidate edge:

    * identical current *and* birth identities -> the same file collected
      again (e.g. repeated across backup rounds),
    * successor birth identity == predecessor current identity -> the
      successor continues the predecessor (migration or copy),
    * shared birth identity but different current identity -> possible
      snapshot reuse; kept as a weaker, ambiguous branch.
    """
    fields = {
        "volume_id": succ.birth_volume_id,
        "file_id": succ.birth_file_id,
    }
    if succ.current_ids == pred.current_ids and succ.birth_ids == pred.birth_ids:
        evidence = {
            "rule": "identical_current_and_birth",
            "source_block": TRACKER_BLOCK_NAME,
            "matched_fields": {
                "volume_id": succ.volume_id,
                "file_id": succ.file_id,
                "birth_volume_id": succ.birth_volume_id,
                "birth_file_id": succ.birth_file_id,
            },
        }
        return KIND_DUPLICATE, SUPPORT_DUPLICATE, evidence
    if succ.birth_ids == pred.current_ids:
        evidence = {
            "rule": "birth_matches_predecessor_current",
            "source_block": TRACKER_BLOCK_NAME,
            "matched_fields": fields,
        }
        return KIND_MIGRATION, SUPPORT_CONTINUATION, evidence
    if succ.birth_ids == pred.birth_ids and succ.current_ids != pred.current_ids:
        evidence = {
            "rule": "shared_birth_identity",
            "source_block": TRACKER_BLOCK_NAME,
            "matched_fields": fields,
        }
        return KIND_SNAPSHOT, SUPPORT_SHARED_BIRTH, evidence
    return None


def _check_constraints(pred, succ):
    """Check caller-supplied and header-time constraints.

    Returns (constraints, rejection_reason). Constraints can only prune a
    candidate, never create one; missing data means "not applicable".
    """
    constraints = {}

    if pred.collection_order is not None and succ.collection_order is not None:
        ok = pred.collection_order < succ.collection_order
        constraints["collection_order"] = {
            "predecessor": pred.collection_order,
            "successor": succ.collection_order,
            "satisfied": ok,
        }
        if not ok:
            return constraints, "predecessor was not collected before successor"

    if pred.hardware_generation is not None and succ.hardware_generation is not None:
        ok = pred.hardware_generation <= succ.hardware_generation
        constraints["hardware_generation"] = {
            "predecessor": pred.hardware_generation,
            "successor": succ.hardware_generation,
            "satisfied": ok,
        }
        if not ok:
            return constraints, "successor is on an older hardware generation"

    # Header timestamps only add constraints: a successor cannot be created
    # before the predecessor's last known modification.
    if pred.write_time is not None and succ.creation_time is not None:
        ok = pred.write_time <= succ.creation_time
        constraints["header_timestamps"] = {
            "predecessor_write_time": pred.write_time.isoformat(),
            "successor_creation_time": succ.creation_time.isoformat(),
            "satisfied": ok,
        }
        if not ok:
            return constraints, "successor header creation time predates predecessor write time"

    return constraints, None


class Lineage:
    """Result of :func:`build_lineage`: nodes, edges and rejected candidates."""

    def __init__(self, identities, edges, rejected):
        self.identities = list(identities)
        self.edges = list(edges)
        self.rejected = list(rejected)

    def predecessors(self, sample):
        """All retained predecessors of ``sample``, best-supported first."""
        inbound = [edge for edge in self.edges if edge.target == sample]
        return sorted(inbound, key=lambda edge: (-edge.support, edge.source))

    def parallel_predecessors(self):
        """Map of sample -> equally best-supported predecessors (branches).

        Only nodes with more than one predecessor at the top support level
        are listed; those are the branches a reviewer should look at to
        decide what is a continuation and what may just be a backup.
        """
        result = {}
        for identity in self.identities:
            inbound = self.predecessors(identity.sample)
            if not inbound:
                continue
            best = inbound[0].support
            tied = [edge.source for edge in inbound if edge.support == best]
            if len(tied) > 1:
                result[identity.sample] = sorted(tied)
        return result

    def to_dict(self):
        return {
            "format": "LnkParse3-lineage/1.0",
            "nodes": [
                {
                    "sample": identity.sample,
                    "source": identity.source,
                    "machine_id": identity.machine_id,
                    "volume_id": identity.volume_id,
                    "file_id": identity.file_id,
                    "birth_volume_id": identity.birth_volume_id,
                    "birth_file_id": identity.birth_file_id,
                    "collection_order": identity.collection_order,
                    "hardware_generation": identity.hardware_generation,
                }
                for identity in self.identities
            ],
            "edges": [edge.as_dict() for edge in self.edges],
            "parallel_predecessors": self.parallel_predecessors(),
            "rejected_candidates": [candidate.as_dict() for candidate in self.rejected],
        }

    def export(self, path):
        """Export the lineage (edges with provenance) as JSON."""
        with open(path, "w") as fp:
            json.dump(self.to_dict(), fp, indent=2, sort_keys=True)
            fp.write("\n")
        return path


def build_lineage(identities):
    """Build a :class:`Lineage` from an iterable of :class:`TrackerIdentity`.

    Every ordered pair is tested for identifier evidence; matching pairs are
    then pruned by collection order, hardware generation and header
    timestamp constraints. Rejected candidates are kept for traceability.
    """
    identities = list(identities)
    edges = []
    rejected = []

    for succ in identities:
        for pred in identities:
            if pred is succ:
                continue
            match = _match_evidence(pred, succ)
            if match is None:
                continue
            kind, support, evidence = match
            constraints, reason = _check_constraints(pred, succ)
            if reason is not None:
                rejected.append(
                    RejectedCandidate(
                        source=pred.sample, target=succ.sample, kind=kind, reason=reason
                    )
                )
                continue
            edges.append(
                LineageEdge(
                    source=pred.sample,
                    target=succ.sample,
                    kind=kind,
                    support=support,
                    evidence=[evidence],
                    constraints=constraints,
                )
            )

    return Lineage(identities, edges, rejected)
