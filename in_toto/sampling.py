# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Deterministic acceptance sampling for signed in-toto release evidence.

The release layout may carry an optional, owner-signed ``sampling`` policy.
Given that policy and the artifacts reported by verified in-toto links, this
module computes a reproducible draw sheet, verifies signed reviewer evidence
for the drawn artifacts, and enforces the release cutoff.

The draw is deterministic: artifacts are ranked with HMAC-SHA256 using the
batch seed as key and a canonical representation of the complete signed
artifact set as message. Consequently, replacing *any* artifact, including one
that was not drawn, changes the full-set digest and invalidates the previous
draw and all evidence bound to it.

Review evidence is ordinary signed in-toto link metadata. Its signed
``byproducts`` bind it to a draw sheet and to the release cutoff, e.g.::

  {
    "draw_sheet_digest": "<sample digest from the draw sheet>",
    "release_cutoff": "2026-11-23T12:00:00Z",
    "reviewed_at": "2026-11-23T11:30:00Z",
    "artifact": "materials/notes-a.txt",
    "artifact_type": "materials",
    "artifact_hashes": {"sha256": "..."}
  }

Evidence signed at or before the cutoff may satisfy the draw. Evidence signed
after the cutoff is not accepted for this release, but is retained in
``SamplingResult.late`` for re-review.
"""

import copy
import glob
import hashlib
import hmac
import json
import os
from datetime import timezone

import attr
import iso8601
import securesystemslib.exceptions

import in_toto.exceptions
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock, Metadata

SAMPLING_VERSION = "in-toto-sampling/v1"
SAMPLING_ALGORITHM = "hmac-sha256-rank-v1"

_ARTIFACT_TYPES = {"materials", "products", "both"}


def _canonical_json(data):
    """Return canonical UTF-8 JSON bytes for deterministic hashing."""
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_digest(data):
    return hashlib.sha256(data).hexdigest()


def _parse_timestamp(value, field="timestamp"):
    """Parse an ISO 8601 timestamp and return a timezone-aware datetime."""
    if not isinstance(value, str):
        raise securesystemslib.exceptions.FormatError(
            f"'{field}' must be an ISO 8601 string"
        )

    try:
        parsed = iso8601.parse_date(value)
    except iso8601.ParseError as exc:
        raise securesystemslib.exceptions.FormatError(
            f"Malformed ISO 8601 timestamp in '{field}': {value}"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _check_hash_dict(hashes, field="artifact_hashes"):
    if not isinstance(hashes, dict) or not hashes:
        raise securesystemslib.exceptions.FormatError(
            f"'{field}' must be a non-empty hash dictionary"
        )

    for algorithm, digest in hashes.items():
        if not isinstance(algorithm, str) or not isinstance(digest, str):
            raise securesystemslib.exceptions.FormatError(
                f"'{field}' must map strings to strings"
            )


def _normalize_hashes(hashes):
    _check_hash_dict(hashes)
    return {str(algorithm): str(digest) for algorithm, digest in hashes.items()}


def _normalize_full_set(full_set):
    """Validate and return a copy of an artifact full set.

    The full set maps stable artifact ids to hash dictionaries. A single
    artifact type uses the artifact path as id. When materials and products
    are sampled together, ids are prefixed with ``materials:`` or
    ``products:`` to avoid ambiguous ids.
    """
    if not isinstance(full_set, dict) or not full_set:
        raise securesystemslib.exceptions.FormatError(
            "The signed artifact full set must be a non-empty dictionary"
        )

    normalized = {}
    for artifact_id, hashes in full_set.items():
        if not isinstance(artifact_id, str) or not artifact_id:
            raise securesystemslib.exceptions.FormatError(
                "Artifact ids in the full set must be non-empty strings"
            )
        normalized[artifact_id] = _normalize_hashes(hashes)

    return dict(sorted(normalized.items()))


def full_set_digest(full_set):
    """Return the digest of a canonical, sorted signed artifact full set."""
    return _sha256_digest(_canonical_json(_normalize_full_set(full_set)))


@attr.s(repr=False, init=False)
class SamplingPolicy:
    """An owner-signed, ex-ante sampling agreement.

    Attributes:
      seed: Fixed batch seed. The draw is recomputable from this seed and the
          signed full set.
      sample_size: Number of artifacts to draw. If the full set is smaller,
          all artifacts are drawn.
      cutoff: Release cutoff as ISO 8601 timestamp. Evidence signed after this
          point is late and retained for re-review.
      reviewers: Optional authorized reviewer keyids. If empty, any key passed
          in ``review_keys`` may sign evidence.
      steps: Step names whose verified links contribute to the full set. An
          empty list means all steps.
      artifact_type: One of ``materials``, ``products`` or ``both``.
      threshold: Number of distinct valid reviewer signatures required per
          artifact.
      algorithm: Fixed sampling algorithm id.
    """

    seed = attr.ib()
    sample_size = attr.ib()
    cutoff = attr.ib()
    reviewers = attr.ib()
    steps = attr.ib()
    artifact_type = attr.ib()
    threshold = attr.ib()
    algorithm = attr.ib()

    def __init__(  # noqa: PLR0913
        self,
        seed=None,
        sample_size=None,
        cutoff=None,
        reviewers=None,
        steps=None,
        artifact_type="both",
        threshold=1,
        algorithm=SAMPLING_ALGORITHM,
        **kwargs,
    ):
        size_aliases = [
            alias
            for alias in (
                kwargs.pop("size", None),
                kwargs.pop("sample_count", None),
            )
            if alias is not None
        ]
        cutoff_alias = kwargs.pop("release_cutoff", None)
        seed_alias = kwargs.pop("batch_seed", None)
        if kwargs:
            raise securesystemslib.exceptions.FormatError(
                "Unexpected sampling policy fields: "
                + ", ".join(sorted(kwargs))
            )

        if seed is None:
            seed = seed_alias
        elif seed_alias is not None and seed_alias != seed:
            raise securesystemslib.exceptions.FormatError(
                "Conflicting sampling policy fields 'seed' and 'batch_seed'"
            )

        if sample_size is None and size_aliases:
            sample_size = size_aliases[0]
        for alias in size_aliases:
            if sample_size is not None and alias != sample_size:
                raise securesystemslib.exceptions.FormatError(
                    "Conflicting sampling policy size fields"
                )

        if cutoff is None:
            cutoff = cutoff_alias
        elif cutoff_alias is not None and cutoff_alias != cutoff:
            raise securesystemslib.exceptions.FormatError(
                "Conflicting sampling policy fields 'cutoff' and"
                " 'release_cutoff'"
            )

        self.seed = seed
        self.sample_size = sample_size
        self.cutoff = cutoff
        self.reviewers = reviewers if reviewers is not None else []
        self.steps = steps if steps is not None else []
        self.artifact_type = artifact_type
        self.threshold = threshold
        self.algorithm = algorithm

        self.validate()

    def validate(self):
        if not isinstance(self.seed, str) or not self.seed:
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy 'seed' must be a non-empty string"
            )

        if (
            not isinstance(self.sample_size, int)
            or isinstance(self.sample_size, bool)
            or self.sample_size < 1
        ):
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy 'sample_size' must be a positive integer"
            )

        _parse_timestamp(self.cutoff, "cutoff")

        if not isinstance(self.reviewers, list) or not all(
            isinstance(reviewer, str) and reviewer
            for reviewer in self.reviewers
        ):
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy 'reviewers' must be a list of keyids"
            )

        if not isinstance(self.steps, list) or not all(
            isinstance(step, str) and step for step in self.steps
        ):
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy 'steps' must be a list of step names"
            )

        if self.artifact_type not in _ARTIFACT_TYPES:
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy 'artifact_type' must be one of: "
                + ", ".join(sorted(_ARTIFACT_TYPES))
            )

        if (
            not isinstance(self.threshold, int)
            or isinstance(self.threshold, bool)
            or self.threshold < 1
        ):
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy 'threshold' must be a positive integer"
            )

        if self.algorithm != SAMPLING_ALGORITHM:
            raise securesystemslib.exceptions.FormatError(
                "Unsupported sampling algorithm: "
                f"'{self.algorithm}' (expected '{SAMPLING_ALGORITHM}')"
            )

        if self.reviewers and self.threshold > len(self.reviewers):
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy 'threshold' exceeds the number of"
                " authorized reviewers"
            )

    @classmethod
    def read(cls, data):
        """Create a policy from a dict or return an existing policy."""
        if isinstance(data, cls):
            return data
        if not isinstance(data, dict):
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy must be a dictionary"
            )
        return cls(**data)

    from_dict = read

    @classmethod
    def load(cls, path):
        """Load a policy from a JSON file."""
        with open(path, encoding="utf8") as file_object:
            return cls.read(json.load(file_object))

    def dump(self, path):
        """Write the policy as JSON."""
        with open(path, "w", encoding="utf8") as file_object:
            json.dump(self.to_dict(), file_object, indent=1, sort_keys=True)
            file_object.write("\n")

    def to_dict(self):
        return {
            "seed": self.seed,
            "sample_size": self.sample_size,
            "cutoff": self.cutoff,
            "reviewers": list(self.reviewers),
            "steps": list(self.steps),
            "artifact_type": self.artifact_type,
            "threshold": self.threshold,
            "algorithm": self.algorithm,
        }

    @property
    def digest(self):
        return _sha256_digest(_canonical_json(self.to_dict()))

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def keys(self):
        return self.to_dict().keys()

    def __iter__(self):
        return iter(self.to_dict())

    def __len__(self):
        return len(self.to_dict())

    @property
    def cutoff_datetime(self):
        return _parse_timestamp(self.cutoff, "cutoff")


SamplingPlan = SamplingPolicy
SamplePlan = SamplingPolicy


def _artifact_type_for_id(artifact_id, artifact_type):
    if artifact_type != "both":
        return artifact_type, artifact_id

    for candidate in ("materials", "products"):
        prefix = candidate + ":"
        if artifact_id.startswith(prefix):
            return candidate, artifact_id[len(prefix) :]

    raise securesystemslib.exceptions.FormatError(
        f"Ambiguous artifact id '{artifact_id}' for a 'both' policy"
    )


def _collection_links(links_per_step):  # noqa: C901, PLR0912
    """Yield (step_name, Link) from verified step link collections."""
    if isinstance(links_per_step, (Link, Metadata)):
        links_per_step = {"": links_per_step}

    if isinstance(links_per_step, (list, tuple, set)):
        links_per_step = {"": list(links_per_step)}

    if not isinstance(links_per_step, dict):
        raise securesystemslib.exceptions.FormatError(
            "Links must be passed per step as a dictionary"
        )

    for step_name, per_functionary in links_per_step.items():
        if per_functionary is None:
            continue

        if isinstance(per_functionary, (Link, Metadata)):
            links = [per_functionary]
        elif isinstance(per_functionary, dict):
            links = list(per_functionary.values())
        elif isinstance(per_functionary, (list, tuple)):
            links = list(per_functionary)
        else:
            raise securesystemslib.exceptions.FormatError(
                f"Unsupported link collection for step '{step_name}'"
            )

        for metadata in links:
            if isinstance(metadata, Metadata):
                payload = metadata.get_payload()
            elif isinstance(metadata, Link):
                payload = metadata
            else:
                raise securesystemslib.exceptions.FormatError(
                    f"Unsupported link metadata for step '{step_name}'"
                )

            if not isinstance(payload, Link):
                raise securesystemslib.exceptions.FormatError(
                    f"Step '{step_name}' does not contain link metadata"
                )

            yield step_name, payload


def collect_full_set(
    links,
    steps=None,
    artifact_type="materials",
    raise_on_conflict=True,
    policy=None,
):
    """Collect the signed artifact full set from verified in-toto links.

    Arguments:
      links: Either the dictionary returned by
          ``verify_link_signature_thresholds`` or ``verify_sublayouts``, or a
          flat collection of Link/Metadata objects.
      steps: Optional step names to include. ``None`` or an empty sequence
          includes all steps.
      artifact_type: ``materials``, ``products`` or ``both``.
      raise_on_conflict: Raise if differently signed links report different
          hashes for the same artifact.

    Returns:
      A sorted dictionary mapping stable artifact ids to hash dictionaries.
    """
    if policy is not None:
        policy = SamplingPolicy.read(policy)
        steps = policy.steps
        artifact_type = policy.artifact_type

    if artifact_type not in _ARTIFACT_TYPES:
        raise securesystemslib.exceptions.FormatError(
            "artifact_type must be one of: "
            + ", ".join(sorted(_ARTIFACT_TYPES))
        )

    selected_steps = set(steps or [])
    full_set = {}

    for step_name, link in _collection_links(links):
        if selected_steps and step_name and step_name not in selected_steps:
            continue

        types = (
            ("materials", "products")
            if artifact_type == "both"
            else (artifact_type,)
        )
        for current_type in types:
            artifacts = getattr(link, current_type, {})
            for path, hashes in artifacts.items():
                artifact_id = (
                    f"{current_type}:{path}"
                    if artifact_type == "both"
                    else path
                )
                normalized_hashes = _normalize_hashes(hashes)

                existing = full_set.get(artifact_id)
                if existing is not None and existing != normalized_hashes:
                    message = (
                        "Verified links disagree about hashes for artifact "
                        f"'{artifact_id}'"
                    )
                    if raise_on_conflict:
                        raise in_toto.exceptions.SamplingError(message)
                    continue

                full_set[artifact_id] = normalized_hashes

    if not full_set:
        raise in_toto.exceptions.SamplingError(
            "The signed artifact full set is empty"
        )

    return dict(sorted(full_set.items()))


def collect_full_set_for_policy(policy, links):
    """Collect the full set selected by a sampling policy."""
    policy = SamplingPolicy.read(policy)
    return collect_full_set(
        links,
        steps=policy.steps,
        artifact_type=policy.artifact_type,
    )


def _selection_rank(policy, artifact_id, hashes, current_full_set_digest):
    message = {
        "algorithm": policy.algorithm,
        "artifact": artifact_id,
        "hashes": hashes,
        "full_set_digest": current_full_set_digest,
    }
    return hmac.new(
        policy.seed.encode("utf-8"),
        _canonical_json(message),
        hashlib.sha256,
    ).hexdigest()


def _selection_entry(policy, artifact_id, hashes, current_full_set_digest):
    current_type, path = _artifact_type_for_id(
        artifact_id, policy.artifact_type
    )
    return {
        "artifact": artifact_id,
        "path": path,
        "type": current_type,
        "hashes": hashes,
        "rank": _selection_rank(
            policy, artifact_id, hashes, current_full_set_digest
        ),
    }


def _compute_sample_digest(policy_digest, current_full_set_digest, selection):
    return _sha256_digest(
        _canonical_json(
            {
                "version": SAMPLING_VERSION,
                "algorithm": SAMPLING_ALGORITHM,
                "policy_digest": policy_digest,
                "full_set_digest": current_full_set_digest,
                "selection": selection,
            }
        )
    )


@attr.s(repr=False, init=False)
class SamplingDraw:
    """A deterministic, recomputable draw sheet.

    Attributes:
      policy: The policy used for the draw.
      full_set: The complete signed artifact set the draw was computed from.
      selected: Stable artifact ids selected by the draw.
      selection: Detailed selection entries, including HMAC ranks.
      full_set_digest: Digest of ``full_set``.
      sample_digest: Digest binding policy, full set and selection. Review
          evidence references this value.
    """

    policy = attr.ib()
    full_set = attr.ib()
    selected = attr.ib()
    selection = attr.ib()
    full_set_digest = attr.ib()
    sample_digest = attr.ib()

    def __init__(  # noqa: PLR0913
        self,
        policy,
        full_set,
        selected,
        selection,
        full_set_digest,
        sample_digest,
    ):
        self.policy = SamplingPolicy.read(policy)
        self.full_set = _normalize_full_set(full_set)
        self.selected = list(selected)
        self.selection = copy.deepcopy(list(selection))
        self.full_set_digest = full_set_digest
        self.sample_digest = sample_digest

    def recompute(self):
        """Return a fresh draw for this sheet policy and full set."""
        return compute_draw_sheet(self.policy, self.full_set)

    def verify(self, full_set=None):
        """Verify this sheet against its policy and a full set."""
        return verify_draw_sheet(
            self, self.policy, self.full_set if full_set is None else full_set
        )

    @property
    def draw_sheet_digest(self):
        """Alias used by review evidence and external tooling."""
        return self.sample_digest

    @property
    def sample(self):
        """Alias for the selected artifact ids."""
        return self.selected

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        return {
            "version": SAMPLING_VERSION,
            "algorithm": self.policy.algorithm,
            "policy": self.policy.to_dict(),
            "policy_digest": self.policy.digest,
            "full_set": copy.deepcopy(self.full_set),
            "full_set_digest": self.full_set_digest,
            "sample_size": self.policy.sample_size,
            "selected": list(self.selected),
            "selection": copy.deepcopy(self.selection),
            "sample_digest": self.sample_digest,
        }

    @classmethod
    def from_dict(cls, data):
        """Load a draw sheet and verify its internal digests."""
        if not isinstance(data, dict):
            raise securesystemslib.exceptions.FormatError(
                "Draw sheet must be a dictionary"
            )

        if data.get("version") != SAMPLING_VERSION:
            raise in_toto.exceptions.SamplingVerificationError(
                "Unsupported sampling draw sheet version: "
                f"{data.get('version')}"
            )

        policy = SamplingPolicy.read(data["policy"])
        full_set = _normalize_full_set(data["full_set"])
        selection = copy.deepcopy(data["selection"])
        selected = (
            [entry["artifact"] for entry in selection]
            if "selection" in data
            else list(data["selected"])
        )

        expected_full_set_digest = full_set_digest(full_set)
        if data.get("full_set_digest") != expected_full_set_digest:
            raise in_toto.exceptions.SamplingVerificationError(
                "Draw sheet full-set digest does not match its full set"
            )

        expected_sample_digest = _compute_sample_digest(
            policy.digest, expected_full_set_digest, selection
        )
        if data.get("sample_digest") != expected_sample_digest:
            raise in_toto.exceptions.SamplingVerificationError(
                "Draw sheet sample digest does not match its contents"
            )

        recorded_selected = list(data.get("selected", []))
        if recorded_selected and recorded_selected != selected:
            raise in_toto.exceptions.SamplingVerificationError(
                "Draw sheet 'selected' and 'selection' fields disagree"
            )

        return cls(
            policy,
            full_set,
            selected,
            selection,
            expected_full_set_digest,
            expected_sample_digest,
        )

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf8") as file_object:
            return cls.from_dict(json.load(file_object))

    def dump(self, path):
        with open(path, "w", encoding="utf8") as file_object:
            json.dump(
                self.to_dict(),
                file_object,
                indent=1,
                sort_keys=True,
            )
            file_object.write("\n")


DrawSheet = SamplingDraw
SampleDraw = SamplingDraw


def compute_draw_sheet(policy, full_set):
    """Compute the deterministic draw sheet for a policy and full set."""
    policy = SamplingPolicy.read(policy)
    full_set = _normalize_full_set(full_set)
    current_full_set_digest = full_set_digest(full_set)

    ranked = [
        _selection_entry(policy, artifact_id, hashes, current_full_set_digest)
        for artifact_id, hashes in full_set.items()
    ]
    ranked.sort(key=lambda entry: (entry["rank"], entry["artifact"]))

    sample_size = min(policy.sample_size, len(ranked))
    selection = ranked[:sample_size]
    selected = [entry["artifact"] for entry in selection]
    sample_digest = _compute_sample_digest(
        policy.digest, current_full_set_digest, selection
    )

    return SamplingDraw(
        policy=policy,
        full_set=full_set,
        selected=selected,
        selection=selection,
        full_set_digest=current_full_set_digest,
        sample_digest=sample_digest,
    )


build_draw_sheet = compute_draw_sheet
create_draw_sheet = compute_draw_sheet


def select_sample(policy, full_set):
    """Return the sampled artifact ids, recomputed from policy and full set."""
    return compute_draw_sheet(policy, full_set).selected


recompute_sample = select_sample


def diff_full_sets(recorded, current):
    """Return changed, added and removed artifacts between two full sets."""
    recorded = _normalize_full_set(recorded)
    current = _normalize_full_set(current)

    changed = {
        artifact_id: {
            "old": recorded[artifact_id],
            "new": current[artifact_id],
        }
        for artifact_id in recorded.keys() & current.keys()
        if recorded[artifact_id] != current[artifact_id]
    }
    added = sorted(current.keys() - recorded.keys())
    removed = sorted(recorded.keys() - current.keys())
    return changed, added, removed


def verify_draw_sheet(draw_sheet, policy, full_set):
    """Verify a draw sheet can be recomputed from policy and full set.

    Raises:
      SamplingFullSetChangedError: The signed full set changed after the draw.
      SamplingVerificationError: The policy changed or the recorded selection
          cannot be reproduced.
    """
    if isinstance(draw_sheet, dict):
        draw_sheet = SamplingDraw.from_dict(draw_sheet)
    if not isinstance(draw_sheet, SamplingDraw):
        raise securesystemslib.exceptions.FormatError(
            "draw_sheet must be SamplingDraw or its dictionary representation"
        )

    policy = SamplingPolicy.read(policy)
    full_set = _normalize_full_set(full_set)

    changed, added, removed = diff_full_sets(draw_sheet.full_set, full_set)
    actual_digest = full_set_digest(full_set)
    if changed or added or removed:
        raise in_toto.exceptions.SamplingFullSetChangedError(
            "The signed artifact full set changed after the sampling draw;"
            " recompute the draw and re-verify every artifact",
            expected_digest=draw_sheet.full_set_digest,
            actual_digest=actual_digest,
            changed=changed,
            added=added,
            removed=removed,
        )

    if draw_sheet.policy.digest != policy.digest:
        raise in_toto.exceptions.SamplingVerificationError(
            "The sampling policy differs from the policy bound to the draw"
        )

    recomputed = compute_draw_sheet(policy, full_set)
    if (
        draw_sheet.full_set_digest != recomputed.full_set_digest
        or draw_sheet.sample_digest != recomputed.sample_digest
        or draw_sheet.selected != recomputed.selected
        or draw_sheet.selection != recomputed.selection
    ):
        raise in_toto.exceptions.SamplingVerificationError(
            "Draw sheet cannot be reproduced from its policy and full set"
        )

    return recomputed


def _looks_like_verified_links(value):
    """Return True if value looks like verified links rather than a full set."""
    if isinstance(value, (Link, Metadata)):
        return True
    if not isinstance(value, dict):
        return False

    for item in value.values():
        if isinstance(item, (Link, Metadata)):
            return True
        if isinstance(item, dict) and any(
            isinstance(nested, (Link, Metadata)) for nested in item.values()
        ):
            return True
    return False


def _review_byproducts(link):
    byproducts = link.byproducts or {}
    if not isinstance(byproducts, dict):
        raise in_toto.exceptions.SamplingError(
            "Review evidence byproducts must be a dictionary"
        )

    nested = byproducts.get("sampling")
    if nested is None:
        nested = {}
    elif isinstance(nested, str):
        nested = {"draw_sheet_digest": nested}
    elif not isinstance(nested, dict):
        raise in_toto.exceptions.SamplingError(
            "Review evidence 'sampling' byproduct must be a dictionary"
        )

    merged = dict(byproducts)
    merged.update(nested)
    return merged


def _first_field(mapping, names):
    for name in names:
        if name in mapping and mapping[name] not in (None, ""):
            return mapping[name]
    return None


def _resolve_artifact_id(artifact, artifact_type, selected, full_set, policy):
    if artifact in selected:
        return artifact

    if isinstance(artifact, str) and ":" in artifact:
        prefix, path = artifact.split(":", 1)
        if (
            prefix in ("materials", "products")
            and policy.artifact_type == prefix
            and path in selected
        ):
            return path

    if artifact_type:
        candidate = (
            f"{artifact_type}:{artifact}"
            if policy.artifact_type == "both"
            else artifact
        )
        if candidate in selected:
            return candidate

    matches = [
        artifact_id
        for artifact_id in selected
        if _artifact_type_for_id(artifact_id, policy.artifact_type)[1]
        == artifact
    ]
    if len(matches) == 1:
        return matches[0]

    if artifact in full_set:
        raise in_toto.exceptions.SamplingVerificationError(
            f"Evidence is for artifact '{artifact}', which was not sampled"
        )

    raise in_toto.exceptions.SamplingVerificationError(
        f"Evidence names artifact '{artifact}', which is not in the signed"
        " full set"
    )


@attr.s(repr=False, init=False)
class ReviewEvidence:
    """Parsed and signature-verified review evidence."""

    metadata = attr.ib()
    link = attr.ib()
    artifact_id = attr.ib()
    path = attr.ib()
    artifact_type = attr.ib()
    hashes = attr.ib()
    draw_sheet_digest = attr.ib()
    cutoff = attr.ib()
    reviewed_at = attr.ib()
    keyid = attr.ib()
    name = attr.ib()

    def __init__(self, **kwargs):
        for field in (
            "metadata",
            "link",
            "artifact_id",
            "path",
            "artifact_type",
            "hashes",
            "draw_sheet_digest",
            "cutoff",
            "reviewed_at",
            "keyid",
            "name",
        ):
            setattr(self, field, kwargs.get(field))

    @property
    def reviewed_at_datetime(self):
        return _parse_timestamp(self.reviewed_at, "reviewed_at")

    def to_dict(self):
        return {
            "artifact": self.artifact_id,
            "path": self.path,
            "type": self.artifact_type,
            "hashes": copy.deepcopy(self.hashes),
            "draw_sheet_digest": self.draw_sheet_digest,
            "release_cutoff": self.cutoff,
            "reviewed_at": self.reviewed_at,
            "keyid": self.keyid,
            "name": self.name,
        }


def _metadata_name(metadata, index):
    for attribute in ("filename", "path", "name"):
        value = getattr(metadata, attribute, None)
        if isinstance(value, str) and value:
            return value

    payload = metadata.get_payload() if isinstance(metadata, Metadata) else None
    if payload is not None and isinstance(payload.name, str):
        return payload.name

    return f"review-{index}"


def _normalize_review_keys(review_keys):
    if review_keys is None or isinstance(review_keys, dict):
        return review_keys
    if isinstance(review_keys, (list, tuple)):
        return {key["keyid"]: key for key in review_keys}
    return review_keys


def _verified_reviewer_keyids(metadata, review_keys, policy):
    if not isinstance(metadata, Metadata):
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence must be signed in-toto metadata"
        )

    if not isinstance(review_keys, dict) or not review_keys:
        raise in_toto.exceptions.SamplingVerificationError(
            "Verification keys are required to verify review evidence"
        )

    candidate_keyids = list(review_keys)
    if policy.reviewers:
        candidate_keyids = [
            keyid for keyid in policy.reviewers if keyid in review_keys
        ]

    valid_keyids = []
    for keyid in candidate_keyids:
        try:
            metadata.verify_signature(review_keys[keyid])
        except Exception:  # noqa: BLE001, S112
            continue
        valid_keyids.append(keyid)

    if len(valid_keyids) < policy.threshold:
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence does not carry the required number of valid"
            " reviewer signatures"
        )

    return valid_keyids


def parse_review_evidence(  # noqa: C901, PLR0912, PLR0915
    metadata,
    draw_sheet,
    review_keys=None,
    require_signatures=True,
    index=0,
):
    """Parse review evidence and bind it to a draw sheet and cutoff."""
    review_keys = _normalize_review_keys(review_keys)
    if isinstance(metadata, Metadata):
        link = metadata.get_payload()
    elif isinstance(metadata, Link):
        link = metadata
    else:
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence must be Link or Metadata"
        )

    if not isinstance(link, Link):
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence payload must be a Link"
        )

    valid_keyids = []
    if require_signatures:
        valid_keyids = _verified_reviewer_keyids(
            metadata, review_keys, draw_sheet.policy
        )

    byproducts = _review_byproducts(link)
    artifact = _first_field(
        byproducts, ("artifact", "artifact_id", "artifact_path", "path")
    )
    artifact_type = _first_field(byproducts, ("artifact_type", "type"))
    provided_hashes = _first_field(byproducts, ("artifact_hashes", "hashes"))
    draw_digest = _first_field(
        byproducts,
        (
            "draw_sheet_digest",
            "sampling_digest",
            "sample_digest",
            "draw_digest",
            "draw",
        ),
    )
    cutoff = _first_field(byproducts, ("release_cutoff", "cutoff"))
    reviewed_at = _first_field(
        byproducts,
        (
            "reviewed_at",
            "review_time",
            "reviewed",
            "review_timestamp",
            "reviewed_on",
            "completed_at",
            "signed_at",
            "timestamp",
        ),
    )

    if artifact is None:
        for current_type in ("materials", "products"):
            artifacts = getattr(link, current_type)
            if len(artifacts) == 1:
                artifact = next(iter(artifacts))
                artifact_type = artifact_type or current_type
                break

    if artifact is None:
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence does not identify its artifact"
        )

    if draw_digest is None:
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence does not reference a draw sheet"
        )

    if cutoff is None:
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence does not reference the release cutoff"
        )

    if reviewed_at is None:
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence does not carry a signed review timestamp"
        )

    if draw_digest != draw_sheet.sample_digest:
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence references a different sampling draw"
        )

    if (
        _parse_timestamp(cutoff, "release_cutoff")
        != draw_sheet.policy.cutoff_datetime
    ):
        raise in_toto.exceptions.SamplingVerificationError(
            "Review evidence references a different release cutoff"
        )

    artifact_id = _resolve_artifact_id(
        artifact,
        artifact_type,
        draw_sheet.selected,
        draw_sheet.full_set,
        draw_sheet.policy,
    )
    current_type, path = _artifact_type_for_id(
        artifact_id, draw_sheet.policy.artifact_type
    )

    link_artifacts = getattr(link, current_type)
    link_hashes = link_artifacts.get(path)
    if link_hashes is None:
        raise in_toto.exceptions.SamplingVerificationError(
            f"Review evidence does not record hashes for '{artifact_id}'"
        )
    link_hashes = _normalize_hashes(link_hashes)

    if (
        provided_hashes is not None
        and _normalize_hashes(provided_hashes) != link_hashes
    ):
        raise in_toto.exceptions.SamplingVerificationError(
            f"Review evidence hashes disagree for '{artifact_id}'"
        )

    expected_hashes = draw_sheet.full_set[artifact_id]
    if link_hashes != expected_hashes:
        raise in_toto.exceptions.SamplingVerificationError(
            f"Review evidence is stale for '{artifact_id}'"
        )

    reviewed_at_dt = _parse_timestamp(reviewed_at, "reviewed_at")
    if reviewed_at_dt <= draw_sheet.policy.cutoff_datetime:
        cutoff_status = "on-time"
    else:
        cutoff_status = "late"

    return (
        ReviewEvidence(
            metadata=metadata,
            link=link,
            artifact_id=artifact_id,
            path=path,
            artifact_type=current_type,
            hashes=expected_hashes,
            draw_sheet_digest=draw_digest,
            cutoff=cutoff,
            reviewed_at=reviewed_at,
            keyid=valid_keyids[0] if valid_keyids else None,
            name=_metadata_name(metadata, index),
        ),
        cutoff_status,
    )


@attr.s(repr=False, init=False)
class SamplingResult:
    """Result of sampling acceptance verification.

    ``accepted`` and ``late`` map sampled artifact ids to evidence. ``late``
    is deliberately preserved when verification fails so the same evidence can
    be used in a later re-review.
    """

    draw_sheet = attr.ib()
    accepted = attr.ib()
    late = attr.ib()
    missing = attr.ib()
    invalid = attr.ib()

    def __init__(
        self, draw_sheet, accepted=None, late=None, missing=None, invalid=None
    ):
        self.draw_sheet = draw_sheet
        self.accepted = accepted or {}
        self.late = late or {}
        self.missing = list(missing or [])
        self.invalid = list(invalid or [])

    @property
    def passed(self):
        return (
            not self.missing
            and not self.invalid
            and all(
                artifact_id in self.accepted
                for artifact_id in self.draw_sheet.selected
            )
        )

    @property
    def late_artifacts(self):
        return sorted(self.late)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        return {
            "passed": self.passed,
            "cutoff": self.draw_sheet.policy.cutoff,
            "draw_sheet": self.draw_sheet.to_dict(),
            "accepted": {
                artifact_id: [evidence.to_dict() for evidence in evidences]
                for artifact_id, evidences in sorted(self.accepted.items())
            },
            "late": {
                artifact_id: [evidence.to_dict() for evidence in evidences]
                for artifact_id, evidences in sorted(self.late.items())
            },
            "missing": list(self.missing),
            "invalid": copy.deepcopy(self.invalid),
        }

    def dump(self, path):
        with open(path, "w", encoding="utf8") as file_object:
            json.dump(
                self.to_dict(),
                file_object,
                indent=1,
                sort_keys=True,
            )
            file_object.write("\n")

    def raise_for_status(self):
        """Raise a sampling exception if acceptance did not pass."""
        if self.passed:
            return

        if (
            self.missing
            and not self.invalid
            and all(artifact in self.late for artifact in self.missing)
        ):
            raise in_toto.exceptions.SamplingCutoffError(
                "Review evidence for sampled artifacts is late and has been"
                " retained for re-review: " + ", ".join(self.missing),
                result=self,
            )

        details = []
        if self.missing:
            details.append("missing: " + ", ".join(self.missing))
        if self.invalid:
            details.append(
                "invalid: "
                + ", ".join(
                    str(item.get("artifact", item.get("reason", "unknown")))
                    for item in self.invalid
                )
            )
        if self.late:
            details.append(
                "late retained for re-review: " + ", ".join(self.late_artifacts)
            )

        raise in_toto.exceptions.SamplingVerificationError(
            "Sampling acceptance failed"
            + (": " + "; ".join(details) if details else ""),
            result=self,
        )


SamplingAcceptance = SamplingResult


def _iter_review_metadata(review_metadata):
    if review_metadata is None:
        return []
    if isinstance(review_metadata, (Metadata, Link)):
        return [review_metadata]
    if isinstance(review_metadata, (str, os.PathLike)):
        return [Metadata.load(review_metadata)]
    if isinstance(review_metadata, dict):
        review_metadata = review_metadata.values()
    if isinstance(review_metadata, (list, tuple, set)) or hasattr(
        review_metadata, "__iter__"
    ):
        metadata_items = []
        for item in review_metadata:
            metadata_items.extend(_iter_review_metadata(item))
        return metadata_items
    raise securesystemslib.exceptions.FormatError(
        "Review evidence must be metadata, a path, or a collection thereof"
    )


def verify_sampling_acceptance(  # noqa: C901, PLR0913
    policy,
    full_set,
    review_metadata,
    review_keys=None,
    draw_sheet=None,
    require_signatures=True,
    raise_on_failure=True,
    write_draw_sheet=None,
    write_result=None,
):
    """Verify optional sampling acceptance for a signed release full set.

    Arguments:
      policy: SamplingPolicy or its dictionary representation.
      full_set: The complete signed artifact set, recomputed from verified
          links.
      review_metadata: Signed review Link/Metadata objects, or paths to them.
      review_keys: Dictionary of reviewer public keys. Required unless
          ``require_signatures`` is false.
      draw_sheet: Previously issued draw sheet. If passed, it is checked
          against the current full set before evidence is considered.
      require_signatures: Require signed review metadata (default true).
      raise_on_failure: Raise the corresponding sampling exception when
          acceptance fails (default true).
      write_draw_sheet: Optional path to write the recomputable draw sheet.
      write_result: Optional path to write the full acceptance result,
          including late evidence retained for re-review.

    Returns:
      SamplingResult.
    """
    policy = SamplingPolicy.read(policy)
    review_keys = _normalize_review_keys(review_keys)
    if _looks_like_verified_links(full_set):
        full_set = collect_full_set_for_policy(policy, full_set)
    else:
        full_set = _normalize_full_set(full_set)

    if draw_sheet is None:
        draw_sheet = compute_draw_sheet(policy, full_set)
    else:
        try:
            draw_sheet = verify_draw_sheet(draw_sheet, policy, full_set)
        except in_toto.exceptions.SamplingFullSetChangedError as exc:
            replacement_draw = compute_draw_sheet(policy, full_set)
            result = SamplingResult(
                draw_sheet=replacement_draw,
                missing=list(replacement_draw.selected),
                invalid=[{"artifact": None, "reason": str(exc)}],
            )
            if write_draw_sheet:
                replacement_draw.dump(write_draw_sheet)
            if write_result:
                result.dump(write_result)
            exc.result = result
            raise

    accepted = {}
    late = {}
    invalid = []

    for index, metadata in enumerate(_iter_review_metadata(review_metadata)):
        try:
            evidence, cutoff_status = parse_review_evidence(
                metadata,
                draw_sheet,
                review_keys=review_keys,
                require_signatures=require_signatures,
                index=index,
            )
        except (
            in_toto.exceptions.SamplingError,
            securesystemslib.exceptions.FormatError,
            KeyError,
            ValueError,
        ) as exc:
            invalid.append(
                {
                    "artifact": None,
                    "reason": str(exc),
                    "evidence": _metadata_name(metadata, index),
                }
            )
            continue

        target = accepted if cutoff_status == "on-time" else late
        target.setdefault(evidence.artifact_id, []).append(evidence)

    missing = [
        artifact_id
        for artifact_id in draw_sheet.selected
        if artifact_id not in accepted
    ]
    result = SamplingResult(
        draw_sheet=draw_sheet,
        accepted=accepted,
        late=late,
        missing=missing,
        invalid=invalid,
    )

    if write_draw_sheet:
        draw_sheet.dump(write_draw_sheet)
    if write_result:
        result.dump(write_result)

    if raise_on_failure:
        result.raise_for_status()

    return result


check_sampling_acceptance = verify_sampling_acceptance
verify_release_sampling = verify_sampling_acceptance


def verify_sampling_for_links(
    policy,
    links,
    review_metadata,
    **kwargs,
):
    """Convenience wrapper that builds the full set from verified links."""
    policy = SamplingPolicy.read(policy)
    full_set = collect_full_set_for_policy(policy, links)
    return verify_sampling_acceptance(
        policy,
        full_set,
        review_metadata,
        **kwargs,
    )


def create_review_evidence(  # noqa: PLR0913
    artifact,
    hashes,
    draw_sheet,
    reviewed_at,
    signer,
    name="sampling-review",
    artifact_type=None,
):
    """Create and sign in-toto link metadata for one sampled artifact.

    The signed ``byproducts`` bind the evidence to ``draw_sheet`` and to the
    draw's release cutoff.
    """
    policy = draw_sheet.policy
    artifact_id = _resolve_artifact_id(
        artifact,
        artifact_type,
        draw_sheet.selected,
        draw_sheet.full_set,
        policy,
    )
    current_type, path = _artifact_type_for_id(
        artifact_id, policy.artifact_type
    )
    hashes = _normalize_hashes(hashes)

    if hashes != draw_sheet.full_set[artifact_id]:
        raise in_toto.exceptions.SamplingVerificationError(
            f"Hashes do not match the sampled artifact '{artifact_id}'"
        )

    _parse_timestamp(reviewed_at, "reviewed_at")

    materials = {path: hashes} if current_type == "materials" else {}
    products = {path: hashes} if current_type == "products" else {}
    byproducts = {
        "artifact": artifact_id,
        "artifact_type": current_type,
        "artifact_hashes": hashes,
        "draw_sheet_digest": draw_sheet.sample_digest,
        "release_cutoff": policy.cutoff,
        "reviewed_at": reviewed_at,
    }

    metadata = Metablock(
        signed=Link(
            name=name,
            materials=materials,
            products=products,
            byproducts=byproducts,
        )
    )
    metadata.create_signature(signer)
    return metadata


def load_verified_links(link_dir_path, step_name):
    """Load all link metadata files for a step from a directory.

    This helper is useful when a release verifier has already authenticated
    links and only needs the corresponding Link objects for sampling.
    """
    pattern = os.path.join(link_dir_path, f"{glob.escape(step_name)}.*.link")
    links = {}
    for path in sorted(glob.glob(pattern)):
        links[path] = Metadata.load(path)
    return links
