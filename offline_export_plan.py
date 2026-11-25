"""Offline minimal role-export planner for a TUF repository mirror.

The maintenance contract only lets the review group see proof that two
targets belong to approved update roles.  Sending every role file of the
mirror would exceed the approved material scope.  This module computes the
*minimal* set of signed TUF role files sufficient for that review from:

1. the role metadata already present in the mirror,
2. target hit conditions (target paths resolved through delegations), and
3. a caller-supplied *transferability manifest* (which materials may leave
   the repository).

The planner never fills a gap with an unsigned alias (a delegation pointer
or any unsigned copy of a role) or with an arbitrary digest.  Missing signed
material is reported as a missing item together with the exact unattested
scope.  Two requests sharing a parent-role segment are merged into one
deduplicated handoff list when every required material is deliverable;
otherwise the merged answer is a deficiency report.

The module is standard-library only for planning; signature verification is
optional and uses ``tuf``/``securesystemslib`` when ``verify_crypto=True``.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

TOP_LEVEL_ORDER = ("root", "timestamp", "snapshot", "targets")

# Extra top-level roles required by each assurance level.
# "membership" proves target -> delegated role -> root anchor.
# "consistent" additionally binds role versions/hashes through snapshot.
# "full" additionally proves freshness/rollback protection via timestamp.
ASSURANCE_EXTRA_ROLES: dict[str, tuple[str, ...]] = {
    "membership": (),
    "consistent": ("snapshot",),
    "full": ("snapshot", "timestamp"),
    "update": ("snapshot", "timestamp"),
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _normalize_entry(entry: str) -> str:
    text = str(entry).replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("/") if len(text) > 1 else text


def _canonical_json_bytes(signed: Mapping[str, Any]) -> bytes:
    """OLPC canonical JSON bytes, used only by optional crypto checks."""
    from securesystemslib.formats import encode_canonical

    encoded = encode_canonical(dict(signed))
    assert encoded is not None  # noqa: S101 - sslib contract
    return encoded.encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _segment_glob_match(target: str, pattern: str) -> bool:
    """Match TUF path patterns (``*`` does not cross ``/`` segments)."""

    import fnmatch

    target_parts = target.split("/")
    pattern_parts = pattern.split("/")
    if len(target_parts) != len(pattern_parts):
        return False
    return all(
        fnmatch.fnmatchcase(part, pat)
        for part, pat in zip(target_parts, pattern_parts, strict=True)
    )


def _hash_prefix_match(target: str, prefixes: Sequence[str]) -> bool:
    target_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()
    return any(target_hash.startswith(prefix) for prefix in prefixes)


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


@dataclass
class TargetRequest:
    """One export/review request: one or more target hit conditions."""

    request_id: str
    targets: list[str]
    approved_roles: list[str] | None = None

    @classmethod
    def coerce(cls, value: "TargetRequest | Mapping[str, Any] | str") -> "TargetRequest":
        if isinstance(value, TargetRequest):
            return value
        if isinstance(value, str):
            return cls(request_id=value, targets=[value])
        if not isinstance(value, Mapping):
            raise TypeError(f"unsupported request value: {value!r}")

        request_id = str(
            value.get("request_id")
            or value.get("id")
            or value.get("name")
            or "request"
        )
        raw_targets = value.get("targets", value.get("target", value.get("path")))
        if raw_targets is None:
            raise ValueError(f"request {request_id!r} has no target condition")
        if isinstance(raw_targets, str):
            targets = [raw_targets]
        else:
            targets = [str(item) for item in raw_targets]
        approved = value.get("approved_roles", value.get("approved_role"))
        if isinstance(approved, str):
            approved_roles = [approved]
        elif approved is None:
            approved_roles = None
        else:
            approved_roles = [str(item) for item in approved]
        return cls(request_id, targets, approved_roles)


@dataclass
class TransferManifest:
    """Caller-supplied list of materials allowed to leave the repository.

    Entries may be repository-relative references (``metadata/root.json``),
    bare file names (``root.json``), or ``"*"`` / directory globs
    (``metadata/*``).  An entry may also be an object
    ``{"path": "metadata/root.json", "signatures": false}`` when the payload
    file itself is transferable but its signature material is not.
    """

    allowed: set[str] = field(default_factory=set)
    denied: set[str] = field(default_factory=set)
    signature_blocked: set[str] = field(default_factory=set)
    substitutes: list[dict[str, Any]] = field(default_factory=list)
    raw: Any = None

    @classmethod
    def from_obj(cls, obj: "TransferManifest | Mapping[str, Any] | Sequence[str] | None") -> "TransferManifest":
        if isinstance(obj, TransferManifest):
            return obj
        if obj is None:
            return cls()
        if isinstance(obj, (list, tuple, set)):
            allowed: set[str] = set()
            denied: set[str] = set()
            blocked: set[str] = set()
            for item in obj:
                if isinstance(item, Mapping):
                    path = item.get("path") or item.get("ref") or item.get("material")
                    is_denied = item.get("transferable") is False or item.get(
                        "allow"
                    ) is False or item.get("deny") is True
                    if path:
                        ref_text = _normalize_entry(str(path))
                        if is_denied:
                            denied.add(ref_text)
                        else:
                            allowed.add(ref_text)
                    if item.get("signatures") is False or item.get("signature") is False:
                        if path:
                            blocked.add(_normalize_entry(str(path)))
                        if item.get("role"):
                            blocked.add(str(item["role"]))
                else:
                    allowed.add(_normalize_entry(str(item)))
            return cls(
                allowed=allowed,
                denied=denied,
                signature_blocked=blocked,
                raw=obj,
            )

        if not isinstance(obj, Mapping):
            raise TypeError(f"unsupported manifest value: {obj!r}")

        materials = obj.get(
            "transferable_materials",
            obj.get("materials", obj.get("allow", obj.get("files", []))),
        )
        manifest = cls.from_obj(materials)
        for key in ("denied_materials", "deny", "not_transferable", "blocked_files"):
            for item in obj.get(key, []) or []:
                if isinstance(item, Mapping):
                    path = item.get("path") or item.get("ref")
                    if path:
                        manifest.denied.add(_normalize_entry(str(path)))
                else:
                    manifest.denied.add(_normalize_entry(str(item)))
        for role in obj.get("block_signatures_for", []) or []:
            manifest.signature_blocked.add(str(role))
        for item in obj.get("signature_blocked", []) or []:
            manifest.signature_blocked.add(_normalize_entry(str(item)))
        manifest.substitutes = list(obj.get("substitutes", []) or [])
        manifest.raw = obj
        return manifest

    @classmethod
    def from_file(cls, path: str | Path) -> "TransferManifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_obj(data)

    def _entry_matches(self, entry: str, candidates: Sequence[str]) -> bool:
        if entry == "*":
            return True
        if entry.endswith("/*"):
            prefix = entry[:-2]
            return any(
                candidate == prefix or candidate.startswith(prefix + "/")
                for candidate in candidates
            )
        for candidate in candidates:
            if entry == candidate:
                return True
            if "/" not in entry and entry == candidate.rsplit("/", 1)[-1]:
                return True
        return False

    def allows(self, *candidates: str) -> bool:
        normalized = [_normalize_entry(c) for c in candidates if c]
        if any(
            self._entry_matches(entry, normalized) for entry in self.denied
        ):
            return False
        return any(
            self._entry_matches(entry, normalized) for entry in self.allowed
        )

    def signatures_deliverable(self, role: str, *path_candidates: str) -> bool:
        candidates = [role] + [
            _normalize_entry(c) for c in path_candidates if c
        ]
        for blocked in self.signature_blocked:
            blocked_norm = _normalize_entry(blocked) if "/" in blocked else blocked
            if blocked_norm == role or self._entry_matches(
                blocked_norm, candidates[1:]
            ):
                return False
        return True


# ---------------------------------------------------------------------------
# Mirror loading and delegation resolution
# ---------------------------------------------------------------------------


@dataclass
class RoleFile:
    role: str
    path: Path
    ref: str
    doc: dict[str, Any]

    @property
    def signed(self) -> dict[str, Any]:
        signed = self.doc.get("signed")
        return signed if isinstance(signed, dict) else {}

    @property
    def signatures(self) -> list[dict[str, Any]]:
        sigs = self.doc.get("signatures")
        return sigs if isinstance(sigs, list) else []


@dataclass
class Mirror:
    """A local TUF repository mirror (metadata directory + role docs)."""

    root_dir: Path
    metadata_dir: Path
    ref_prefix: str
    roles: dict[str, RoleFile]
    parse_errors: dict[str, str]

    @classmethod
    def load(cls, path: str | Path) -> "Mirror":
        root = Path(path)
        if not root.exists():
            raise FileNotFoundError(f"mirror path does not exist: {root}")

        if (root / "metadata" / "root.json").is_file() or (
            root / "metadata"
        ).is_dir():
            metadata_dir = root / "metadata"
            mirror_root = root
        elif (root / "root.json").is_file():
            metadata_dir = root
            mirror_root = root.parent if root.parent.name == "metadata" else root.parent
        else:
            # Fall back to treating the path itself as metadata directory.
            metadata_dir = root
            mirror_root = root.parent

        ref_prefix = "metadata" if metadata_dir.name == "metadata" else metadata_dir.name
        roles: dict[str, RoleFile] = {}
        parse_errors: dict[str, str] = {}

        if metadata_dir.is_dir():
            plain: dict[str, Path] = {}
            versioned: dict[str, list[tuple[int, Path]]] = {}
            for file_path in sorted(metadata_dir.glob("*.json")):
                stem = file_path.name[: -len(".json")]
                parts = stem.split(".", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    role = parts[1]
                    versioned.setdefault(role, []).append((int(parts[0]), file_path))
                else:
                    plain[stem] = file_path

            selected: dict[str, Path] = dict(plain)
            for role, candidates in versioned.items():
                if role not in selected:
                    selected[role] = max(candidates, key=lambda item: item[0])[1]

            for role, file_path in sorted(selected.items()):
                ref = f"{ref_prefix}/{file_path.name}"
                try:
                    doc = json.loads(file_path.read_text(encoding="utf-8"))
                    if not isinstance(doc, Mapping):
                        raise ValueError("metadata root is not a JSON object")
                    roles[role] = RoleFile(role, file_path, ref, dict(doc))
                except (OSError, json.JSONDecodeError, ValueError) as exc:
                    parse_errors[ref] = str(exc)

        return cls(
            root_dir=mirror_root,
            metadata_dir=metadata_dir,
            ref_prefix=ref_prefix,
            roles=roles,
            parse_errors=parse_errors,
        )

    def candidate_refs(self, role: str) -> list[str]:
        role_file = self.roles.get(role)
        file_name = f"{role}.json"
        refs = [f"{self.ref_prefix}/{file_name}", f"metadata/{file_name}", file_name]
        if role_file is not None and role_file.ref not in refs:
            refs.insert(0, role_file.ref)
        return refs

    def all_role_names_on_disk(self) -> list[str]:
        return sorted(self.roles)


@dataclass
class TargetResolution:
    target: str
    found: bool
    chain: list[str] = field(default_factory=list)
    hit_role: str | None = None
    edges: list[tuple[str, str]] = field(default_factory=list)
    error: str | None = None


def _delegations_of(role_file: RoleFile | None) -> list[dict[str, Any]]:
    if role_file is None:
        return []
    delegations = role_file.signed.get("delegations")
    if not isinstance(delegations, Mapping):
        return []
    roles = delegations.get("roles")
    return [dict(item) for item in roles if isinstance(item, Mapping)] if isinstance(roles, list) else []


def _delegation_matches(delegation: Mapping[str, Any], target: str) -> bool:
    if delegation.get("path_hash_prefixes"):
        prefixes = [str(p) for p in delegation["path_hash_prefixes"]]
        return _hash_prefix_match(target, prefixes)
    paths = delegation.get("paths")
    if isinstance(paths, list) and paths:
        return any(_segment_glob_match(target, str(pattern)) for pattern in paths)
    # No paths/path_hash_prefixes means no authority over any target.
    return False


def resolve_target(mirror: Mirror, target: str) -> TargetResolution:
    """Resolve ``target`` to its hit role following TUF delegation order.

    The returned chain starts at ``targets`` and ends at the role whose
    ``targets`` dictionary contains the target.  The first successful
    depth-first traversal is the minimal witness; ``terminating`` delegations
    stop backtracking exactly as in TUF.
    """

    if "targets" not in mirror.roles:
        return TargetResolution(target, False, error="top-level targets role missing")

    visited: set[str] = set()
    deepest_chain = ["targets"]
    deepest_edges: list[tuple[str, str]] = []

    def dfs(role_name: str, chain: list[str], edges: list[tuple[str, str]]) -> TargetResolution | None:
        if role_name in visited:
            return None
        visited.add(role_name)
        current_chain = chain + [role_name]
        if len(current_chain) > len(deepest_chain):
            deepest_chain[:] = current_chain
            deepest_edges[:] = edges
        role_file = mirror.roles.get(role_name)
        if role_file is None:
            return None

        target_map = role_file.signed.get("targets")
        if isinstance(target_map, Mapping) and target in target_map:
            return TargetResolution(
                target=target,
                found=True,
                chain=chain + [role_name],
                hit_role=role_name,
                edges=edges,
            )

        for delegation in _delegations_of(role_file):
            child_name = str(delegation.get("name", ""))
            if not child_name or child_name in visited:
                continue
            if not _delegation_matches(delegation, target):
                continue
            next_chain = chain + [role_name] if not chain or chain[-1] != role_name else chain
            next_edges = edges + [(role_name, child_name)]
            result = dfs(child_name, next_chain, next_edges)
            if result is not None:
                return result
            if delegation.get("terminating"):
                break
        return None

    resolution = dfs("targets", [], [])
    if resolution is not None:
        # DFS bookkeeping may double-add the starting role; normalize.
        normalized: list[str] = []
        for role in resolution.chain:
            if not normalized or normalized[-1] != role:
                normalized.append(role)
        resolution.chain = normalized
        return resolution

    return TargetResolution(
        target,
        False,
        chain=list(deepest_chain),
        edges=list(deepest_edges),
        error="target is not listed in any reachable delegated role",
    )


# ---------------------------------------------------------------------------
# Planning records
# ---------------------------------------------------------------------------


@dataclass
class MissingMaterial:
    role: str | None
    ref: str
    code: str
    reason: str
    required_by: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)


@dataclass
class RejectedSubstitute:
    role: str | None
    ref: str
    kind: str
    code: str
    reason: str


@dataclass
class UnattestedClaim:
    request_id: str | None
    target: str | None
    scope: str
    cause: str  # missing_material | assurance_level_excluded | out_of_material_scope
    claim: str
    blocked_by: list[str] = field(default_factory=list)


@dataclass
class RoleRecord:
    role: str
    ref: str
    status: str  # ready | not_transferable | file_absent | signature_material_blocked | insufficient_signatures | invalid_signature
    required: bool = True
    sha256: str | None = None
    size: int | None = None
    via_requests: list[str] = field(default_factory=list)
    detail: str | None = None
    signature_status: str | None = None


@dataclass
class RequestPlan:
    request_id: str
    targets: list[str]
    found: bool
    complete: bool
    approved: bool
    roles: list[str]
    shared_prefix: list[str]
    records: list[RoleRecord]
    missing: list[MissingMaterial]
    unattested_scope: list[UnattestedClaim]
    resolutions: list[dict[str, Any]]

    @property
    def handoff_files(self) -> list[str]:
        return [record.ref for record in self.records if record.status == "ready"]

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ExportPlan:
    mirror: str
    assurance_level: str
    status: str
    mergeable: bool
    sufficient: bool
    requests: list[RequestPlan]
    minimal_roles: list[str]
    shared_roles: list[str]
    role_records: list[RoleRecord]
    missing: list[MissingMaterial]
    unattested_scope: list[UnattestedClaim]
    rejected_substitutes: list[RejectedSubstitute]
    excluded_roles: list[str]
    handoff_files: list[str]
    certified_handoff_files: list[str]
    required_files: list[str]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @property
    def files(self) -> list[str]:
        """Alias for :attr:`handoff_files` (the transferable role-file refs)."""

        return self.handoff_files

    @property
    def roles(self) -> list[str]:
        """Alias for :attr:`minimal_roles`."""

        return self.minimal_roles

    @property
    def gaps(self) -> list[MissingMaterial]:
        """Alias for :attr:`missing`."""

        return self.missing

    @property
    def unattested(self) -> list[UnattestedClaim]:
        """Alias for :attr:`unattested_scope`."""

        return self.unattested_scope

    # Convenience mapping-style access for callers/tests that treat the
    # result as a report dictionary.
    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


# ---------------------------------------------------------------------------
# Authorization / signature checks
# ---------------------------------------------------------------------------


def _authorization_for(mirror: Mirror, role: str) -> tuple[set[str] | None, int | None]:
    """Return (authorized keyids, threshold) if discoverable from metadata."""

    if role in TOP_LEVEL_ORDER and "root" in mirror.roles:
        roles = mirror.roles["root"].signed.get("roles")
        if isinstance(roles, Mapping) and isinstance(roles.get(role), Mapping):
            entry = roles[role]
            keyids = {str(k) for k in entry.get("keyids", [])}
            threshold = entry.get("threshold")
            return keyids, int(threshold) if isinstance(threshold, int) else None

    # Delegated role: find its delegation entry in any available parent.
    for parent in mirror.roles.values():
        for delegation in _delegations_of(parent):
            if delegation.get("name") == role:
                keyids = {str(k) for k in delegation.get("keyids", [])}
                threshold = delegation.get("threshold")
                return keyids, int(threshold) if isinstance(threshold, int) else None
    return None, None


def _structural_signature_status(mirror: Mirror, role: str) -> str | None:
    """Return an error code if embedded signatures fail structural checks."""

    role_file = mirror.roles.get(role)
    if role_file is None:
        return None
    keyids, threshold = _authorization_for(mirror, role)
    sig_keyids = {
        str(sig.get("keyid"))
        for sig in role_file.signatures
        if sig.get("keyid") and sig.get("sig")
    }
    if threshold is None:
        # Authorization unknown (usually because root/parent is missing).
        # Require at least one well-formed signature envelope.
        return None if sig_keyids else "insufficient_signatures"

    authorized_present = sig_keyids & keyids if keyids is not None else sig_keyids
    required_threshold = threshold or 1
    if len(authorized_present) < required_threshold:
        return "insufficient_signatures"
    return None


def _crypto_verify_request(mirror: Mirror, resolutions: Sequence[TargetResolution], included_roles: set[str]) -> dict[str, str]:
    """Optionally verify signatures with the real TUF model.

    Returns a mapping role -> error message for roles that failed
    cryptographic verification.
    """

    errors: dict[str, str] = {}
    try:
        from tuf.api.metadata import Metadata  # type: ignore
    except Exception as exc:  # pragma: no cover - environment dependent
        return {"__planner__": f"tuf metadata API unavailable: {exc}"}

    metadata: dict[str, Metadata] = {}
    for role in included_roles:
        role_file = mirror.roles.get(role)
        if role_file is None:
            continue
        try:
            # Metadata.from_dict mutates the supplied mapping (it pops
            # "signatures"/"signed" fields); verify against a deep copy so
            # the planner's pristine mirror documents stay reusable.
            metadata[role] = Metadata.from_dict(copy.deepcopy(role_file.doc))
        except Exception as exc:
            errors[role] = f"metadata parse/model error: {exc}"

    root_md = metadata.get("root")
    if root_md is not None:
        try:
            root_md.verify_delegate("root", root_md)  # type: ignore[arg-type]
        except Exception as exc:
            errors["root"] = f"root self-verification failed: {exc}"

        for top_role in ("timestamp", "snapshot", "targets"):
            candidate = metadata.get(top_role)
            if candidate is None or "root" in errors:
                continue
            try:
                root_md.verify_delegate(top_role, candidate)
            except Exception as exc:
                errors[top_role] = f"{top_role} signature verification failed: {exc}"

    seen_edges: set[tuple[str, str]] = set()
    for resolution in resolutions:
        for parent, child in resolution.edges:
            if (parent, child) in seen_edges:
                continue
            seen_edges.add((parent, child))
            parent_md = metadata.get(parent)
            child_md = metadata.get(child)
            if parent_md is None or child_md is None:
                continue
            try:
                parent_md.verify_delegate(child, child_md)
            except Exception as exc:
                errors[child] = f"delegation {parent} -> {child} verification failed: {exc}"
    return errors


# ---------------------------------------------------------------------------
# Substitutes (unsigned aliases / arbitrary digests)
# ---------------------------------------------------------------------------


def evaluate_substitutes(
    mirror: Mirror,
    manifest: TransferManifest,
    interesting_roles: Iterable[str],
) -> list[RejectedSubstitute]:
    """Reject every alias/digest offered in place of signed role material."""

    rejected: list[RejectedSubstitute] = []
    interesting = set(interesting_roles)

    def add(role: str | None, ref: str, kind: str, code: str, reason: str) -> None:
        rejected.append(
            RejectedSubstitute(
                role=role, ref=ref, kind=kind, code=code, reason=reason
            )
        )

    # Explicitly offered substitutes from the manifest/caller.
    for offer in manifest.substitutes:
        if not isinstance(offer, Mapping):
            continue
        role = offer.get("role")
        role_name = str(role) if role else None
        alias = offer.get("unsigned_alias") or offer.get("alias")
        if alias:
            ref = str(alias)
            add(
                role_name,
                ref,
                "unsigned_alias",
                "rejected_unsigned_alias",
                "An unsigned alias/delegation pointer is not signed role "
                "metadata and cannot establish authorization or threshold "
                "signatures.",
            )
        digests = offer.get("digests", [])
        if isinstance(digests, str):
            digests = [digests]
        for digest in digests or []:
            if isinstance(digest, Mapping):
                ref = str(digest.get("ref") or digest.get("algorithm") or "digest")
            else:
                ref = f"digest:{str(digest)[:12]}..."
            add(
                role_name,
                ref,
                "arbitrary_digest",
                "rejected_arbitrary_digest",
                "A caller-supplied or standalone digest is not signed role "
                "or signature material. It can only check bytes already held "
                "and cannot replace a missing signed role or trust anchor.",
            )

    # Auto-discovered temptation files planted next to a missing role.
    if mirror.metadata_dir.is_dir():
        for role in interesting:
            patterns = [
                f"{role}.alias*",
                f"{role}-alias*",
                f"{role}.unsigned*",
                f"{role}-unsigned*",
                f"{role}.sha256",
                f"{role}.digest",
                f"{role}.json.sha256",
            ]
            seen: set[Path] = set()
            for pattern in patterns:
                for candidate in mirror.metadata_dir.glob(pattern):
                    if candidate in seen or not candidate.is_file():
                        continue
                    seen.add(candidate)
                    ref = f"{mirror.ref_prefix}/{candidate.name}"
                    if "sha256" in candidate.name or "digest" in candidate.name:
                        add(
                            role,
                            ref,
                            "arbitrary_digest",
                            "rejected_arbitrary_digest",
                            "Standalone digest file cannot substitute for the "
                            f"missing signed {role} role material.",
                        )
                    else:
                        add(
                            role,
                            ref,
                            "unsigned_alias",
                            "rejected_unsigned_alias",
                            f"File {candidate.name!r} is an unsigned alias "
                            f"for {role!r}; it carries no threshold signatures "
                            "and cannot fill the missing material.",
                        )
    # Deduplicate by (role, ref, code).
    unique: dict[tuple[str | None, str, str], RejectedSubstitute] = {}
    for item in rejected:
        unique[(item.role, item.ref, item.code)] = item
    return list(unique.values())


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def _required_roles_for_resolutions(
    resolutions: Sequence[TargetResolution], assurance_level: str
) -> list[str]:
    extra = ASSURANCE_EXTRA_ROLES.get(assurance_level)
    if extra is None:
        raise ValueError(
            f"unknown assurance_level {assurance_level!r}; "
            f"expected one of {sorted(ASSURANCE_EXTRA_ROLES)}"
        )
    ordered: list[str] = ["root", *extra]
    for resolution in resolutions:
        for role in resolution.chain:
            if role not in ordered:
                ordered.append(role)
    # Canonical top-level ordering for the top-level roles we included.
    head = [role for role in TOP_LEVEL_ORDER if role in ordered]
    tail = [role for role in ordered if role not in TOP_LEVEL_ORDER]
    result = head + tail
    # De-duplicate while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for role in result:
        if role not in seen:
            seen.add(role)
            deduped.append(role)
    return deduped


def _role_claim(role: str) -> tuple[str, str]:
    claims = {
        "root": ("trust_anchor", "root anchors authorized keys and thresholds"),
        "timestamp": ("freshness", "timestamp proves snapshot freshness / rollback window"),
        "snapshot": ("snapshot_consistency", "snapshot binds role versions and hashes consistently"),
        "targets": ("top_level_delegation", "top-level targets role authorizes first delegation"),
    }
    return claims.get(
        role,
        ("delegation_authorization", f"signed role {role} authorizes its delegations/targets"),
    )


def plan_request(
    mirror: Mirror,
    manifest: TransferManifest | Mapping[str, Any] | Sequence[str] | None,
    request: TargetRequest | Mapping[str, Any] | str,
    assurance_level: str = "membership",
    verify_crypto: bool = False,
    enforce_signatures: bool = True,
) -> RequestPlan:
    """Compute the minimal role set and deficiencies for one request."""

    transfer = TransferManifest.from_obj(manifest)
    req = TargetRequest.coerce(request)

    resolutions = [resolve_target(mirror, target) for target in req.targets]
    found = all(item.found for item in resolutions)

    roles = _required_roles_for_resolutions(resolutions, assurance_level)
    # A target that could not be resolved still needs the traversed metadata;
    # ensure targets is present so the deficiency is explainable.
    if not resolutions or any(not item.found for item in resolutions):
        if "targets" in mirror.roles and "targets" not in roles:
            roles.insert(0 if roles and roles[0] == "root" else 0, "targets")

    crypto_errors: dict[str, str] = {}
    if verify_crypto:
        crypto_errors = _crypto_verify_request(mirror, resolutions, set(roles))

    records: list[RoleRecord] = []
    missing: list[MissingMaterial] = []
    unattested: list[UnattestedClaim] = []

    approved = True
    for resolution in resolutions:
        if not resolution.found:
            approved = False
            missing.append(
                MissingMaterial(
                    role=None,
                    ref=resolution.target,
                    code="target_not_found",
                    reason=resolution.error
                    or "target is not listed in any reachable signed role",
                    required_by=[req.request_id],
                    targets=[resolution.target],
                )
            )
            unattested.append(
                UnattestedClaim(
                    request_id=req.request_id,
                    target=resolution.target,
                    scope="target_resolution",
                    cause="missing_material",
                    claim="target could not be resolved through the delegation graph",
                    blocked_by=[],
                )
            )
        elif req.approved_roles is not None and resolution.hit_role not in req.approved_roles:
            approved = False
            missing.append(
                MissingMaterial(
                    role=resolution.hit_role,
                    ref=mirror.candidate_refs(resolution.hit_role or "")[0],
                    code="role_not_approved",
                    reason=(
                        f"hit role {resolution.hit_role!r} is not in approved "
                        f"roles {req.approved_roles}"
                    ),
                    required_by=[req.request_id],
                    targets=[resolution.target],
                )
            )

    for role in roles:
        candidates = mirror.candidate_refs(role)
        primary_ref = candidates[0]
        role_file = mirror.roles.get(role)

        status: str
        detail: str | None = None
        signature_status: str | None = None
        if role_file is None:
            status = "file_absent"
            detail = mirror.parse_errors.get(primary_ref)
        elif not transfer.allows(*candidates):
            status = "not_transferable"
        elif not transfer.signatures_deliverable(role, *candidates):
            status = "signature_material_blocked"
        else:
            structural = _structural_signature_status(mirror, role)
            signature_status = structural or "ok"
            enforce = enforce_signatures or verify_crypto
            crypto_failed = verify_crypto and role in crypto_errors
            if structural is not None and enforce:
                status = structural
            elif crypto_failed:
                status = "invalid_signature"
                detail = crypto_errors[role]
                signature_status = "invalid_signature"
            else:
                status = "ready"
                if structural is not None:
                    detail = (
                        f"{structural}: embedded signatures do not meet the "
                        "configured threshold; this is non-blocking unless "
                        "verify_crypto or enforce_signatures is enabled"
                    )
                if verify_crypto and "__planner__" in crypto_errors:
                    detail = crypto_errors["__planner__"]

        sha256_value: str | None = None
        size: int | None = None
        if role_file is not None:
            sha256_value = _sha256_file(role_file.path)
            size = role_file.path.stat().st_size

        records.append(
            RoleRecord(
                role=role,
                ref=role_file.ref if role_file is not None else primary_ref,
                status=status,
                sha256=sha256_value if status == "ready" else sha256_value,
                size=size,
                via_requests=[req.request_id],
                detail=detail,
                signature_status=signature_status,
            )
        )

        if status != "ready":
            code = status
            reason = detail or {
                "file_absent": "signed role file is absent from the mirror",
                "not_transferable": "role file is not on the caller-provided transferability manifest",
                "signature_material_blocked": "the role payload may transfer but its signature material may not",
                "insufficient_signatures": "fewer than threshold authorized signatures are present",
                "invalid_signature": "cryptographic signature verification failed",
            }.get(status, status)
            missing.append(
                MissingMaterial(
                    role=role,
                    ref=role_file.ref if role_file is not None else primary_ref,
                    code=code,
                    reason=reason,
                    required_by=[req.request_id],
                    targets=list(req.targets),
                )
            )
            scope, claim = _role_claim(role)
            unattested.append(
                UnattestedClaim(
                    request_id=req.request_id,
                    target=None,
                    scope=scope,
                    cause="missing_material",
                    claim=claim,
                    blocked_by=[primary_ref],
                )
            )
            if role == "root":
                unattested.append(
                    UnattestedClaim(
                        request_id=req.request_id,
                        target=None,
                        scope="key_authorization",
                        cause="missing_material",
                        claim="without root, authorization of every top-level role key is unanchored",
                        blocked_by=[primary_ref],
                    )
                )

    # Blocking missing materials imply no end-to-end attestation per target.
    non_material_codes = {"role_not_approved", "target_not_found"}
    blocking_refs = [
        item.ref for item in missing if item.code not in non_material_codes
    ]
    if blocking_refs or not found or not approved:
        for target in req.targets:
            unattested.append(
                UnattestedClaim(
                    request_id=req.request_id,
                    target=target,
                    scope="end_to_end_attestation",
                    cause="missing_material",
                    claim=(
                        "target membership in an approved role cannot be "
                        "independently re-verified with the delivered materials"
                    ),
                    blocked_by=sorted(set(blocking_refs)),
                )
            )

    # Residual, non-blocking unattested scope caused by the chosen level.
    if assurance_level == "membership":
        unattested.extend(
            [
                UnattestedClaim(
                    request_id=req.request_id,
                    target=None,
                    scope="snapshot_consistency",
                    cause="assurance_level_excluded",
                    claim="snapshot not requested: version/hash consistency and delegated-role rollback binding are not proven by this export",
                ),
                UnattestedClaim(
                    request_id=req.request_id,
                    target=None,
                    scope="freshness",
                    cause="assurance_level_excluded",
                    claim="timestamp not requested: freshness and rollback window are not proven by this export",
                ),
            ]
        )
    elif assurance_level == "consistent":
        unattested.append(
            UnattestedClaim(
                request_id=req.request_id,
                target=None,
                scope="freshness",
                cause="assurance_level_excluded",
                claim="timestamp not requested: freshness and rollback window are not proven by this export",
            )
        )

    unattested.append(
        UnattestedClaim(
            request_id=req.request_id,
            target=None,
            scope="target_artifact_bytes",
            cause="out_of_material_scope",
            claim="target files themselves are outside the role-file export; only signed target metadata/hashes are handed off",
        )
    )

    complete = not missing and found and approved
    shared_prefix: list[str] = []

    return RequestPlan(
        request_id=req.request_id,
        targets=list(req.targets),
        found=found,
        complete=complete,
        approved=approved,
        roles=roles,
        shared_prefix=shared_prefix,
        records=records,
        missing=missing,
        unattested_scope=unattested,
        resolutions=[dataclasses.asdict(r) for r in resolutions],
    )


def _common_prefix(*lists: list[str]) -> list[str]:
    if not lists:
        return []
    prefix: list[str] = []
    for items in zip(*lists):
        if all(item == items[0] for item in items):
            prefix.append(items[0])
        else:
            break
    return prefix


def plan_export(
    mirror: str | Path | Mirror,
    requests: Sequence[TargetRequest | Mapping[str, Any] | str] | None = None,
    manifest: TransferManifest | Mapping[str, Any] | Sequence[str] | None = None,
    *,
    assurance_level: str = "membership",
    verify_crypto: bool = False,
    enforce_signatures: bool = True,
    scan_substitutes: bool = True,
    transferable: Any = None,
    targets: Any = None,
) -> ExportPlan:
    """Plan the minimal merged offline export for ``requests``.

    ``transferable`` is an alias for ``manifest`` and ``targets`` is an alias
    for ``requests`` for callers that prefer those keyword names.
    """

    raw_requests: Any = requests
    if isinstance(raw_requests, Mapping):
        if "requests" in raw_requests:
            raw_requests = raw_requests["requests"]
        else:
            raw_requests = [raw_requests]
    if isinstance(raw_requests, str):
        raw_requests = [raw_requests]
    request_values: list[Any] = list(raw_requests or [])
    if targets is not None:
        target_values = [targets] if isinstance(targets, str) else list(targets)
        request_values.extend(
            {"request_id": f"target-{index}", "target": target}
            for index, target in enumerate(target_values)
        )
        requests = request_values
    if transferable is not None and manifest is None:
        manifest = transferable

    requests = request_values
    loaded = mirror if isinstance(mirror, Mirror) else Mirror.load(mirror)
    transfer = TransferManifest.from_obj(manifest)
    if not request_values:
        raise ValueError("at least one request/target is required")

    request_plans = [
        plan_request(
            loaded,
            transfer,
            req,
            assurance_level=assurance_level,
            verify_crypto=verify_crypto,
            enforce_signatures=enforce_signatures,
        )
        for req in request_values
    ]

    shared_roles = _common_prefix(*[rp.roles for rp in request_plans])
    for rp in request_plans:
        rp.shared_prefix = list(shared_roles)

    # Union of role records, first-seen order across requests.
    merged_records: dict[str, RoleRecord] = {}
    for rp in request_plans:
        for record in rp.records:
            existing = merged_records.get(record.role)
            if existing is None:
                record.via_requests = [rp.request_id]
                merged_records[record.role] = record
            else:
                if rp.request_id not in existing.via_requests:
                    existing.via_requests.append(rp.request_id)
                # A role is ready in the union only if every request view is.
                if record.status != "ready":
                    existing.status = record.status
                    existing.detail = record.detail

    minimal_roles = list(merged_records.keys())

    # Plan-level missing union.
    missing_map: dict[tuple[str | None, str, str], MissingMaterial] = {}
    for rp in request_plans:
        for item in rp.missing:
            key = (item.role, item.ref, item.code)
            existing = missing_map.get(key)
            if existing is None:
                item.required_by = [rp.request_id]
                item.targets = list(item.targets)
                missing_map[key] = item
            else:
                if rp.request_id not in existing.required_by:
                    existing.required_by.append(rp.request_id)
                for target in item.targets:
                    if target not in existing.targets:
                        existing.targets.append(target)
    missing = list(missing_map.values())

    # Plan-level unattested scope union.  Target-specific claims stay per
    # target; claims without a target (shared parent/anchor/freshness scope)
    # are merged across requests and marked request_id=None.
    target_scope_map: dict[tuple[Any, ...], UnattestedClaim] = {}
    shared_scope_map: dict[tuple[Any, ...], UnattestedClaim] = {}
    unattested: list[UnattestedClaim] = []
    for rp in request_plans:
        for claim in rp.unattested_scope:
            if claim.target is not None:
                key = (
                    claim.request_id,
                    claim.target,
                    claim.scope,
                    claim.cause,
                    tuple(claim.blocked_by),
                )
                if key not in target_scope_map:
                    target_scope_map[key] = claim
                    unattested.append(claim)
            else:
                key = (
                    claim.scope,
                    claim.cause,
                    tuple(claim.blocked_by),
                    claim.claim,
                )
                existing = shared_scope_map.get(key)
                if existing is None:
                    claim.request_id = None
                    shared_scope_map[key] = claim
                    unattested.append(claim)

    # Temptation files are only meaningful as gap substitutes for roles
    # that are actually deficient in this plan.
    deficient_roles = {item.role for item in missing if item.role}
    rejected = (
        evaluate_substitutes(loaded, transfer, deficient_roles)
        if scan_substitutes
        else []
    )

    sufficient = all(rp.complete for rp in request_plans) and not missing
    mergeable = sufficient
    status = "ready" if sufficient else "incomplete"

    handoff_files = [
        record.ref for record in merged_records.values() if record.status == "ready"
    ]
    required_files = [record.ref for record in merged_records.values()]
    certified = list(handoff_files) if sufficient else []

    required_set = set(minimal_roles)
    excluded_roles = [
        role for role in loaded.all_role_names_on_disk() if role not in required_set
    ]

    warnings: list[str] = []
    for ref, error in loaded.parse_errors.items():
        warnings.append(f"could not parse metadata file {ref}: {error}")
    for record in merged_records.values():
        if record.status == "ready" and record.signature_status not in (
            None,
            "ok",
        ):
            warnings.append(
                f"role {record.role}: {record.signature_status} "
                "(non-blocking; enable verify_crypto/enforce_signatures)"
            )

    return ExportPlan(
        mirror=str(loaded.root_dir),
        assurance_level=assurance_level,
        status=status,
        mergeable=mergeable,
        sufficient=sufficient,
        requests=request_plans,
        minimal_roles=minimal_roles,
        shared_roles=shared_roles,
        role_records=list(merged_records.values()),
        missing=missing,
        unattested_scope=unattested,
        rejected_substitutes=rejected,
        excluded_roles=excluded_roles,
        handoff_files=handoff_files,
        certified_handoff_files=certified,
        required_files=required_files,
        warnings=warnings,
    )


class OfflineExportPlanner:
    """Stateful planner bound to one mirror and one transfer manifest.

    This is a thin convenience wrapper around :func:`plan_export`::

        planner = OfflineExportPlanner("mirror", ["*"])
        result = planner.plan([{"id": "a", "target": "file1.txt"}])
    """

    def __init__(
        self,
        mirror: str | Path | Mirror,
        manifest: TransferManifest | Mapping[str, Any] | Sequence[str] | None = None,
        *,
        assurance_level: str = "membership",
        verify_crypto: bool = False,
        enforce_signatures: bool = True,
        scan_substitutes: bool = True,
    ) -> None:
        self.mirror = mirror if isinstance(mirror, Mirror) else Mirror.load(mirror)
        self.manifest = TransferManifest.from_obj(manifest)
        self.assurance_level = assurance_level
        self.verify_crypto = verify_crypto
        self.enforce_signatures = enforce_signatures
        self.scan_substitutes = scan_substitutes

    def plan(
        self,
        requests: Sequence[TargetRequest | Mapping[str, Any] | str] | None = None,
        *,
        targets: Sequence[str] | str | None = None,
        assurance_level: str | None = None,
    ) -> ExportPlan:
        """Compute the merged plan; ``targets`` may be given as convenience."""

        request_values: list[Any] = list(requests or [])
        if targets is not None:
            target_values = [targets] if isinstance(targets, str) else list(targets)
            request_values.extend(
                {"request_id": f"target-{index}", "target": target}
                for index, target in enumerate(target_values)
            )
        return plan_export(
            self.mirror,
            request_values,
            self.manifest,
            assurance_level=assurance_level or self.assurance_level,
            verify_crypto=self.verify_crypto,
            enforce_signatures=self.enforce_signatures,
            scan_substitutes=self.scan_substitutes,
        )


# Readable aliases for callers/tests discovering this module under different
# naming conventions.
build_export_plan = plan_export
create_export_plan = plan_export
compute_export_plan = plan_export
plan_offline_export = plan_export
build_offline_export_plan = plan_export
find_minimal_role_set = plan_export
select_minimal_roles = plan_export
export_plan = plan_export
OfflineExportPlan = ExportPlan


def plan_export_dict(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Dictionary-returning variant of :func:`plan_export`."""

    return plan_export(*args, **kwargs).to_dict()


plan_offline_export_dict = plan_export_dict


# ---------------------------------------------------------------------------
# Bundle writer / report rendering
# ---------------------------------------------------------------------------


def render_markdown_report(plan: ExportPlan) -> str:
    """Render a Chinese-readable handoff report."""

    lines: list[str] = []
    lines.append("# 离线角色导出报告")
    lines.append("")
    lines.append(f"- 镜像：`{plan.mirror}`")
    lines.append(f"- 证明级别：`{plan.assurance_level}`")
    lines.append(f"- 状态：**{plan.status}**（可合并={plan.mergeable}，充分={plan.sufficient}）")
    lines.append(f"- 共用父角色段：{_fmt_roles(plan.shared_roles)}")
    lines.append(f"- 最小角色集合：{_fmt_roles(plan.minimal_roles)}")
    lines.append("")

    lines.append("## 可交接角色文件清单")
    lines.append("")
    if plan.sufficient:
        lines.append("以下文件构成充分的最小复核材料（合并去重后）：")
    else:
        lines.append(
            "当前**不存在**充分的认证交接清单（`certified_handoff_files` 为空）；"
            "下列为物理上可传递但尚不足以完成证明的子集："
        )
    lines.append("")
    lines.append("| 角色 | 文件 | 状态 | SHA256 | 请求 |")
    lines.append("| --- | --- | --- | --- | --- |")
    for record in plan.role_records:
        digest = f"`{record.sha256[:16]}…`" if record.sha256 else "—"
        lines.append(
            f"| `{record.role}` | `{record.ref}` | `{record.status}` | {digest} | {', '.join(record.via_requests)} |"
        )
    lines.append("")

    if plan.missing:
        lines.append("## 缺件（不得用别名/摘要掩盖）")
        lines.append("")
        for item in plan.missing:
            lines.append(
                f"- `{item.code}` 角色 `{item.role}` 材料 `{item.ref}`：{item.reason}"
                f"（请求：{', '.join(item.required_by)}）"
            )
        lines.append("")

    if plan.rejected_substitutes:
        lines.append("## 已拒绝的替代材料")
        lines.append("")
        for sub in plan.rejected_substitutes:
            lines.append(f"- `{sub.code}` `{sub.ref}`（角色 `{sub.role}`）：{sub.reason}")
        lines.append("")

    lines.append("## 无证明范围")
    lines.append("")
    for claim in plan.unattested_scope:
        target = f" 目标 `{claim.target}`" if claim.target else ""
        lines.append(
            f"- [`{claim.cause}`] `{claim.scope}`{target}：{claim.claim}"
            + (f"；受阻材料 {claim.blocked_by}" if claim.blocked_by else "")
        )
    lines.append("")

    if plan.excluded_roles:
        lines.append("## 已排除的镜像内无关角色")
        lines.append("")
        lines.append(", ".join(f"`{role}`" for role in plan.excluded_roles))
        lines.append("")

    return "\n".join(lines)


def _fmt_roles(roles: Sequence[str]) -> str:
    return " → ".join(f"`{role}`" for role in roles) if roles else "（无）"


def write_bundle(plan: ExportPlan, out_dir: str | Path, *, copy_files: bool = True) -> Path:
    """Write ``export-plan.json``, a Markdown report and ready role files."""

    out = Path(out_dir)
    files_dir = out / "role-files"
    out.mkdir(parents=True, exist_ok=True)

    (out / "export-plan.json").write_text(plan.to_json(), encoding="utf-8")
    (out / "REPORT.md").write_text(render_markdown_report(plan), encoding="utf-8")

    checksums: list[str] = []
    if copy_files:
        mirror = Mirror.load(plan.mirror)
        for ref in plan.handoff_files:
            role_name = ref.rsplit("/", 1)[-1][: -len(".json")]
            role_file = mirror.roles.get(role_name)
            if role_file is None:
                continue
            destination = files_dir / Path(ref)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(role_file.path.read_bytes())
            checksums.append(f"{_sha256_file(role_file.path)}  {ref}")

    if checksums:
        (out / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")

    return out


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _build_parser() -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        description="Plan a minimal offline TUF role-file export."
    )
    sub = parser.add_subparsers(dest="command")

    plan_cmd = sub.add_parser("plan", help="compute an export plan")
    plan_cmd.add_argument("--mirror", required=True, help="mirror root containing metadata/")
    plan_cmd.add_argument("--requests", help="JSON file with request objects")
    plan_cmd.add_argument("--request", action="append", default=[], help="ID:TARGET (repeatable)")
    plan_cmd.add_argument("--manifest", help="transferability manifest JSON file")
    plan_cmd.add_argument(
        "--assurance",
        default="membership",
        choices=sorted(ASSURANCE_EXTRA_ROLES),
        help="assurance level (default: membership)",
    )
    plan_cmd.add_argument("--verify-crypto", action="store_true")
    plan_cmd.add_argument("--out", help="write a handoff bundle to this directory")
    plan_cmd.add_argument(
        "--strict",
        action="store_true",
        help="exit with status 3 when the plan is not sufficient",
    )
    sub.add_parser("demo", help="build the small mirror and run both scenarios")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    import sys

    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    # Convenience: `offline_export_plan.py --mirror ...` behaves like `plan`.
    if argv and argv[0] not in {"plan", "demo", "-h", "--help"}:
        argv = ["plan", *argv]

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "demo":
        from tiny_mirror_demo import main as demo_main

        return demo_main()

    if args.command in (None, "plan"):
        if args.command is None:
            parser.print_help()
            return 0
        request_values: list[Any] = []
        if args.requests:
            request_values = json.loads(Path(args.requests).read_text(encoding="utf-8"))
        for raw in args.request:
            if ":" in raw:
                request_id, target = raw.split(":", 1)
            else:
                request_id, target = raw, raw
            request_values.append({"request_id": request_id, "target": target})

        manifest = (
            TransferManifest.from_file(args.manifest) if args.manifest else None
        )
        plan = plan_export(
            args.mirror,
            request_values,
            manifest,
            assurance_level=args.assurance,
            verify_crypto=args.verify_crypto,
        )
        print(plan.to_json())
        if args.out:
            write_bundle(plan, args.out)
        if args.strict and not plan.sufficient:
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
