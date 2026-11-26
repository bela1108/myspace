import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

STATUS_MATCH = "match"
STATUS_MISMATCH = "mismatch"
STATUS_TRUNCATED = "truncated"
STATUS_MISSING_EVIDENCE = "missing_evidence"
STATUS_MISSING_RULE = "missing_rule"
STATUS_NO_DIGEST = "no_digest"

PathLike = Union[str, Path]
HashRuleResolver = Callable[[dict[str, Any]], Optional["AmcacheHashRule"]]


@dataclass(frozen=True)
class AmcacheHashRule:
    """Caller-supplied rule describing how an Amcache digest was calculated."""

    algorithm: str = "sha1"
    offset: int = 0
    max_bytes: Optional[int] = None
    strip_hex_prefix_chars: int = 0
    windows_generation: Optional[str] = None

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("Hash rule offset must be non-negative")
        if self.max_bytes is not None and self.max_bytes <= 0:
            raise ValueError("Hash rule max_bytes must be positive")
        if self.strip_hex_prefix_chars < 0:
            raise ValueError("Hash rule strip_hex_prefix_chars must be non-negative")
        try:
            hashlib.new(self.algorithm)
        except ValueError as ex:
            raise ValueError(f"Unsupported hash algorithm: {self.algorithm}") from ex


@dataclass(frozen=True)
class AmcacheEvidenceFile:
    """A local collected file selected by the caller's evidence id."""

    evidence_id: str
    local_path: PathLike
    registered_size: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str):
            raise ValueError("Evidence id must be a string")
        if not self.evidence_id:
            raise ValueError("Evidence id must not be empty")


@dataclass
class AmcacheEvidenceVerification:
    """Verification result and supporting basis for one Amcache entry."""

    entry_index: int
    evidence_id: Optional[str]
    windows_generation: Optional[str]
    registry_key_path: Optional[str]
    original_digest: Optional[str]
    original_digest_source: Optional[str]
    original_digest_raw: Optional[str]
    recomputed_digest: Optional[str]
    complete_file_sha1: Optional[str]
    algorithm: Optional[str]
    hashed_offset: Optional[int]
    hashed_length: Optional[int]
    local_path: Optional[str]
    local_size: Optional[int]
    registered_size: Optional[int]
    status: str
    findings: list[str] = field(default_factory=list)
    digest_scope: Optional[str] = None
    digest_proof: Optional[str] = None
    source: dict[str, Any] = field(default_factory=dict)


def _entry_generation(entry: Mapping[str, Any]) -> Optional[str]:
    source = entry.get("amcache_source") or {}
    if not isinstance(source, Mapping):
        return None
    generations = source.get("windows_generations")
    if isinstance(generations, Sequence) and not isinstance(generations, (str, bytes)):
        for generation in reversed(generations):
            if generation:
                return str(generation)
    generation = source.get("windows_generation")
    return str(generation) if generation else None


def _entry_digest(entry: Mapping[str, Any]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    source = entry.get("amcache_source") or {}
    if not isinstance(source, Mapping):
        digest = entry.get("sha1")
        return (str(digest) if digest else None, None, None)

    sources = source.get("hash_sources")
    if not isinstance(sources, Sequence) or isinstance(sources, (str, bytes)) or not sources:
        digest = entry.get("sha1")
        return (str(digest) if digest else None, None, None)

    digest_sources = [source for source in sources if isinstance(source, Mapping) and source.get("normalized_value")]
    if not digest_sources:
        digest = entry.get("sha1")
        return (str(digest) if digest else None, None, None)

    latest = digest_sources[-1]
    digest = entry.get("sha1") or latest.get("normalized_value")
    return (
        str(digest) if digest else None,
        str(latest.get("output_field")) if latest.get("output_field") else None,
        str(latest.get("raw_value")) if latest.get("raw_value") else None,
    )


def _rule_for_entry(
    entry: Mapping[str, Any],
    rules: Mapping[str, AmcacheHashRule],
    rule_resolver: Optional[HashRuleResolver],
) -> Optional[AmcacheHashRule]:
    if rule_resolver is not None:
        rule = rule_resolver(dict(entry))
        if rule is not None:
            return rule

    generation = entry.get("windows_generation") or _entry_generation(entry)
    if generation and generation in rules:
        return rules[generation]
    return None


def _normalize_original_digest(digest: str, rule: AmcacheHashRule) -> str:
    if rule.strip_hex_prefix_chars:
        if rule.strip_hex_prefix_chars >= len(digest):
            raise ValueError("strip_hex_prefix_chars must be shorter than the original digest")
        return digest[rule.strip_hex_prefix_chars :]
    return digest


def _hash_file(path: PathLike, rule: AmcacheHashRule) -> tuple[str, int]:
    hasher = hashlib.new(rule.algorithm)
    hashed_length = 0
    with open(path, "rb") as evidence_file:
        if rule.offset:
            evidence_file.seek(rule.offset)
        remaining = rule.max_bytes
        while remaining is None or remaining > 0:
            chunk_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            chunk = evidence_file.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            hashed_length += len(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return hasher.hexdigest(), hashed_length


def _calculate_full_sha1(path: PathLike) -> str:
    hasher = hashlib.sha1()
    with open(path, "rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_amcache_evidence(
    entries: Sequence[Mapping[str, Any]],
    evidence_files: Mapping[str, AmcacheEvidenceFile],
    hash_rules: Mapping[str, AmcacheHashRule],
    entry_evidence_ids: Optional[Mapping[int, str]] = None,
    rule_resolver: Optional[HashRuleResolver] = None,
) -> list[AmcacheEvidenceVerification]:
    """Recompute Amcache hashes for entries using caller-supplied evidence files.

    Registry ``full_path`` values are never opened. The caller maps each entry index
    to an evidence id, and ``evidence_files`` maps that id to a local collected file.
    ``hash_rules`` is keyed by the Windows generation recorded in the entry or supplied
    directly on the entry. A missing rule is returned as a per-entry finding; no default
    segment boundary is assumed. Partial hashes return both the segment digest and a
    complete-file SHA-1 so the limit of the original Amcache digest remains explicit.
    """
    entry_evidence_ids = entry_evidence_ids or {}
    results: list[AmcacheEvidenceVerification] = []

    for entry_index, entry in enumerate(entries):
        source = entry.get("amcache_source") if isinstance(entry.get("amcache_source"), Mapping) else {}
        generation = entry.get("windows_generation") or _entry_generation(entry)
        original_digest, digest_source, raw_digest = _entry_digest(entry)
        registry_key_path = source.get("registry_key_path") if source else None
        evidence_id_value = entry_evidence_ids.get(entry_index, entry.get("evidence_id"))
        evidence_id = str(evidence_id_value) if evidence_id_value is not None else None

        result = AmcacheEvidenceVerification(
            entry_index=entry_index,
            evidence_id=evidence_id,
            windows_generation=str(generation) if generation else None,
            registry_key_path=str(registry_key_path) if registry_key_path else None,
            original_digest=original_digest,
            original_digest_source=digest_source,
            original_digest_raw=raw_digest,
            recomputed_digest=None,
            complete_file_sha1=None,
            algorithm=None,
            hashed_offset=None,
            hashed_length=None,
            local_path=None,
            local_size=None,
            registered_size=entry.get("file_size", entry.get("size")),
            status=STATUS_NO_DIGEST,
            findings=[],
            digest_scope=None,
            source=dict(source),
        )

        if original_digest is None:
            result.findings.append("Amcache entry does not contain a digest")
            result.digest_proof = "No original digest is available to prove file content"
            results.append(result)
            continue

        rule = _rule_for_entry(entry, hash_rules, rule_resolver)
        if rule is None:
            result.status = STATUS_MISSING_RULE
            result.findings.append(f"No hash override rule was supplied for generation {generation}")
            result.digest_proof = "The original digest cannot be interpreted without the generation-specific hash rule"
            results.append(result)
            continue

        normalized_original_digest = _normalize_original_digest(original_digest, rule)

        if evidence_id is None:
            result.status = STATUS_MISSING_EVIDENCE
            result.findings.append("No evidence id was supplied for this entry")
            result.digest_proof = "The original digest remains untested because no evidence file was supplied"
            results.append(result)
            continue

        evidence = evidence_files.get(evidence_id)
        if evidence is None:
            result.status = STATUS_MISSING_EVIDENCE
            result.findings.append(f"Evidence id {evidence_id} was not found in the local evidence manifest")
            result.digest_proof = "The original digest remains untested because the evidence file was not found"
            results.append(result)
            continue

        local_path = Path(evidence.local_path)
        result.local_path = str(local_path)
        if not local_path.is_file():
            result.status = STATUS_MISSING_EVIDENCE
            result.findings.append("Local evidence file does not exist or is not a regular file")
            result.digest_proof = "The original digest remains untested because the local evidence file is unavailable"
            results.append(result)
            continue

        local_size = local_path.stat().st_size
        result.local_size = local_size
        result.complete_file_sha1 = _calculate_full_sha1(local_path)
        registered_size = evidence.registered_size if evidence.registered_size is not None else result.registered_size
        result.registered_size = registered_size

        if registered_size is not None and registered_size != local_size:
            result.findings.append(f"Registered size {registered_size} conflicts with local size {local_size}")

        required_size = rule.offset + rule.max_bytes if rule.max_bytes is not None else None
        offset_out_of_bounds = local_size < rule.offset
        if offset_out_of_bounds or (required_size is not None and local_size < required_size):
            result.status = STATUS_TRUNCATED
            result.findings.append(
                f"Collected file is truncated: rule requires offset {rule.offset} and max_bytes {rule.max_bytes} "
                f"but local file has {local_size} bytes"
            )
            result.algorithm = rule.algorithm
            result.hashed_offset = rule.offset
            result.hashed_length = 0 if offset_out_of_bounds else max(local_size - rule.offset, 0)
            result.digest_scope = "offset_out_of_bounds" if offset_out_of_bounds else _digest_scope(rule)
            result.digest_proof = _digest_proof(rule, result.status)
            if offset_out_of_bounds:
                result.digest_proof = (
                    f"The original digest starts at offset {rule.offset}; "
                    "truncation prevents the file content from being verified"
                )
            results.append(result)
            continue

        recomputed_digest, hashed_length = _hash_file(local_path, rule)
        result.recomputed_digest = recomputed_digest
        result.algorithm = rule.algorithm
        result.hashed_offset = rule.offset
        result.hashed_length = hashed_length
        result.digest_scope = _digest_scope(rule)
        result.status = (
            STATUS_MATCH if recomputed_digest.casefold() == normalized_original_digest.casefold() else STATUS_MISMATCH
        )
        result.digest_proof = _digest_proof(rule, result.status)

        if result.status == STATUS_MATCH:
            result.findings.append("Recomputed digest matches the original Amcache digest")
        else:
            result.findings.append("Recomputed digest does not match the original Amcache digest")

        results.append(result)

    return results


def _digest_scope(rule: AmcacheHashRule) -> str:
    if rule.max_bytes is None:
        return "complete_file"
    return f"bytes_{rule.offset}_to_{rule.offset + rule.max_bytes}"


def _digest_proof(rule: AmcacheHashRule, status: str) -> str:
    if rule.max_bytes is None:
        if status == STATUS_MATCH:
            return "A matching complete-file digest proves the collected file content under the configured hash rule"
        return "The complete-file digest did not establish file content identity"

    scope = f"bytes {rule.offset} through {rule.offset + rule.max_bytes}"
    if status == STATUS_TRUNCATED:
        if rule.max_bytes is None:
            return (
                f"The original digest starts at offset {rule.offset}; truncation prevents the file content from being verified"
            )
        return f"The original digest would only cover {scope}; truncation prevents even that segment from being verified"
    if status == STATUS_MATCH:
        return f"A matching partial digest proves only {scope}; it does not prove bytes outside that segment"
    return f"The partial digest for {scope} did not establish even segment-level identity"
