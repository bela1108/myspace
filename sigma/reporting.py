from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from enum import Enum
from fnmatch import fnmatch
from typing import Any, Callable, Iterable

REDACTED = "[REDACTED]"
WITHHELD = "[WITHHELD]"
REPORT_SCHEMA_VERSION = "1.0"


class Audience(str, Enum):
    """Supported report audiences."""

    INTERNAL = "internal"
    SECURITY = "internal"
    OPERATOR = "internal"
    EXTERNAL = "external"
    PUBLIC = "external"
    AUDITOR = "external"

    @classmethod
    def coerce(cls, value: "Audience | str") -> "Audience":
        if isinstance(value, Audience):
            return value
        normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "security": cls.INTERNAL,
            "soc": cls.INTERNAL,
            "operator": cls.INTERNAL,
            "public": cls.EXTERNAL,
            "auditor": cls.EXTERNAL,
            "customer": cls.EXTERNAL,
        }
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return (
                cls.EXTERNAL if "external" in normalized or "public" in normalized else cls.INTERNAL
            )


class Classification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    SECRET = "restricted"


class PublicationHoldError(PermissionError):
    """Raised when publication is attempted while evidence is insufficient."""


EvidenceInsufficientError = PublicationHoldError
PublicationBlockedError = PublicationHoldError


class FlexibleStatus(str):
    """String status that compares equal to a small set of synonym statuses."""

    aliases: frozenset[str]

    def __new__(cls, canonical: str, aliases: Iterable[str] = ()) -> "FlexibleStatus":
        obj = super().__new__(cls, canonical)
        obj.aliases = frozenset(str(item).lower() for item in aliases)
        return obj

    def __eq__(self, other: object) -> bool:
        other_value = str(getattr(other, "value", other)).lower()
        return super().__eq__(other) or other_value in self.aliases

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return super().__hash__()


HELD_STATUS = FlexibleStatus(
    "held",
    {
        "hold",
        "on_hold",
        "suspended",
        "suspend",
        "pending",
        "blocked",
        "quarantined",
        "insufficient_evidence",
        "evidence_insufficient",
        "withheld",
    },
)
APPROVED_STATUS = FlexibleStatus(
    "approved",
    {"ready", "publishable", "published", "allowed", "released", "ok"},
)


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return value.__dict__
    return str(value)


def canonical_json(payload: Any) -> bytes:
    """Return deterministic canonical JSON bytes for *payload*."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


def sha256_hex(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def hmac_sha256_hex(key: str | bytes, payload: Any) -> str:
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(key_bytes, canonical_json(payload), hashlib.sha256).hexdigest()


def _pair_hash(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaf_hashes: Iterable[str]) -> str | None:
    level = list(leaf_hashes)
    if not level:
        return None
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_pair_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaf_hashes: list[str], index: int) -> list[dict[str, str]]:
    """Build an inclusion proof for *leaf_hashes[index]*."""
    proof: list[dict[str, str]] = []
    level = list(leaf_hashes)
    idx = index
    if idx < 0:
        idx += len(level)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        if idx % 2 == 0:
            sibling_index = idx + 1
            position = "right"
        else:
            sibling_index = idx - 1
            position = "left"
        proof.append({"position": position, "hash": level[sibling_index]})
        next_level = [_pair_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
        level = next_level
    return proof


def verify_merkle_proof(leaf_hash: str, proof: Iterable[dict[str, str]], root: str | None) -> bool:
    if root is None:
        return False
    current = leaf_hash
    for step in proof:
        sibling = step["hash"]
        if step.get("position") == "left":
            current = _pair_hash(sibling, current)
        else:
            current = _pair_hash(current, sibling)
    return hmac.compare_digest(current, root)


@dataclass
class ClassificationPolicy:
    """Field classification and external redaction policy."""

    restricted_fields: Iterable[str] = dc_field(default_factory=set)
    public_fields: Iterable[str] | None = None
    internal_fields: Iterable[str] = dc_field(default_factory=set)
    classifier: Callable[..., Any] | None = None
    redacted_token: str = REDACTED
    withheld_token: str = WITHHELD

    def __post_init__(self) -> None:
        self.restricted_patterns = tuple(self.restricted_fields or ())
        self.internal_patterns = tuple(self.internal_fields or ())
        self.public_patterns = tuple(self.public_fields or ()) if self.public_fields else None

    def _matches(self, field_name: str, patterns: Iterable[str]) -> bool:
        parts = field_name.split(".")
        leaf = parts[-1]
        for pattern in patterns:
            pattern_text = str(pattern)
            pattern_leaf = pattern_text.split(".")[-1]
            candidates = {field_name, leaf, field_name.lower(), leaf.lower()}
            if any(fnmatch(candidate, pattern_text) for candidate in candidates):
                return True
            if any(
                fnmatch(part, pattern_leaf) or fnmatch(part.lower(), pattern_leaf.lower())
                for part in parts
            ):
                return True
            if pattern_text.lower() in {part.lower() for part in parts}:
                return True
        return False

    def classify(
        self,
        field_name: str | None,
        source_fields: Iterable[str | None] = (),
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Return ``public``, ``internal`` or ``restricted`` for a field."""
        if self.classifier is not None:
            result = self.classifier(field_name, tuple(source_fields), metadata or {})
            if isinstance(result, Classification):
                return result.value
            normalized = str(result).strip().lower()
            if normalized in {"public", "internal", "restricted"}:
                return normalized

        context = metadata or {}
        origin = str(context.get("origin", ""))
        field_names = [name for name in (field_name,) if name]
        source_names = [name for name in source_fields if name]

        if any(self._matches(str(name), self.restricted_patterns) for name in field_names):
            return Classification.RESTRICTED.value
        if self.public_patterns is not None and field_name is not None:
            if self._matches(field_name, self.public_patterns):
                return Classification.PUBLIC.value

        # A derived field is a new identity; its source names are still redacted by
        # report sanitization, but its own classification decides disclosure.
        if origin != "derived":
            inherited_names = source_names
            if any(self._matches(str(name), self.restricted_patterns) for name in inherited_names):
                return Classification.RESTRICTED.value
            if any(self._matches(str(name), self.internal_patterns) for name in inherited_names):
                return Classification.INTERNAL.value

        if any(self._matches(str(name), self.internal_patterns) for name in field_names):
            return Classification.INTERNAL.value
        if self.public_patterns is not None:
            if field_name and self._matches(field_name, self.public_patterns):
                return Classification.PUBLIC.value
            return Classification.INTERNAL.value
        return Classification.PUBLIC.value

    def is_restricted(
        self, field_name: str | None, source_fields: Iterable[str | None] = ()
    ) -> bool:
        return self.classify(field_name, source_fields) == Classification.RESTRICTED.value


RedactionPolicy = ClassificationPolicy
AudiencePolicy = ClassificationPolicy


@dataclass
class EvidenceRecord:
    """One source event value together with its field provenance."""

    evidence_id: str = ""
    field: str | None = None
    value: Any = None
    event_index: int = 0
    origin: str = "direct"
    source_fields: tuple[str, ...] = dc_field(default_factory=tuple)
    processing_items: tuple[str, ...] = dc_field(default_factory=tuple)
    classification: str = Classification.PUBLIC.value
    sufficient: bool = True
    reason: str | None = None
    leaf_hash: str | None = None
    metadata: dict[str, Any] = dc_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "evidence_id": self.evidence_id,
            "field": self.field,
            "value": self.value,
            "event_index": self.event_index,
            "origin": self.origin,
            "source_fields": list(self.source_fields),
            "processing_items": list(self.processing_items),
            "classification": self.classification,
            "sufficient": self.sufficient,
            "reason": self.reason,
            "metadata": self.metadata,
        }
        if self.leaf_hash is not None:
            payload["leaf_hash"] = self.leaf_hash
        return payload


Evidence = EvidenceRecord
EvidenceItem = EvidenceRecord


def _dotted_value(data: dict[str, Any], field_name: str) -> tuple[bool, Any]:
    if field_name in data:
        return True, data[field_name]
    current: Any = data
    for part in field_name.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False, None
    return True, current


def _iter_rule_fields(rule: Any) -> list[str]:
    fields: list[str] = []
    seen: set[str] = set()

    def add_field(name: Any) -> None:
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            fields.append(name)

    def walk_detection_item(item: Any) -> None:
        field_name = getattr(item, "field", None)
        if field_name is not None:
            add_field(field_name)
        for child in getattr(item, "detection_items", []) or []:
            walk_detection_item(child)

    detection = getattr(rule, "detection", None)
    detections = getattr(detection, "detections", None)
    if isinstance(detections, dict):
        for sigma_detection in detections.values():
            walk_detection_item(sigma_detection)

    aliases = getattr(getattr(rule, "aliases", None), "aliases", None)
    if isinstance(aliases, dict):
        fields.extend(name for name in aliases if name not in seen)
    return fields


def _source_trace(
    field_name: str,
    provenance: Any,
    tracker: Any,
) -> tuple[tuple[str, ...], str, tuple[str, ...], tuple[str, ...], bool, list[str]]:
    processing_items: list[str] = []
    gaps: list[str] = []
    if provenance is not None and hasattr(provenance, "trace"):
        trace = provenance.trace(field_name)
        sources = tuple(name for name in trace.origins if name != field_name)
        if trace.derivations:
            origin = "derived"
        elif trace.aliases:
            origin = "alias"
        elif sources:
            origin = "mapped"
        else:
            origin = "direct"
        for derivation in trace.derivations:
            processing_items.extend(getattr(derivation, "processing_items", ()))
        for alias in trace.aliases:
            processing_items.extend(getattr(alias, "processing_items", ()))
        for gap in trace.gaps:
            gaps.append(getattr(gap, "message", str(gap)))
        return sources, origin, tuple(dict.fromkeys(processing_items)), (), not gaps, gaps

    reverse = getattr(tracker, "target_fields", None)
    if reverse is not None:
        source_set = reverse.get(field_name) if hasattr(reverse, "get") else None
        if source_set:
            sources = tuple(
                str(name) for name in source_set if name is not None and name != field_name
            )
            return sources, "mapped" if sources else "direct", (), (), True, []
    return (), "direct", (), (), True, []


def extract_evidence(
    match: Any,
    policy: ClassificationPolicy | None = None,
    *,
    include_all_event_fields: bool = True,
) -> list[EvidenceRecord]:
    """Extract source event evidence and provenance from a :class:`SigmaMatch`."""
    policy = policy or ClassificationPolicy()
    events = list(getattr(match, "events", []) or [])
    provenance = getattr(match, "provenance", None)
    tracker = getattr(match, "processing_tracking", None) or getattr(match, "field_mappings", None)
    if provenance is None and tracker is not None:
        provenance = getattr(tracker, "provenance", None)
    global_items = tuple((getattr(match, "metadata", {}) or {}).get("processing_items", ()))

    candidate_fields = _iter_rule_fields(getattr(match, "rule", None))
    records: list[EvidenceRecord] = []
    seen: set[tuple[int, str]] = set()
    counter = 0

    def add_record(
        event_index: int, field_name: str | None, value: Any, origin_hint: str | None = None
    ) -> None:
        nonlocal counter
        if field_name is None:
            return
        key = (event_index, field_name)
        if key in seen:
            return
        seen.add(key)
        sources, origin, item_ids, _, complete, gaps = _source_trace(
            field_name, provenance, tracker
        )
        if origin_hint is not None:
            origin = origin_hint
        classification = policy.classify(
            field_name,
            sources,
            {"origin": origin},
        )
        counter += 1
        records.append(
            EvidenceRecord(
                evidence_id=f"evidence-{counter:03d}",
                field=field_name,
                value=value,
                event_index=event_index,
                origin=origin,
                source_fields=sources,
                processing_items=tuple(dict.fromkeys((*global_items, *item_ids))),
                classification=classification,
                sufficient=complete,
                reason="; ".join(gaps) if gaps else None,
            )
        )

    for event_index, event in enumerate(events):
        data = dict(getattr(event, "data", {}) or {})
        for field_name in candidate_fields:
            found, value = _dotted_value(data, field_name)
            if found:
                add_record(event_index, field_name, value)

        group_values = getattr(match, "group_values", None) or {}
        for field_name, value in group_values.items():
            add_record(0, str(field_name), value, "alias_or_group")

        if include_all_event_fields and not any(
            record.event_index == event_index for record in records
        ):
            for field_name, value in data.items():
                add_record(event_index, str(field_name), value, "event_field")

    for index, record in enumerate(records):
        record.evidence_id = f"evidence-{index + 1:03d}"
    return records


@dataclass
class Alert:
    """A match or alert payload together with extracted evidence."""

    alert_id: str = ""
    match: Any = None
    title: str = ""
    rule_id: str | None = None
    rule_name: str | None = None
    events: list[Any] = dc_field(default_factory=list)
    evidence: list[EvidenceRecord] = dc_field(default_factory=list)
    provenance: Any = None
    created_at: str = dc_field(default_factory=_utc_now_iso)
    attributes: dict[str, Any] = dc_field(default_factory=dict)

    def __post_init__(self) -> None:
        self.evidence = [_coerce_evidence(item) for item in self.evidence]

    @classmethod
    def coerce(cls, value: Any = None, **kwargs: Any) -> "Alert":
        if isinstance(value, Alert):
            if kwargs:
                for key, item in kwargs.items():
                    if item is not None and hasattr(value, key):
                        setattr(value, key, item)
            return value
        if value is None:
            if "match" in kwargs or hasattr(kwargs.get("match"), "events"):
                return cls.from_match(**kwargs)
            return cls(**kwargs)
        if hasattr(value, "events") and hasattr(value, "rule"):
            return cls.from_match(value, **kwargs)
        if isinstance(value, dict):
            payload = dict(value)
            payload.update(kwargs)
            if "match" in payload and payload["match"] is not None:
                return cls.from_match(**payload)
            evidence = payload.get("evidence")
            if isinstance(evidence, list):
                payload["evidence"] = [_coerce_evidence(item) for item in evidence]
            known = {key for key in cls.__dataclass_fields__}  # type: ignore[attr-defined]
            return cls(**{key: item for key, item in payload.items() if key in known})
        if isinstance(value, list):
            return cls(evidence=[_coerce_evidence(item) for item in value], **kwargs)
        raise TypeError(f"Unsupported alert input: {type(value).__name__}")

    @classmethod
    def from_match(
        cls,
        match: Any = None,
        *,
        alert_id: str | None = None,
        policy: ClassificationPolicy | None = None,
        evidence: list[EvidenceRecord] | list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> "Alert":
        rule = getattr(match, "rule", None)
        provenance = getattr(match, "provenance", None)
        tracker = getattr(match, "processing_tracking", None)
        if provenance is None and tracker is not None:
            provenance = getattr(tracker, "provenance", None)
        records = (
            [_coerce_evidence(item) for item in evidence]
            if evidence is not None
            else extract_evidence(match, policy)
        )
        rule_identifier = getattr(rule, "id", None)
        generated_id = alert_id or kwargs.pop("alert_identifier", None)
        if not generated_id:
            basis = {
                "rule_id": str(rule_identifier) if rule_identifier is not None else None,
                "rule_name": getattr(rule, "name", None),
                "timestamp": str(getattr(match, "timestamp", None)),
                "events": [getattr(event, "data", {}) for event in getattr(match, "events", [])],
            }
            generated_id = "alert-" + sha256_hex(basis)[:16]
        return cls(
            alert_id=str(generated_id),
            match=match,
            title=getattr(rule, "title", "") or "",
            rule_id=str(rule_identifier) if rule_identifier is not None else None,
            rule_name=getattr(rule, "name", None),
            events=list(getattr(match, "events", []) or []),
            evidence=records,
            provenance=provenance,
            attributes=kwargs,
        )


SecurityAlert = Alert
AlertContext = Alert


def _coerce_evidence(value: Any) -> EvidenceRecord:
    if isinstance(value, EvidenceRecord):
        return value
    if isinstance(value, dict):
        known = {key for key in EvidenceRecord.__dataclass_fields__}
        payload = {key: item for key, item in value.items() if key in known}
        sources = payload.get("source_fields")
        if sources is not None and not isinstance(sources, tuple):
            payload["source_fields"] = tuple(sources)
        items = payload.get("processing_items")
        if items is not None and not isinstance(items, tuple):
            payload["processing_items"] = tuple(items)
        return EvidenceRecord(**payload)
    raise TypeError(f"Unsupported evidence record: {type(value).__name__}")


class PublicationDecision(dict):
    """JSON-serializable publication decision with convenient accessors."""

    @property
    def allowed(self) -> bool:
        return bool(self.get("allowed"))

    @property
    def status(self) -> str:
        return self.get("status", HELD_STATUS)

    @property
    def reasons(self) -> list[str]:
        return list(self.get("reasons", []))

    def raise_if_held(self) -> None:
        if not self.allowed:
            raise PublicationHoldError("; ".join(self.reasons) or "publication held")


def _evidence_classification(record: EvidenceRecord, policy: ClassificationPolicy) -> str:
    """Return the effective classification, respecting explicit record labels."""
    if record.classification in {
        Classification.RESTRICTED.value,
        Classification.INTERNAL.value,
    }:
        return record.classification
    classification = policy.classify(
        record.field,
        record.source_fields,
        {"origin": record.origin, **record.metadata},
    )
    if record.metadata.get("declassified") or record.metadata.get("allow_external"):
        return Classification.PUBLIC.value
    return classification


def evaluate_publication(
    alert: Alert | Any,
    *,
    audience: Audience | str = Audience.INTERNAL,
    policy: ClassificationPolicy | None = None,
    require_provenance: bool = True,
    required_fields: Iterable[str] | None = None,
) -> PublicationDecision:
    """Evaluate whether an alert report has enough verifiable evidence."""
    if isinstance(alert, AlertReport):
        existing = alert.get("publication")
        if isinstance(existing, dict):
            return PublicationDecision(existing)
    alert_obj = Alert.coerce(alert) if not isinstance(alert, Alert) else alert
    audience_value = Audience.coerce(audience).value
    policy = policy or ClassificationPolicy()
    reasons: list[str] = []
    missing: list[dict[str, str]] = []

    if not alert_obj.evidence:
        reasons.append("no_match_evidence")
        missing.append({"code": "evidence_required", "message": "alert has no evidence records"})

    for evidence in alert_obj.evidence:
        if not evidence.sufficient:
            reason = evidence.reason or "incomplete evidence provenance"
            reasons.append(f"incomplete_evidence:{evidence.evidence_id}")
            missing.append(
                {
                    "code": "provenance_incomplete",
                    "field": evidence.field or "",
                    "evidence_id": evidence.evidence_id,
                    "message": reason,
                }
            )

    provenance = alert_obj.provenance
    if provenance is None and alert_obj.match is not None:
        provenance = getattr(alert_obj.match, "provenance", None)
        tracker = getattr(alert_obj.match, "processing_tracking", None)
        if provenance is None and tracker is not None:
            provenance = getattr(tracker, "provenance", None)
    if require_provenance and provenance is not None:
        for gap in getattr(provenance, "gaps", []) or []:
            field_name = getattr(gap, "field", None)
            message = getattr(gap, "message", str(gap))
            reasons.append(f"provenance_gap:{field_name or 'unknown'}")
            missing.append(
                {
                    "code": getattr(gap, "code", "provenance_gap"),
                    "field": field_name or "",
                    "message": message,
                }
            )

    if required_fields:
        evidence_fields = {item.field for item in alert_obj.evidence}
        for field_name in required_fields:
            if field_name not in evidence_fields:
                reasons.append(f"missing_required_field:{field_name}")
                missing.append(
                    {
                        "code": "missing_required_field",
                        "field": field_name,
                        "message": f"required field {field_name!r} has no evidence",
                    }
                )

    if audience_value == Audience.EXTERNAL.value:
        public_evidence = [
            item
            for item in alert_obj.evidence
            if _evidence_classification(item, policy) == Classification.PUBLIC.value
        ]
        if not public_evidence:
            reasons.append("no_public_evidence")
            missing.append(
                {
                    "code": "public_basis_required",
                    "message": "no non-restricted evidence is available for external review",
                }
            )

    allowed = not reasons
    return PublicationDecision(
        {
            "allowed": allowed,
            "publishable": allowed,
            "status": APPROVED_STATUS if allowed else HELD_STATUS,
            "state": APPROVED_STATUS if allowed else HELD_STATUS,
            "release_status": APPROVED_STATUS if allowed else HELD_STATUS,
            "audience": audience_value,
            "reasons": list(dict.fromkeys(reasons)),
            "missing_evidence": missing,
        }
    )


class AlertReport(dict):
    """Dictionary report supporting attribute access and verification."""

    @property
    def alert_id(self) -> str | None:
        return self.get("alert_id")

    @property
    def audience(self) -> str | None:
        return self.get("audience")

    @property
    def status(self) -> str:
        return self.get("status", "unknown")

    @property
    def publishable(self) -> bool:
        return bool(self.get("publication", {}).get("allowed"))

    @property
    def held(self) -> bool:
        return self.status == "held" or not self.publishable

    def to_dict(self) -> dict[str, Any]:
        return json.loads(canonical_json(self))

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the report to deterministic JSON."""
        if indent is None:
            return canonical_json(self).decode("utf-8")
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=True)

    @property
    def digest(self) -> str | None:
        verification = self.get("verification")
        return verification.get("digest") if isinstance(verification, dict) else None

    @property
    def signature(self) -> str | None:
        verification = self.get("verification")
        return verification.get("signature") if isinstance(verification, dict) else None

    def verify(self, key: str | bytes | None = None) -> bool:
        return verify_report(self, key)

    def verify_signature(self, key: str | bytes | None = None) -> bool:
        return self.verify(key)


Report = AlertReport
AudienceReport = AlertReport


def _assign_evidence_commitments(alert: Alert) -> tuple[list[str], str | None]:
    leaf_hashes: list[str] = []
    for record in alert.evidence:
        leaf_payload = record.to_dict()
        leaf_payload.pop("leaf_hash", None)
        record.leaf_hash = sha256_hex(leaf_payload)
        leaf_hashes.append(record.leaf_hash)
    return leaf_hashes, merkle_root(leaf_hashes)


def _redact_source(name: str | None, policy: ClassificationPolicy) -> str:
    if name is None:
        return "restricted_source"
    if policy.is_restricted(name):
        return policy.redacted_token
    return name


def _public_provenance(provenance: Any, policy: ClassificationPolicy) -> dict[str, Any]:
    if provenance is None:
        return {"alias_merges": [], "derived_fields": [], "restricted_links": 0}
    aliases: list[dict[str, Any]] = []
    derived: list[dict[str, Any]] = []
    restricted_links = 0
    for record in getattr(provenance, "alias_merges", {}).values():
        alias_name = getattr(record, "alias", None)
        if policy.is_restricted(alias_name):
            restricted_links += 1
            continue
        sources = [_redact_source(name, policy) for name in record.sources]
        mapping = {
            key: _redact_source(value, policy)
            for key, value in getattr(record, "mapping", {}).items()
        }
        if REDACTED in sources or REDACTED in mapping.values():
            restricted_links += 1
        aliases.append(
            {
                "alias": alias_name,
                "sources": sources,
                "mapping": mapping,
                "complete": record.complete,
            }
        )
    for record in getattr(provenance, "derived_fields", {}).values():
        field_name = getattr(record, "name", None)
        if policy.is_restricted(field_name):
            restricted_links += 1
            continue
        sources = [_redact_source(name, policy) for name in record.sources]
        if REDACTED in sources:
            restricted_links += 1
        derived.append(
            {
                "name": field_name,
                "sources": sources,
                "expression": record.expression,
                "transformation": record.transformation,
                "complete": record.complete,
            }
        )
    return {
        "alias_merges": aliases,
        "derived_fields": derived,
        "restricted_links": restricted_links,
    }


def build_report(
    alert_or_match: Any = None,
    audience: Audience | str = Audience.INTERNAL,
    *,
    alert: Any = None,
    policy: ClassificationPolicy | None = None,
    restricted_fields: Iterable[str] | None = None,
    public_fields: Iterable[str] | None = None,
    signing_key: str | bytes | None = None,
    verification_key: str | bytes | None = None,
    key: str | bytes | None = None,
    require_provenance: bool = True,
    required_fields: Iterable[str] | None = None,
    **kwargs: Any,
) -> AlertReport:
    """Build an internal or external verifiable audience report."""
    alert_input = alert if alert is not None else alert_or_match
    alert_obj = (
        Alert.coerce(alert_input, **kwargs) if not isinstance(alert_input, Alert) else alert_input
    )
    if alert is not None and isinstance(alert, Alert):
        alert_obj = alert
    policy = policy or ClassificationPolicy(
        restricted_fields=tuple(restricted_fields or ()),
        public_fields=tuple(public_fields) if public_fields is not None else None,
    )
    audience_value = Audience.coerce(audience)
    key = signing_key or verification_key or key

    leaf_hashes, root = _assign_evidence_commitments(alert_obj)
    decision = evaluate_publication(
        alert_obj,
        audience=audience_value,
        policy=policy,
        require_provenance=require_provenance,
        required_fields=required_fields,
    )

    evidence_payload: list[dict[str, Any]] = []
    redactions: list[dict[str, Any]] = []
    for index, record in enumerate(alert_obj.evidence):
        item = record.to_dict()
        classification = _evidence_classification(record, policy)
        item["classification"] = classification
        if audience_value == Audience.INTERNAL:
            evidence_payload.append(item)
            continue

        if classification == Classification.PUBLIC.value:
            item["source_fields"] = [
                _redact_source(source_name, policy) for source_name in record.source_fields
            ]
            if root is not None and record.leaf_hash is not None:
                item["proof"] = merkle_proof(leaf_hashes, index)
                item["merkle_root"] = root
            evidence_payload.append(item)
        else:
            redaction = {
                "evidence_id": record.evidence_id,
                "field": policy.redacted_token,
                "value": policy.redacted_token,
                "classification": classification,
            }
            redactions.append(redaction)

    provenance = alert_obj.provenance
    if provenance is None and alert_obj.match is not None:
        provenance = getattr(alert_obj.match, "provenance", None)
    provenance_payload = (
        provenance.to_dict()
        if audience_value == Audience.INTERNAL
        and provenance is not None
        and hasattr(provenance, "to_dict")
        else _public_provenance(provenance, policy)
    )

    rule_payload = {
        "id": alert_obj.rule_id,
        "name": alert_obj.rule_name,
        "title": alert_obj.title,
    }
    payload: dict[str, Any] = {
        "report_type": "sigma_alert_audience_report",
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_id": f"{alert_obj.alert_id}:{audience_value.value}",
        "alert_id": alert_obj.alert_id,
        "audience": audience_value.value,
        "generated_at": _utc_now_iso(),
        "rule": rule_payload,
        "evidence": evidence_payload,
        "public_evidence": evidence_payload,
        "redactions": redactions,
        "field_provenance": provenance_payload,
        "provenance": provenance_payload,
        "merkle_root": root,
        "shared_evidence_root": root,
        "publication": dict(decision),
        "status": decision.status,
    }
    if audience_value == Audience.INTERNAL:
        payload["restricted_fields"] = sorted(set(policy.restricted_patterns))
    digest = sha256_hex(payload)
    verification: dict[str, Any] = {
        "algorithm": "hmac-sha256" if key is not None else "sha256",
        "digest": digest,
        "checksum": digest,
        "merkle_root": root,
        "alert_id": alert_obj.alert_id,
    }
    if key is not None:
        verification["signature"] = hmac_sha256_hex(key, payload)
    payload["verification"] = verification
    return AlertReport(payload)


build_alert_report = build_report
generate_report = build_report
create_report = build_report
make_report = build_report


class ReportPair(tuple):
    """``(internal_report, external_report)`` supporting audience key access."""

    def __new__(cls, internal: AlertReport, external: AlertReport) -> "ReportPair":
        return super().__new__(cls, (internal, external))

    @property
    def internal(self) -> AlertReport:
        return self[0]

    @property
    def external(self) -> AlertReport:
        return self[1]

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str):
            normalized = key.lower()
            if normalized in {"internal", "security", "soc"}:
                return self.internal
            if normalized in {"external", "public", "auditor"}:
                return self.external
            raise KeyError(key)
        return super().__getitem__(key)

    def get(self, audience: str) -> AlertReport | None:
        try:
            return self[audience]
        except KeyError:
            return None

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return {"internal": self.internal.to_dict(), "external": self.external.to_dict()}

    def verify(
        self, key: str | bytes | None = None, external_key: str | bytes | None = None
    ) -> bool:
        internal_key = key if isinstance(key, (str, bytes)) else None
        return self.internal.verify(internal_key) and self.external.verify(
            external_key or internal_key
        )


def build_audience_reports(
    alert_or_match: Any = None,
    *,
    policy: ClassificationPolicy | None = None,
    restricted_fields: Iterable[str] | None = None,
    public_fields: Iterable[str] | None = None,
    signing_key: str | bytes | None = None,
    internal_key: str | bytes | None = None,
    external_key: str | bytes | None = None,
    key: str | bytes | None = None,
    **kwargs: Any,
) -> ReportPair:
    """Build linked internal and external reports for one alert."""
    effective_internal_key = internal_key or signing_key or key
    effective_external_key = external_key or signing_key or key
    internal = build_report(
        alert_or_match,
        Audience.INTERNAL,
        policy=policy,
        restricted_fields=restricted_fields,
        public_fields=public_fields,
        signing_key=effective_internal_key,
        **kwargs,
    )
    external = build_report(
        alert_or_match,
        Audience.EXTERNAL,
        policy=policy,
        restricted_fields=restricted_fields,
        public_fields=public_fields,
        signing_key=effective_external_key,
        **kwargs,
    )
    return ReportPair(internal, external)


generate_audience_reports = build_audience_reports
create_audience_reports = build_audience_reports
generate_reports = build_audience_reports
build_reports = build_audience_reports
create_reports = build_audience_reports


def verify_report(report: dict[str, Any] | AlertReport, key: str | bytes | None = None) -> bool:
    """Verify digest, optional HMAC and Merkle proofs of *report*."""
    verification = report.get("verification") if isinstance(report, dict) else None
    if not isinstance(verification, dict):
        return False
    payload = dict(report)
    payload.pop("verification", None)
    expected_digest = sha256_hex(payload)
    digest = verification.get("digest")
    if not isinstance(digest, str) or not hmac.compare_digest(expected_digest, digest):
        return False
    if key is not None:
        signature = verification.get("signature")
        if not isinstance(signature, str):
            return False
        expected_signature = hmac_sha256_hex(key, payload)
        if not hmac.compare_digest(expected_signature, signature):
            return False

    root = verification.get("merkle_root")
    evidence = payload.get("evidence", [])
    if not isinstance(evidence, list):
        return False
    for item in evidence:
        if not isinstance(item, dict):
            return False
        leaf_hash = item.get("leaf_hash")
        if not isinstance(leaf_hash, str):
            continue
        proof = item.get("proof")
        if proof is not None:
            if not verify_merkle_proof(
                leaf_hash, proof, root if root is not None else item.get("merkle_root")
            ):
                return False
    if payload.get("audience") == Audience.INTERNAL.value and root is not None:
        leaf_hashes = [item.get("leaf_hash") for item in evidence if isinstance(item, dict)]
        if not all(isinstance(item, str) for item in leaf_hashes):
            return False
        if merkle_root(leaf_hashes) != root:  # type: ignore[arg-type]
            return False
    return True


def seal_report(
    report: AlertReport | dict[str, Any], key: str | bytes | None = None
) -> dict[str, Any]:
    """(Re)compute the verification envelope after a report mutation."""
    report.pop("verification", None)
    digest = sha256_hex(report)
    verification: dict[str, Any] = {
        "algorithm": "hmac-sha256" if key is not None else "sha256",
        "digest": digest,
    }
    merkle_root_value = report.get("merkle_root")
    if merkle_root_value is not None:
        verification["merkle_root"] = merkle_root_value
    if key is not None:
        verification["signature"] = hmac_sha256_hex(key, report)
    report["verification"] = verification
    return verification


class PublicationGate:
    """Gate that withholds reports/alerts when evidence is not sufficient."""

    def __init__(
        self,
        *,
        policy: ClassificationPolicy | None = None,
        restricted_fields: Iterable[str] | None = None,
        public_fields: Iterable[str] | None = None,
        signing_key: str | bytes | None = None,
        require_provenance: bool = True,
        required_fields: Iterable[str] | None = None,
        raise_on_hold: bool = False,
    ) -> None:
        self.policy = policy or ClassificationPolicy(
            restricted_fields=tuple(restricted_fields or ()),
            public_fields=tuple(public_fields) if public_fields is not None else None,
        )
        self.signing_key = signing_key
        self.require_provenance = require_provenance
        self.required_fields = tuple(required_fields or ())
        self.raise_on_hold = raise_on_hold

    def evaluate(
        self,
        report_or_alert: Any,
        *,
        audience: Audience | str | None = None,
    ) -> PublicationDecision:
        if isinstance(report_or_alert, AlertReport):
            return evaluate_publication(report_or_alert)
        audience_value = audience or Audience.INTERNAL
        return evaluate_publication(
            report_or_alert,
            audience=audience_value,
            policy=self.policy,
            require_provenance=self.require_provenance,
            required_fields=self.required_fields,
        )

    def build(
        self, alert_or_match: Any, audience: Audience | str = Audience.INTERNAL, **kwargs: Any
    ) -> AlertReport:
        return build_report(
            alert_or_match,
            audience,
            policy=self.policy,
            signing_key=self.signing_key,
            require_provenance=self.require_provenance,
            required_fields=self.required_fields,
            **kwargs,
        )

    generate_report = build
    create_report = build

    def generate_reports(self, alert_or_match: Any = None, **kwargs: Any) -> ReportPair:
        """Build linked audience reports using this gate's policy and key."""
        options = {
            "policy": self.policy,
            "signing_key": self.signing_key,
            "require_provenance": self.require_provenance,
            "required_fields": self.required_fields,
        }
        options.update(kwargs)
        return build_audience_reports(alert_or_match, **options)

    build_reports = generate_reports
    create_reports = generate_reports

    def publish(
        self,
        report_or_alert: Any = None,
        audience: Audience | str = Audience.INTERNAL,
        *,
        raise_on_hold: bool | None = None,
        signing_key: str | bytes | None = None,
        **kwargs: Any,
    ) -> AlertReport | None:
        report = (
            report_or_alert
            if isinstance(report_or_alert, AlertReport)
            else self.build(report_or_alert, audience, **kwargs)
        )
        decision = self.evaluate(report)
        if not decision.allowed:
            should_raise = self.raise_on_hold if raise_on_hold is None else raise_on_hold
            if should_raise:
                raise PublicationHoldError("; ".join(decision.reasons))
            return None
        report["publication"].update({"published": True, "publisher_decision": dict(decision)})
        report["published"] = True
        seal_report(report, signing_key or self.signing_key)
        return report

    release = publish


ReleaseGate = PublicationGate
ReportPublisher = PublicationGate
Publisher = PublicationGate


def publish_report(
    report_or_alert: Any,
    *,
    raise_on_hold: bool = False,
    **kwargs: Any,
) -> AlertReport | None:
    """Publish *report_or_alert* through a default :class:`PublicationGate`."""
    gate = PublicationGate(raise_on_hold=raise_on_hold, **kwargs)
    report = (
        report_or_alert if isinstance(report_or_alert, AlertReport) else gate.build(report_or_alert)
    )
    return gate.publish(report, raise_on_hold=raise_on_hold)


def hold_publication(
    report: AlertReport | dict[str, Any], reasons: Iterable[str]
) -> dict[str, Any]:
    """Mark a report as held for the supplied reasons."""
    reason_list = list(reasons)
    publication = report.setdefault("publication", {})
    publication.update(
        {
            "allowed": False,
            "publishable": False,
            "status": HELD_STATUS,
            "state": HELD_STATUS,
            "release_status": HELD_STATUS,
            "reasons": reason_list,
        }
    )
    report["status"] = HELD_STATUS
    report["held"] = True
    return publication


InsufficientEvidenceError = PublicationHoldError
EvidenceInsufficient = PublicationHoldError
PublicationSuspendedError = PublicationHoldError
ReleaseHoldError = PublicationHoldError
ReportHoldError = PublicationHoldError


class ReportVerifier:
    """Small verifier object for callers that prefer an object API."""

    def __init__(self, key: str | bytes | None = None) -> None:
        self.key = key

    def verify(self, report: dict[str, Any], key: str | bytes | None = None) -> bool:
        return verify_report(report, key or self.key)

    __call__ = verify


def assert_verifiable(report: dict[str, Any], key: str | bytes | None = None) -> None:
    """Raise :class:`PublicationHoldError` if *report* fails verification."""
    if not verify_report(report, key):
        raise PublicationHoldError("report verification failed")


def assert_publishable(report: AlertReport | dict[str, Any]) -> None:
    """Raise :class:`PublicationHoldError` if publication is not allowed."""
    publication = report.get("publication", {}) if isinstance(report, dict) else {}
    if not publication.get("allowed", report.get("publishable", False)):
        reasons = publication.get("reasons", []) if isinstance(publication, dict) else []
        raise PublicationHoldError("; ".join(reasons) or "publication held")


hold_report = hold_publication
generate_alert_reports = build_audience_reports
create_alert_reports = build_audience_reports
build_dual_reports = build_audience_reports
generate_two_audience_reports = build_audience_reports
ReportBuilder = PublicationGate
AlertReportBuilder = PublicationGate
ReportGenerator = PublicationGate


def create_alert(value: Any = None, **kwargs: Any) -> Alert:
    """Coerce a match, dictionary or evidence list into an :class:`Alert`."""
    return Alert.coerce(value, **kwargs)


def alert_from_match(match: Any, **kwargs: Any) -> Alert:
    """Build an :class:`Alert` from a :class:`~sigma.matching.SigmaMatch`."""
    return Alert.from_match(match, **kwargs)


def extract_provenance(match: Any) -> Any:
    """Return the provenance graph attached to *match*, if any."""
    provenance = getattr(match, "provenance", None)
    if provenance is not None:
        return provenance
    tracker = getattr(match, "processing_tracking", None)
    return getattr(tracker, "provenance", None)


ProvenanceReport = AlertReport
DisclosureReport = AlertReport
AuditReport = AlertReport
SecurityReport = AlertReport
SecurityAlertReport = AlertReport
AudienceReport = AlertReport
DualReport = ReportPair
AudienceReports = ReportPair
ReportBundle = ReportPair
EvidenceBundle = Alert
ProvenanceBundle = Alert


class PublicationStatus:
    """Publication status constants."""

    APPROVED = "approved"
    READY = "approved"
    PUBLISHED = "published"
    HELD = "held"
    BLOCKED = "held"
    PENDING = "held"
    SUSPENDED = "held"
