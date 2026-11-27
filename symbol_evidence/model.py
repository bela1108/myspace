"""Domain objects and normalizers for symbol evidence.

The public model is intentionally dict-friendly.  Every object has a
``to_dict`` method so a report can be serialized without leaking pefile's
internal ``Structure`` objects.
"""

import hashlib
import hmac
import json
import re

NO_EVIDENCE = "no_evidence"
NAME_ONLY = "name_only"
DEBUG_RECORD_MATCH = "debug_record_match"
DIGEST_VERIFIED = "digest_verified"


class EvidenceLevel:
    """String constants plus an ordering used for summaries.

    ``no_evidence`` and ``name_only`` are deliberately distinct.  A filename
    match is useful for finding a candidate, but it is not a build-identity
    match and it must never become ``verified``.
    """

    NO_EVIDENCE = NO_EVIDENCE
    NAME_ONLY = NAME_ONLY
    DEBUG_RECORD_MATCH = DEBUG_RECORD_MATCH
    DIGEST_VERIFIED = DIGEST_VERIFIED

    ORDER = {
        NO_EVIDENCE: 0,
        NAME_ONLY: 1,
        DEBUG_RECORD_MATCH: 2,
        DIGEST_VERIFIED: 3,
    }

    LABELS = {
        NO_EVIDENCE: "无证据",
        NAME_ONLY: "仅有名称",
        DEBUG_RECORD_MATCH: "调试记录身份吻合",
        DIGEST_VERIFIED: "签收摘要已证实",
    }

    @classmethod
    def rank(cls, level):
        return cls.ORDER.get(level, -1)

    @classmethod
    def label(cls, level):
        return cls.LABELS.get(level, level)


_DIGEST_LENGTHS = {"sha1": 40, "sha256": 64, "sha512": 128}
_DIGEST_PREFIX_RE = re.compile(
    r"^(sha-?1|sha-?256|sha-?512)\s*[:=\-]?\s*(.*)$", re.IGNORECASE
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _clean_text(value, default=""):
    if value is None:
        return default
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = str(value).replace("\x00", "").strip()
    return value or default


def _normalise_algorithm(value):
    value = _clean_text(value).lower()
    value = value.replace("-", "")
    if value in ("sha1", "sha2", "sha"):
        return "sha1" if value == "sha1" else "sha256"
    if value in ("sha256", "sha512"):
        return value
    return value or "sha256"


class Digest:
    """A normalized file digest.

    Completeness is strictly tied to a recognized algorithm and the exact
    digest length.  A prefix such as ``abc123`` is kept as a usable clue but
    is reported as incomplete and can never verify a claim.
    """

    def __init__(self, value, algorithm=None):
        self.algorithm = _normalise_algorithm(algorithm)
        self.value = _clean_text(value).lower()
        if self.value.startswith("0x"):
            self.value = self.value[2:]
        if not _HEX_RE.match(self.value):
            self.value = ""

    @property
    def expected_length(self):
        return _DIGEST_LENGTHS.get(self.algorithm)

    @property
    def is_complete(self):
        length = self.expected_length
        return bool(length and len(self.value) == length)

    def matches(self, other):
        if not isinstance(other, Digest):
            other = parse_digest(other)
        if other is None or not self.is_complete or not other.is_complete:
            return False
        if self.algorithm != other.algorithm:
            return False
        return hmac.compare_digest(self.value, other.value)

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "value": self.value,
            "complete": self.is_complete,
            "expected_length": self.expected_length,
            "display": f"{self.algorithm}:{self.value}" if self.value else None,
        }

    def __repr__(self):
        return "Digest(%r, %r)" % (self.value, self.algorithm)


def parse_digest(value, algorithm=None):
    """Parse a digest value from JSON, CSV, or command-line input."""

    if value is None:
        return None
    if isinstance(value, Digest):
        return value
    if isinstance(value, dict):
        algorithm = algorithm or value.get("algorithm") or value.get("algo")
        value = (
            value.get("value")
            or value.get("hex")
            or value.get("digest")
            or value.get("sha256")
            or value.get("sha1")
            or value.get("sha512")
        )
        if value is None:
            return None
    text = _clean_text(value)
    if not text:
        return None

    match = _DIGEST_PREFIX_RE.match(text)
    if match:
        explicit_algorithm = _normalise_algorithm(match.group(1))
        text = match.group(2).strip()
        if explicit_algorithm:
            algorithm = explicit_algorithm

    text = text.replace(" ", "")
    if text.startswith("0x"):
        text = text[2:]
    if _HEX_RE.match(text):
        if algorithm is None:
            for candidate, length in _DIGEST_LENGTHS.items():
                if len(text) == length:
                    algorithm = candidate
                    break
        if algorithm is None:
            algorithm = "sha256"
        return Digest(text, algorithm)
    return Digest(text, algorithm)


def normalise_guid(value):
    """Return a bare, lower-case GUID, or ``None`` for malformed input."""

    text = _clean_text(value)
    if not text:
        return None
    text = text.strip("{}()[]").replace("-", "").replace(" ", "")
    if not _HEX_RE.match(text):
        return None
    if len(text) != 32:
        return None
    return text.lower()


def normalise_age(value):
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = _clean_text(value).lower()
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def parse_identity_value(value):
    """Parse GUIDs, GUID+Age pairs, and NB10 signatures from loose text.

    Returns ``(kind, guid_or_signature, age)``.  ``kind`` is ``"rsds"``,
    ``"nb10"`` or ``None`` when the value is not an identity at all.
    """

    text = _clean_text(value)
    if not text:
        return None, None, None

    upper = text.upper()
    if upper.startswith("NB10:") or upper.startswith("NB10 "):
        remainder = text[5:] if upper.startswith("NB10:") else text[5:]
        parts = re.split(r"[:+,\s]+", remainder.strip())
        signature = parts[0].replace("0x", "").upper() if parts else None
        age = normalise_age(parts[1]) if len(parts) > 1 else None
        return ("nb10" if signature else None), signature, age

    compact = text.strip("{}()[]").replace("-", "").replace(" ", "")
    if "+" in compact:
        left, right = compact.split("+", 1)
        return "rsds", normalise_guid(left), normalise_age(right)
    if ":" in compact and not compact.lower().startswith("nb10"):
        left, right = compact.split(":", 1)
        if len(left.replace("-", "")) == 32:
            return "rsds", normalise_guid(left), normalise_age(right)

    if _HEX_RE.match(compact):
        if len(compact) == 32:
            return "rsds", compact.lower(), None
        if len(compact) > 32:
            # pefile's Signature_String is GUID (32 hex) followed by Age in hex.
            guid_part = compact[:32]
            age_part = compact[32:]
            try:
                age = int(age_part, 16)
            except ValueError:
                age = None
            return "rsds", guid_part.lower(), age

    return None, None, None


def normalise_path(path):
    text = _clean_text(path)
    if not text:
        return ""
    text = text.replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.strip().strip("/").lower()


def basename(path):
    text = _clean_text(path)
    text = text.replace("\\", "/")
    return text.rsplit("/", 1)[-1].strip()


def name_matches(left, right):
    """Case-insensitive Windows basename comparison, with full-path support."""

    if not left or not right:
        return False
    left_text = _clean_text(left)
    right_text = _clean_text(right)
    if normalise_path(left_text) == normalise_path(right_text):
        return True
    return basename(left_text).lower() == basename(right_text).lower()


def stable_fingerprint(payload):
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


class DebugIdentity:
    """A CodeView build identity read from a PE's read-only debug directory."""

    def __init__(
        self,
        kind,
        pdb_path=None,
        guid=None,
        age=None,
        signature=None,
        signature_string=None,
        debug_index=None,
        raw=None,
    ):
        self.kind = _clean_text(kind).lower() or None
        self.pdb_path = _clean_text(pdb_path)
        self.pdb_name = basename(self.pdb_path)
        self.guid = normalise_guid(guid)
        self.age = normalise_age(age)
        self.signature = _clean_text(signature).upper() or None
        self.signature_string = _clean_text(signature_string) or None
        self.debug_index = debug_index
        self.raw = raw or {}

    @property
    def identity_key(self):
        if self.kind == "rsds" and self.guid is not None and self.age is not None:
            return "rsds:%s:%s" % (self.guid, self.age)
        if self.kind == "nb10" and self.signature and self.age is not None:
            return "nb10:%s:%s" % (self.signature, self.age)
        return None

    @property
    def is_complete(self):
        if self.kind == "rsds":
            return self.guid is not None and self.age is not None
        if self.kind == "nb10":
            return bool(self.signature) and self.age is not None
        return False

    def matches(self, guid=None, age=None, signature=None, kind=None):
        if kind and self.kind and _clean_text(kind).lower() != self.kind:
            return False
        if guid is not None and age is not None:
            return (
                self.kind == "rsds"
                and self.guid is not None
                and normalise_guid(guid) == self.guid
                and normalise_age(age) == self.age
            )
        if signature is not None and age is not None:
            return (
                self.kind == "nb10"
                and self.signature
                and _clean_text(signature).upper() == self.signature
                and normalise_age(age) == self.age
            )
        return False

    def matches_name(self, value):
        return bool(
            (self.pdb_name and name_matches(value, self.pdb_name))
            or (self.pdb_path and name_matches(value, self.pdb_path))
        )

    def to_dict(self):
        return {
            "kind": self.kind,
            "pdb": self.pdb_path or None,
            "pdb_name": self.pdb_name or None,
            "guid": self.guid,
            "age": self.age,
            "signature": self.signature,
            "signature_string": self.signature_string,
            "identity": self.identity_key,
            "complete": self.is_complete,
            "debug_index": self.debug_index,
            "raw": self.raw,
        }


class SignoffEntry:
    """One row from a symbol-library sign-off sheet.

    ``digest`` is the symbol-file digest, while ``pe_digest`` is the release
    image digest.  Either can be supplied by the sign-off material; keeping
    them separate prevents a PE digest from being mistaken for a PDB digest.
    """

    def __init__(
        self,
        name=None,
        pdb_path=None,
        guid=None,
        age=None,
        signature=None,
        digest=None,
        pe_digest=None,
        signer=None,
        signed_at=None,
        reference=None,
        notes=None,
        row=None,
        raw=None,
    ):
        self.name = _clean_text(name)
        self.pdb_path = _clean_text(pdb_path)
        self.pdb_name = basename(self.pdb_path or self.name)
        self.guid = normalise_guid(guid)
        self.age = normalise_age(age)
        self.signature = _clean_text(signature).upper() or None
        self.digest = parse_digest(digest)
        self.pe_digest = parse_digest(pe_digest)
        self.signer = _clean_text(signer)
        self.signed_at = _clean_text(signed_at)
        self.reference = _clean_text(reference)
        self.notes = _clean_text(notes)
        self.row = row
        self.raw = raw or {}

    @property
    def artifact_kind(self):
        if self.digest is not None:
            return "symbol_file"
        if self.pe_digest is not None:
            return "release_image"
        return "unknown"

    @property
    def identity_key(self):
        if self.guid is not None and self.age is not None:
            return "rsds:%s:%s" % (self.guid, self.age)
        if self.signature and self.age is not None:
            return "nb10:%s:%s" % (self.signature, self.age)
        return None

    def matches_name(self, value):
        candidates = [self.name, self.pdb_name, self.pdb_path]
        return any(name_matches(value, candidate) for candidate in candidates)

    def matches_identity(self, identity):
        if self.guid is not None and self.age is not None:
            return identity.matches(guid=self.guid, age=self.age)
        if self.signature and self.age is not None:
            return identity.matches(signature=self.signature, age=self.age)
        return False

    def to_dict(self):
        return {
            "row": self.row,
            "name": self.name or None,
            "pdb": self.pdb_path or None,
            "pdb_name": self.pdb_name or None,
            "guid": self.guid,
            "age": self.age,
            "signature": self.signature,
            "artifact_kind": self.artifact_kind,
            "digest": self.digest.to_dict() if self.digest else None,
            "pe_digest": self.pe_digest.to_dict() if self.pe_digest else None,
            "signer": self.signer or None,
            "signed_at": self.signed_at or None,
            "reference": self.reference or None,
            "notes": self.notes or None,
            "raw": self.raw,
        }


class Claim:
    """A source-location claim from a postmortem or review worksheet."""

    def __init__(
        self,
        display_name=None,
        source_file=None,
        line=None,
        symbol=None,
        address=None,
        pdb_path=None,
        pdb_name=None,
        guid=None,
        age=None,
        signature=None,
        digest=None,
        pe_digest=None,
        receipt=None,
        record_id=None,
        ordinal=None,
        metadata=None,
        raw=None,
    ):
        self.display_name = _clean_text(display_name)
        self.source_file = _clean_text(source_file)
        self.line = line
        self.symbol = _clean_text(symbol)
        self.address = address
        self.pdb_path = _clean_text(pdb_path)
        self.pdb_name = _clean_text(pdb_name) or basename(self.pdb_path)
        self.guid = normalise_guid(guid)
        self.age = normalise_age(age)
        self.signature = _clean_text(signature).upper() or None
        self.digest = parse_digest(digest)
        self.pe_digest = parse_digest(pe_digest)
        self.receipt = _clean_text(receipt)
        self.record_id = _clean_text(record_id)
        self.ordinal = ordinal
        self.metadata = metadata or {}
        self.raw = raw or {}

        if not self.display_name:
            self.display_name = (
                self.pdb_name
                or basename(self.source_file)
                or self.symbol
                or "claim-%s" % (ordinal if ordinal is not None else "?")
            )
        if not self.pdb_name and self.display_name.lower().endswith(".pdb"):
            self.pdb_name = self.display_name

    @property
    def identity_key(self):
        if self.guid is not None and self.age is not None:
            return "rsds:%s:%s" % (self.guid, self.age)
        if self.signature and self.age is not None:
            return "nb10:%s:%s" % (self.signature, self.age)
        return None

    @property
    def name_candidates(self):
        return [
            value
            for value in (self.display_name, self.pdb_name, self.pdb_path)
            if value
        ]

    @property
    def fingerprint(self):
        return stable_fingerprint(
            {
                "display_name": self.display_name,
                "source_file": self.source_file,
                "line": self.line,
                "symbol": self.symbol,
                "address": self.address,
                "pdb": self.pdb_path,
                "pdb_name": self.pdb_name,
                "guid": self.guid,
                "age": self.age,
                "signature": self.signature,
                "digest": self.digest.to_dict() if self.digest else None,
                "pe_digest": self.pe_digest.to_dict() if self.pe_digest else None,
                "receipt": self.receipt,
            }
        )

    @property
    def export_id(self):
        if self.record_id:
            return self.record_id
        ordinal = self.ordinal if self.ordinal is not None else 0
        return "claim-%04d-%s" % (ordinal, self.fingerprint[:8])

    def matches_name(self, debug_identity):
        return any(debug_identity.matches_name(value) for value in self.name_candidates)

    def to_dict(self):
        return {
            "id": self.export_id,
            "ordinal": self.ordinal,
            "display_name": self.display_name,
            "source_file": self.source_file or None,
            "line": self.line,
            "symbol": self.symbol or None,
            "address": self.address,
            "pdb": self.pdb_path or None,
            "pdb_name": self.pdb_name or None,
            "guid": self.guid,
            "age": self.age,
            "signature": self.signature,
            "digest": self.digest.to_dict() if self.digest else None,
            "pe_digest": self.pe_digest.to_dict() if self.pe_digest else None,
            "receipt": self.receipt or None,
            "fingerprint": self.fingerprint,
            "metadata": self.metadata,
            "raw": self.raw,
        }


class ClaimEvidence:
    """The graded result for one source-location claim."""

    def __init__(
        self,
        claim,
        level=NO_EVIDENCE,
        checks=None,
        reasons=None,
        conflicts=None,
        identity=None,
        signoff=None,
        matched_identities=None,
    ):
        self.claim = claim
        self.level = level
        self.checks = checks or {}
        self.reasons = list(reasons or [])
        self.conflicts = list(conflicts or [])
        self.identity = identity
        self.signoff = signoff
        self.matched_identities = list(matched_identities or [])

    @property
    def digest_complete(self):
        return bool(self.claim.digest and self.claim.digest.is_complete)

    @property
    def verified(self):
        return bool(
            self.level == DIGEST_VERIFIED
            and self.digest_complete
            and not self.conflicts
            and self.checks.get("digest_match")
        )

    @property
    def basis(self):
        if self.level == DIGEST_VERIFIED:
            return "签收材料完整摘要匹配"
        if self.level == DEBUG_RECORD_MATCH:
            return "PE 调试记录 GUID/Age 或 NB10/Age 吻合"
        if self.level == NAME_ONLY:
            return "仅文件名/显示名匹配，无构建身份或摘要"
        return "未找到可关联证据"

    def to_dict(self):
        claim = self.claim
        digest = claim.digest
        pdb_value = (
            claim.pdb_path
            or claim.pdb_name
            or (
                claim.display_name
                if claim.display_name.lower().endswith(".pdb")
                else None
            )
        )
        flat = {
            "id": claim.export_id,
            "name": claim.display_name,
            "display_name": claim.display_name,
            "file": claim.source_file or None,
            "source": claim.source_file or None,
            "source_file": claim.source_file or None,
            "location": (
                "%s:%s" % (claim.source_file, claim.line)
                if claim.source_file and claim.line is not None
                else (claim.source_file or None)
            ),
            "line": claim.line,
            "symbol": claim.symbol or None,
            "address": claim.address,
            "pdb": pdb_value,
            "pdb_name": claim.pdb_name
            or (
                basename(pdb_value)
                if pdb_value and pdb_value.lower().endswith(".pdb")
                else None
            ),
            "guid": claim.guid,
            "age": claim.age,
            "signature": claim.signature,
            "sha256": (
                digest.value
                if digest is not None and digest.algorithm == "sha256"
                else None
            ),
            "hash": digest.value if digest is not None else None,
            "digest": digest.to_dict() if digest else None,
            "digest_algorithm": digest.algorithm if digest else None,
            "digest_complete": self.digest_complete,
            "evidence_level": self.level,
            "evidence_label": EvidenceLevel.label(self.level),
            "evidence_rank": EvidenceLevel.rank(self.level),
            "verified": self.verified,
            "basis": self.basis,
            "receipt": claim.receipt or None,
            "fingerprint": claim.fingerprint,
        }
        result = dict(flat)
        result["source_location"] = {
            "file": claim.source_file or None,
            "line": claim.line,
            "symbol": claim.symbol or None,
            "address": claim.address,
        }
        result["evidence"] = {
            "level": self.level,
            "label": EvidenceLevel.label(self.level),
            "rank": EvidenceLevel.rank(self.level),
            "verified": self.verified,
            "basis": self.basis,
            "reasons": self.reasons,
            "conflicts": self.conflicts,
            "checks": self.checks,
            "matched_identity": self.identity.to_dict() if self.identity else None,
            "matched_signoff": self.signoff.to_dict() if self.signoff else None,
            "matched_identities": [item.to_dict() for item in self.matched_identities],
        }
        result["claim"] = claim.to_dict()
        result["legacy"] = dict(flat)
        return result

    def to_legacy_dict(self):
        return self.to_dict()["legacy"]
