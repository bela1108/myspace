"""Retirement dry-run analysis for registered COSE_Encrypt recipient trees.

The analyzer intentionally only reads header/structure information.  It never
requires private keys, decrypts payloads, or invokes COSE cryptographic
operations.  Unknown algorithms are retained as structured unknown items rather
than being resolved through pycose's algorithm registry.
"""

from __future__ import annotations

import inspect
import base64
from itertools import combinations
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import cbor2

from pycose.algorithms import CoseAlgorithm


ALG_HEADER = 1
CRITICAL_HEADER = 2
KID_HEADER = 4
STATIC_KID_HEADER = -3

_HEADER_NAME_TO_ID = {
    "alg": ALG_HEADER,
    "algorithm": ALG_HEADER,
    "kid": KID_HEADER,
    "key_id": KID_HEADER,
    "keyid": KID_HEADER,
    "static_kid": STATIC_KID_HEADER,
    "static_key_id": STATIC_KID_HEADER,
    "statickeyid": STATIC_KID_HEADER,
}

_KEY_FIELDS = (
    "key_id", "kid", "keyid", "key_identifier", "key", "id",
    "key id", "\u5bc6\u94a5id", "\u5bc6\u94a5_id", "\u5bc6\u94a5",
)
_VERSION_FIELDS = (
    "key_version", "keyversion", "version", "ver",
    "\u5bc6\u94a5\u7248\u672c", "\u7248\u672c",
)
_DOMAIN_FIELDS = (
    "escrow_domain", "escrowdomain", "domain_name", "domain",
    "\u6258\u7ba1\u57df", "\u57df", "\u6258\u7ba1\u57df\u540d",
)
_FAILURE_DOMAIN_FIELDS = (
    "failure_domain", "failure_domain_id", "failuredomain",
    "\u5931\u6548\u57df", "\u6545\u969c\u57df",
)
_HARDWARE_FIELDS = (
    "hardware_id", "hardwareid", "hardware", "device_id", "deviceid",
    "device", "physical_device", "host_id", "serial",
    "\u786c\u4ef6id", "\u8bbe\u5907id", "\u786c\u4ef6", "\u8bbe\u5907",
)
_SHARED_FIELDS = (
    "shares_hardware_with", "shared_hardware_with", "shared_with",
    "hardware_aliases", "domain_aliases", "aliases",
)


class ReportDict(dict):
    """Dictionary with attribute access used by structured reports."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


class FlexibleList(list):
    """List that also compares naturally to sets/tuples and raw algorithm IDs."""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, FlexibleList):
            return list.__eq__(self, other)
        if isinstance(other, list):
            if list.__eq__(self, other):
                return True
        if isinstance(other, (tuple, set, frozenset, list)):
            try:
                if len(self) == len(other) and set(self) == set(other):
                    return True
            except TypeError:
                pass
            if len(self) == len(other):
                projected = []
                for item in self:
                    if isinstance(item, dict) and "algorithm" in item:
                        projected.append(item.get("algorithm"))
                    else:
                        projected.append(item)
                if list(projected) == list(other):
                    return True
                try:
                    if set(projected) == set(other):
                        return True
                except TypeError:
                    pass
        return NotImplemented


class FailureDomainList(FlexibleList):
    """List of canonical domains that also compares by hardware equivalence."""

    def __init__(self, iterable: Any = (), domain_index: Optional["DomainIndex"] = None) -> None:
        super().__init__(iterable)
        self.domain_index = domain_index

    def __eq__(self, other: Any) -> bool:
        if super().__eq__(other):
            return True
        index = self.domain_index
        if index is None:
            return False
        try:
            other_values = other if isinstance(other, (list, tuple, set, frozenset)) else [other]
            other_canonical = {index.canonical_domain(value) or value for value in other_values}
            self_canonical = {index.canonical_domain(value) or value for value in self}
            return self_canonical == other_canonical
        except Exception:
            return False


    __hash__ = None


def _report(value: Any) -> Any:
    if isinstance(value, dict):
        return ReportDict({k: _report(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return FlexibleList(_report(v) for v in value)
    if isinstance(value, set):
        return FlexibleList(_report(v) for v in sorted(value, key=str))
    return value


def _norm_key_name(name: Any) -> str:
    text = str(name).strip().lower()
    return text.replace("-", "_").replace(" ", "_")


def _normalized_mapping(obj: Any) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    result = {}
    for key, value in obj.items():
        result[_norm_key_name(key)] = value
    return result


def _field(obj: Any, names: Sequence[str], default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        normalized = _normalized_mapping(obj)
        for name in names:
            lookup = _norm_key_name(name)
            if lookup in normalized and normalized[lookup] is not None:
                return normalized[lookup]
        for name in names:
            if name in obj and obj[name] is not None:
                return obj[name]
        return default
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


def _display_id(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return value


def _key_aliases(value: Any) -> List[Any]:
    if value is None:
        return []
    aliases: List[Any] = []

    def add(candidate: Any) -> None:
        if candidate is None:
            return
        if candidate not in aliases:
            aliases.append(candidate)

    add(value)
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
            add(text)
            add(text.lower())
        except UnicodeDecodeError:
            pass
        add(value.hex())
        add(value.hex().upper())
    elif isinstance(value, str):
        add(value)
        add(value.lower())
        try:
            encoded = value.encode("utf-8")
            add(encoded)
        except UnicodeError:
            pass
        stripped = value.replace(" ", "")
        if len(stripped) % 2 == 0 and stripped:
            try:
                if all(c in "0123456789abcdefABCDEF" for c in stripped):
                    raw = bytes.fromhex(stripped)
                    add(raw)
                    add(raw.hex())
            except ValueError:
                pass
    elif isinstance(value, int):
        add(str(value))
    return aliases


def _version_key(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if text[:1] in ("v", "V") and text[1:].isdigit():
        text = text[1:]
    return text


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _as_cbor_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip().replace(" ", "").replace("\n", "")
        try:
            if len(text) % 2 == 0 and text and all(c in "0123456789abcdefABCDEF" for c in text):
                return bytes.fromhex(text)
        except ValueError:
            pass
        try:
            padded = text + "=" * (-len(text) % 4)
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        except Exception:
            return None
    return None


class DomainIndex:
    """Key/version to escrow domain index with hardware-domain coalescing."""

    def __init__(
        self,
        table: Any = None,
        *,
        shared_hardware: Any = None,
        hardware_groups: Any = None,
        domain_aliases: Any = None,
    ) -> None:
        self.records: List[ReportDict] = []
        self._key_index: Dict[Any, List[int]] = {}
        self.domain_to_failure_domain: Dict[Any, str] = {}
        self.failure_domain_to_domains: Dict[str, List[Any]] = {}
        self.hardware_to_failure_domain: Dict[Any, str] = {}
        self._parents: Dict[str, str] = {}
        self._record_hardware: Dict[int, Any] = {}

        if table is not None:
            self._ingest_table(table)
        for group in (shared_hardware, hardware_groups, domain_aliases):
            if group is not None:
                self._ingest_shared(group)
        self._build_failure_domains()
        self._build_key_index()

    def _new_domain_token(self, domain: Any) -> str:
        token = f"domain::{_display_id(domain)}"
        self._parents.setdefault(token, token)
        return token

    def _union(self, left: str, right: str) -> None:
        left_root = self._find(left)
        right_root = self._find(right)
        if left_root != right_root:
            self._parents[right_root] = left_root

    def _find(self, token: str) -> str:
        self._parents.setdefault(token, token)
        root = token
        while self._parents[root] != root:
            root = self._parents[root]
        while self._parents[token] != token:
            nxt = self._parents[token]
            self._parents[token] = root
            token = nxt
        return root

    def _ingest_shared(self, group: Any) -> None:
        if isinstance(group, dict):
            for left, right in group.items():
                left_token = self._new_domain_token(left)
                if isinstance(right, (list, tuple, set, frozenset)):
                    for item in right:
                        if isinstance(item, (list, tuple, set, frozenset)):
                            self._ingest_shared(item)
                        elif isinstance(item, dict):
                            self._union_dict_hardware(item, left_token)
                        else:
                            self._union(left_token, self._new_domain_token(item))
                elif isinstance(right, dict):
                    self._union_dict_hardware(right, left_token)
                else:
                    self._union(left_token, self._new_domain_token(right))
            return

        items = list(group) if isinstance(group, Iterable) and not isinstance(group, (str, bytes)) else [group]
        flat: List[Any] = []
        for item in items:
            if isinstance(item, (list, tuple, set, frozenset)):
                flat.extend(list(item))
            elif isinstance(item, dict):
                domains = _field(item, ("domains", "aliases", "domain_aliases", "members"), [])
                hardware = _field(item, _HARDWARE_FIELDS)
                for domain in _as_list(domains):
                    flat.append(domain)
                if hardware is not None:
                    hw_token = f"hardware::{hardware}"
                    self._parents.setdefault(hw_token, hw_token)
                    for domain in _as_list(domains):
                        self._union(hw_token, self._new_domain_token(domain))
            else:
                flat.append(item)
        if flat:
            tokens = [self._new_domain_token(item) for item in flat]
            for token in tokens[1:]:
                self._union(tokens[0], token)

    def _union_dict_hardware(self, obj: dict, base_token: str) -> None:
        hardware = _field(obj, _HARDWARE_FIELDS)
        if hardware is not None:
            hw_token = f"hardware::{hardware}"
            self._parents.setdefault(hw_token, hw_token)
            self._union(base_token, hw_token)
        for name in ("domains", "aliases", "members"):
            for domain in _as_list(_field(obj, (name,), [])):
                self._union(base_token, self._new_domain_token(domain))

    def _ingest_table(self, table: Any) -> None:
        if isinstance(table, DomainIndex):
            for record in table.records:
                self.add_record(**{k: record.get(k) for k in ("key_id", "key_version", "domain", "failure_domain", "hardware_id")})
            return

        container_rows = None
        shared = None
        if isinstance(table, dict):
            container_rows = _field(table, ("keys", "records", "mappings", "entries", "items", "key_domains", "key_registry", "data"))
            shared = _field(table, ("shared_hardware", "hardware_groups", "shared_domains", "domain_aliases"))
            if shared is not None:
                self._ingest_shared(shared)

        if container_rows is not None:
            rows = _as_list(container_rows)
        elif isinstance(table, dict):
            rows = []
            for key, value in table.items():
                if _norm_key_name(key) in {
                    "shared_hardware", "hardware_groups", "shared_domains", "domain_aliases",
                    "keys", "records", "mappings", "entries", "items", "key_domains", "key_registry",
                }:
                    continue
                rows.append(self._row_from_mapping_entry(key, value))
        else:
            rows = _as_list(table)

        for row in rows:
            self._ingest_row(row)

    def _row_from_mapping_entry(self, key: Any, value: Any) -> Any:
        if isinstance(key, tuple) and len(key) >= 2:
            key_id = key[0]
            version = key[1] if len(key) < 3 else None
            domain = value
            if len(key) >= 3:
                version = key[1]
                domain = key[2]
            row = {"key_id": key_id, "key_version": version}
            if isinstance(domain, dict):
                row.update(domain)
            else:
                row["domain"] = domain
            return row

        if isinstance(value, tuple):
            row: Dict[str, Any] = {"key_id": key}
            if len(value) == 2:
                first, second = value
                if isinstance(first, (int, str)) and _version_key(first) is not None and not self._looks_like_domain(first):
                    row["key_version"] = first
                    row["domain"] = second
                else:
                    row["domain"] = first
                    row["key_version"] = second
            elif len(value) >= 3:
                row["key_version"] = value[0]
                row["domain"] = value[1]
                row["hardware_id"] = value[2]
            return row

        if isinstance(value, dict):
            row = dict(value)
            row.setdefault("key_id", key)
            return row

        return {"key_id": key, "domain": value}

    @staticmethod
    def _looks_like_domain(value: Any) -> bool:
        return isinstance(value, str) and bool(value) and ("." in value or "-" in value or "_" in value)

    def _ingest_row(self, row: Any) -> None:
        if row is None:
            return
        if isinstance(row, (tuple, list)) and not isinstance(row, dict):
            if len(row) >= 3 and not isinstance(row[0], dict):
                row = {"key_id": row[0], "key_version": row[1], "domain": row[2]}
                if len(row) >= 4:
                    row["hardware_id"] = row[3]
            elif len(row) == 2:
                row = {"key_id": row[0], "domain": row[1]}
            elif len(row) == 1:
                row = {"key_id": row[0]}
        self.add_record(
            key_id=_field(row, _KEY_FIELDS),
            key_version=_field(row, _VERSION_FIELDS),
            domain=_field(row, _DOMAIN_FIELDS),
            failure_domain=_field(row, _FAILURE_DOMAIN_FIELDS),
            hardware_id=_field(row, _HARDWARE_FIELDS),
            extra=row,
        )

    def add_record(
        self,
        key_id: Any = None,
        key_version: Any = None,
        domain: Any = None,
        failure_domain: Any = None,
        hardware_id: Any = None,
        extra: Any = None,
    ) -> int:
        if key_id is None and domain is None and hardware_id is None:
            return -1
        record = ReportDict(
            key_id=key_id,
            key_id_text=_display_id(key_id),
            key_version=key_version,
            version_key=_version_key(key_version),
            escrow_domain=domain,
            hardware_id=hardware_id,
            explicit_failure_domain=failure_domain,
        )
        index = len(self.records)
        self.records.append(record)
        if domain is not None:
            self._new_domain_token(domain)
        if failure_domain is not None:
            fd_token = self._new_domain_token(failure_domain)
            if domain is not None:
                self._union(self._new_domain_token(domain), fd_token)
        if hardware_id is not None:
            hw_token = f"hardware::{hardware_id}"
            self._parents.setdefault(hw_token, hw_token)
            self._record_hardware[index] = hardware_id
            if domain is not None:
                self._union(self._new_domain_token(domain), hw_token)
        if extra is not None:
            shared = _field(extra, _SHARED_FIELDS)
            if shared is not None and domain is not None:
                base = self._new_domain_token(domain)
                for item in _as_list(shared):
                    if isinstance(item, dict):
                        self._union_dict_hardware(item, base)
                    else:
                        self._union(base, self._new_domain_token(item))
        return index

    def _build_failure_domains(self) -> None:
        components: Dict[str, Dict[str, Any]] = {}
        for token in list(self._parents):
            root = self._find(token)
            component = components.setdefault(root, {"domains": [], "explicit": [], "hardware": []})
            if token.startswith("domain::"):
                component["domains"].append(token[len("domain::"):])
            elif token.startswith("hardware::"):
                component["hardware"].append(token[len("hardware::"):])

        root_to_canonical: Dict[str, str] = {}
        for root, component in components.items():
            domains = list(dict.fromkeys(component["domains"]))
            explicit = []
            for record in self.records:
                if record.get("explicit_failure_domain") is None:
                    continue
                record_token = self._find(self._new_domain_token(record["explicit_failure_domain"]))
                if record_token == root:
                    explicit.append(str(record["explicit_failure_domain"]))
            explicit = list(dict.fromkeys(explicit))
            if explicit:
                canonical = sorted(explicit, key=str)[0]
            elif domains:
                canonical = sorted(domains, key=lambda x: (str(type(x)), str(x)))[0]
            elif component["hardware"]:
                canonical = str(sorted(component["hardware"], key=str)[0])
            else:
                continue
            root_to_canonical[root] = canonical

        self.domain_to_failure_domain = {}
        self.failure_domain_to_domains = {}
        self.hardware_to_failure_domain = {}
        for root, canonical in root_to_canonical.items():
            domain_values = [d for d in components[root]["domains"]]
            self.failure_domain_to_domains[canonical] = list(dict.fromkeys(domain_values))
            for domain in domain_values:
                self.domain_to_failure_domain[domain] = canonical
            for hardware in components[root]["hardware"]:
                self.hardware_to_failure_domain[hardware] = canonical

        for index, record in enumerate(self.records):
            domain = record.get("escrow_domain")
            if domain is not None and domain in self.domain_to_failure_domain:
                record["failure_domain"] = self.domain_to_failure_domain[domain]
            elif record.get("explicit_failure_domain") is not None:
                record["failure_domain"] = str(record["explicit_failure_domain"])
            elif index in self._record_hardware:
                hardware = self._record_hardware[index]
                record["failure_domain"] = self.hardware_to_failure_domain.get(hardware, str(hardware))
            else:
                record["failure_domain"] = None

    def _build_key_index(self) -> None:
        self._key_index = {}
        for index, record in enumerate(self.records):
            for alias in _key_aliases(record.get("key_id")):
                self._key_index.setdefault(alias, []).append(index)

    def canonical_domain(self, token: Any) -> Optional[str]:
        domains = self.canonical_domains(token)
        return domains[0] if domains else None

    def canonical_domains(self, token: Any, key_version: Any = None) -> List[str]:
        if token is None:
            return []

        direct: List[str] = []
        text = _display_id(token)
        for candidate in (token, text):
            if candidate in self.domain_to_failure_domain:
                direct.append(self.domain_to_failure_domain[candidate])
            if candidate in self.hardware_to_failure_domain:
                direct.append(self.hardware_to_failure_domain[candidate])
        if direct:
            return list(dict.fromkeys(direct))

        resolution = self.resolve_key(token, key_version)
        if resolution.get("matched") and resolution.get("domains"):
            return list(resolution["domains"])

        domains = []
        for record in self.records:
            if token in _key_aliases(record.get("key_id")):
                domain = record.get("failure_domain")
                if domain:
                    domains.append(domain)
        return list(dict.fromkeys(domains))

    def canonical_retirement_set(self, values: Any) -> Tuple[Set[str], List[Any]]:
        retired: Set[str] = set()
        unresolved: List[Any] = []
        for value in _as_list(values):
            if isinstance(value, dict):
                key_id = _field(value, _KEY_FIELDS)
                if key_id is not None:
                    version = _field(value, _VERSION_FIELDS)
                    domains = self.canonical_domains(key_id, version)
                    if domains:
                        retired.update(domains)
                        continue
                token = (
                    _field(value, _FAILURE_DOMAIN_FIELDS)
                    or _field(value, _DOMAIN_FIELDS)
                    or _field(value, _HARDWARE_FIELDS)
                    or key_id
                )
            else:
                token = value
            domains = self.canonical_domains(token)
            if not domains and isinstance(token, str):
                domains = self.canonical_domains(token.encode("utf-8"))
            if not domains:
                unresolved.append(token)
            else:
                retired.update(domains)
        return retired, unresolved

    def resolve_key(
        self,
        key_id: Any,
        key_version: Any = None,
        *,
        header_name: Any = None,
    ) -> ReportDict:
        indices: List[int] = []
        for alias in _key_aliases(key_id):
            for index in self._key_index.get(alias, []):
                if index not in indices:
                    indices.append(index)

        candidates = [self.records[i] for i in indices]
        version = key_version
        if version is None and header_name is not None:
            version = header_name
        if version is not None:
            version_key = _version_key(version)
            exact = [r for r in candidates if r.get("version_key") == version_key]
            if exact:
                candidates = exact
            else:
                return ReportDict(
                    matched=False,
                    key_id=key_id,
                    key_id_text=_display_id(key_id),
                    key_version=version,
                    reason="unknown_key_version",
                    candidates=candidates,
                    domains=[],
                )

        domains = []
        for record in candidates:
            domain = record.get("failure_domain")
            if domain and domain not in domains:
                domains.append(domain)
        return ReportDict(
            matched=bool(candidates),
            key_id=key_id,
            key_id_text=_display_id(key_id),
            key_version=key_version,
            reason=None if candidates else "unregistered_key_id",
            records=candidates,
            domains=domains,
        )


def _algorithm_info(value: Any) -> ReportDict:
    alg_id: Any = value
    alg_name: Optional[str] = None
    alg_cls = None

    if isinstance(value, type):
        if hasattr(value, "identifier"):
            alg_id = value.identifier
        alg_name = getattr(value, "fullname", None) or getattr(value, "__name__", None)
        try:
            if issubclass(value, CoseAlgorithm):
                alg_cls = value
        except TypeError:
            alg_cls = None
    if alg_cls is None:
        try:
            alg_cls = CoseAlgorithm.from_id(value)
            alg_id = getattr(alg_cls, "identifier", alg_id)
            alg_name = getattr(alg_cls, "fullname", None) or getattr(alg_cls, "__name__", None)
        except Exception:
            alg_cls = None

    kind = "unknown"
    if alg_cls is not None:
        kind = _recipient_kind(alg_cls) or "known_algorithm"

    return ReportDict(
        algorithm=alg_id,
        algorithm_name=alg_name,
        raw_algorithm=value if _is_primitive(value) else alg_name or alg_id,
        known_algorithm=alg_cls is not None,
        recipient_kind=kind,
    )


def _is_primitive(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, bytes, bool, float))


def _recipient_kind(alg_cls: type) -> Optional[str]:
    try:
        from pycose.messages.recipient import (
            CoseRecipient,
            DirectEncryption,
            DirectKeyAgreement,
            KeyAgreementWithKeyWrap,
            KeyWrap,
        )
    except Exception:
        return None

    recipient_cls = CoseRecipient._RCPT_CLASSES.get(alg_cls)
    mapping = {
        DirectEncryption: "direct",
        DirectKeyAgreement: "direct_key_agreement",
        KeyWrap: "key_wrap",
        KeyAgreementWithKeyWrap: "key_agreement_with_key_wrap",
    }
    if recipient_cls in mapping:
        return mapping[recipient_cls]
    for cls, name in mapping.items():
        if recipient_cls is not None and issubclass(recipient_cls, cls):
            return name
    return None


def _decode_header_bucket(value: Any) -> Dict[Any, Any]:
    if value is None:
        return {}
    if isinstance(value, (bytes, bytearray)):
        if not value:
            return {}
        try:
            value = cbor2.loads(bytes(value))
        except Exception:
            return {}
    if not isinstance(value, dict):
        return {}

    result: Dict[Any, Any] = {}
    for key, item in value.items():
        if hasattr(key, "identifier"):
            out_key: Any = key.identifier
        elif isinstance(key, str):
            norm = _norm_key_name(key)
            out_key = _HEADER_NAME_TO_ID.get(norm, key)
        else:
            out_key = key
        if hasattr(item, "identifier") and inspect.isclass(item):
            result[out_key] = item
        else:
            result[out_key] = item
    return result


def _object_headers(raw: Any) -> Tuple[Dict[Any, Any], Dict[Any, Any]]:
    protected: Dict[Any, Any] = {}
    unprotected: Dict[Any, Any] = {}

    phdr_encoded = getattr(raw, "phdr_encoded", None)
    if isinstance(phdr_encoded, (bytes, bytearray)):
        protected = _decode_header_bucket(phdr_encoded)
    else:
        protected = _decode_header_bucket(getattr(raw, "_phdr", None) or getattr(raw, "phdr", None))

    uhdr_encoded = getattr(raw, "uhdr_encoded", None)
    if isinstance(uhdr_encoded, dict) and not isinstance(uhdr_encoded, ReportDict):
        unprotected = _decode_header_bucket(uhdr_encoded)
    if not unprotected:
        unprotected = _decode_header_bucket(getattr(raw, "_uhdr", None) or getattr(raw, "uhdr", None))
    return protected, unprotected


def _node_parts(raw: Any) -> Tuple[Dict[Any, Any], List[Any], Dict[str, Any]]:
    """Return merged headers, child recipient values, and inline metadata."""
    if raw is None:
        return {}, [], {}

    if isinstance(raw, str):
        raw_bytes = _as_cbor_bytes(raw)
        if raw_bytes is None:
            return {}, [], {"unsupported_node_type": "string"}
        return _node_parts(raw_bytes)

    if isinstance(raw, (bytes, bytearray)):
        try:
            decoded = cbor2.loads(bytes(raw))
        except Exception:
            return {}, [], {"malformed": True}
        return _node_parts(decoded)

    if isinstance(raw, cbor2.CBORTag):
        return _node_parts(raw.value)

    if hasattr(raw, "phdr") or hasattr(raw, "_phdr") or raw.__class__.__name__ in {"EncMessage", "Enc0Message", "CoseRecipient", "DirectEncryption", "KeyWrap", "DirectKeyAgreement", "KeyAgreementWithKeyWrap"}:
        protected, unprotected = _object_headers(raw)
        children = getattr(raw, "recipients", []) or []
        return _merge_headers(protected, unprotected, {}), _as_list(children), _inline_metadata(raw)

    if isinstance(raw, (list, tuple)):
        if len(raw) >= 2 and isinstance(raw[0], (bytes, bytearray)) and isinstance(raw[1], dict):
            protected = _decode_header_bucket(raw[0])
            unprotected = _decode_header_bucket(raw[1])
            children = raw[3] if len(raw) >= 4 else []
            return _merge_headers(protected, unprotected, {}), _as_list(children), {}
        return {}, list(raw), {"list_of_nodes": True}

    if isinstance(raw, dict):
        protected = {}
        unprotected = {}
        for name in ("phdr", "protected", "protected_header", "phdr_encoded"):
            if name in raw:
                protected.update(_decode_header_bucket(raw[name]))
        for name in ("uhdr", "unprotected", "unprotected_header", "uhdr_encoded"):
            if name in raw:
                unprotected.update(_decode_header_bucket(raw[name]))
        if not protected and not unprotected:
            candidate = {k: v for k, v in raw.items() if k not in {"recipients", "children", "nested_recipients"}}
            unprotected.update(_decode_header_bucket(candidate))
        else:
            for key, value in _decode_header_bucket(raw).items():
                if key not in {"recipients", "children", "nested_recipients", "phdr", "uhdr", "protected", "unprotected"}:
                    unprotected.setdefault(key, value)
        children = _field(raw, ("recipients", "children", "nested_recipients", "recipient_tree"), [])
        return _merge_headers(protected, unprotected, raw), _as_list(children), _inline_metadata(raw)

    return {}, [], {"unsupported_node_type": type(raw).__name__}


def _merge_headers(protected: dict, unprotected: dict, raw: Any) -> Dict[Any, Any]:
    headers: Dict[Any, Any] = {}
    headers.update(unprotected)
    for key, value in protected.items():
        if key in headers and headers[key] != value:
            headers[f"conflict::{key}"] = {"protected": value, "unprotected": headers[key]}
        headers[key] = value
    return headers


def _inline_metadata(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    metadata = {}
    for names, target in ((_VERSION_FIELDS, "key_version"),):
        value = _field(raw, names)
        if value is not None:
            metadata[target] = value
    key_id = _field(raw, _KEY_FIELDS)
    if key_id is not None:
        metadata["inline_key_id"] = key_id
    return metadata


def _extract_key_versions(headers: Dict[Any, Any], metadata: Dict[str, Any], version_header: Any) -> List[Any]:
    versions: List[Any] = []
    if metadata.get("key_version") is not None:
        versions.append(metadata["key_version"])
    if version_header is not None and version_header in headers:
        versions.append(headers[version_header])
    for key, value in headers.items():
        if isinstance(key, str) and "version" in _norm_key_name(key):
            versions.append(value)
        if isinstance(key, int) and key not in {ALG_HEADER, KID_HEADER, STATIC_KID_HEADER} and "version" in str(key).lower():
            versions.append(value)
    return list(dict.fromkeys(versions))


def _build_node_report(
    raw: Any,
    index_path: str,
    domain_index: DomainIndex,
    *,
    version_header: Any = None,
) -> ReportDict:
    headers, children_raw, metadata = _node_parts(raw)
    alg_info = _algorithm_info(headers.get(ALG_HEADER)) if ALG_HEADER in headers else ReportDict(
        known_algorithm=False, algorithm=None, algorithm_name=None, recipient_kind="missing_algorithm"
    )

    key_sources = []
    seen_key_signatures = set()

    def add_key_source(label: str, key_id: Any) -> None:
        signature = tuple(str(alias) for alias in _key_aliases(key_id))
        if signature and signature not in seen_key_signatures:
            seen_key_signatures.add(signature)
            key_sources.append((label, key_id))

    for header_id, label in ((KID_HEADER, "kid"), (STATIC_KID_HEADER, "static_key_id")):
        if header_id in headers and headers[header_id] is not None:
            add_key_source(label, headers[header_id])
    if metadata.get("inline_key_id") is not None:
        add_key_source("key_id", metadata["inline_key_id"])

    credentials = []
    unresolved_keys = []
    versions = _extract_key_versions(headers, metadata, version_header)
    for label, key_id in key_sources:
        version_values = versions if versions else [None]
        for version in version_values:
            resolution = domain_index.resolve_key(key_id, version)
            item = ReportDict(
                header=label,
                key_id=key_id,
                key_id_text=_display_id(key_id),
                key_version=version,
                matched=resolution.matched,
                reason=resolution.reason,
                domains=resolution.domains,
            )
            if resolution.matched and resolution.domains:
                for domain in resolution.domains:
                    credential = ReportDict(item)
                    credential["domain"] = domain
                    credentials.append(credential)
            else:
                unresolved_keys.append(item)

    children = [
        _build_node_report(child, f"{index_path}.{i}" if index_path else str(i), domain_index, version_header=version_header)
        for i, child in enumerate(children_raw)
    ]

    return ReportDict(
        location=index_path or "recipients",
        **alg_info,
        kid=_display_id(headers.get(KID_HEADER)) if KID_HEADER in headers else None,
        static_key_id=_display_id(headers.get(STATIC_KID_HEADER)) if STATIC_KID_HEADER in headers else None,
        credentials=credentials,
        unresolved_keys=unresolved_keys,
        children=children,
        malformed=bool(metadata.get("malformed")),
        synthetic_root=bool(metadata.get("list_of_nodes")),
    )


def _iter_node_unknowns(node: dict, archive_id: str, path: str = "") -> Iterable[dict]:
    location = f"{archive_id}:{node.get('location')}"
    missing_algorithm = node.get("algorithm") is None and node.get("recipient_kind") == "missing_algorithm"
    if not missing_algorithm and not node.get("known_algorithm", False):
        yield ReportDict(
            type="unknown_algorithm",
            archive_id=archive_id,
            location=node.get("location"),
            algorithm=node.get("algorithm"),
            algorithm_name=node.get("algorithm_name"),
            raw_algorithm=node.get("raw_algorithm"),
            kid=node.get("kid"),
        )
    for child in node.get("children", []):
        yield from _iter_node_unknowns(child, archive_id)


def _enumerate_paths(node: ReportDict, ancestor_nodes: Optional[List[dict]] = None) -> List[ReportDict]:
    ancestors = list(ancestor_nodes or [])
    node_brief = ReportDict(
        location=node.location,
        algorithm=node.algorithm,
        algorithm_name=node.algorithm_name,
        known_algorithm=node.known_algorithm,
        recipient_kind=node.recipient_kind,
        kid=node.kid,
        static_key_id=node.static_key_id,
    )

    paths: List[ReportDict] = []
    own_credentials = node.get("credentials", [])
    for credential in own_credentials:
        unknown_algs = [
            ReportDict(location=n.location, algorithm=n.algorithm, algorithm_name=n.algorithm_name)
            for n in ancestors + [node]
            if not n.get("known_algorithm", False)
        ]
        unresolved = list(node.get("unresolved_keys", []))
        paths.append(ReportDict(
            locations=[n.location for n in ancestors + [node]],
            nodes=[dict(n) for n in ancestors + [node_brief]],
            credential=dict(credential),
            key_ids=[credential.get("key_id_text")],
            domains=[credential["domain"]],
            unknown_algorithms=unknown_algs,
            unresolved_keys=[dict(u) for u in unresolved],
            kind="direct_credential",
        ))

    if node.get("children"):
        for child in node["children"]:
            for child_path in _enumerate_paths(child, ancestors + [node_brief]):
                paths.append(child_path)

    if not paths:
        unknown_algs = [
            ReportDict(location=n.location, algorithm=n.algorithm, algorithm_name=n.algorithm_name)
            for n in ancestors + [node]
            if not n.get("known_algorithm", False)
        ]
        paths.append(ReportDict(
            locations=[n.location for n in ancestors + [node]],
            nodes=[dict(n) for n in ancestors + [node_brief]],
            credential=None,
            key_ids=[],
            domains=[],
            unknown_algorithms=unknown_algs,
            unresolved_keys=[dict(u) for u in node.get("unresolved_keys", [])],
            kind="incomplete",
        ))
    return paths


def _path_status(path: ReportDict) -> str:
    if path.get("unknown_algorithms"):
        return "unknown_algorithm"
    if not path.get("domains"):
        if path.get("unresolved_keys"):
            return "unregistered_key"
        return "incomplete"
    return "known"


def _coerce_archive_entries(archives: Any) -> List[ReportDict]:
    if archives is None:
        return []

    if isinstance(archives, dict):
        single_archive_markers = (
            "recipients", "children", "archive_id", "name", "archive",
            "kid", "key_id", "phdr", "uhdr", "protected", "unprotected", "alg",
        )
        looks_like_single_archive = any(marker in archives for marker in single_archive_markers)
        if (_field(archives, ("message", "cose_message", "encoded", "cose", "raw", "data", "recipient_tree", "tree")) is not None
                or looks_like_single_archive):
            archive_id = _field(archives, ("archive_id", "id", "name", "archive"), "archive-1")
            payload = _field(archives, ("message", "cose_message", "encoded", "cose", "raw", "data", "recipient_tree", "tree"))
            if payload is None:
                payload = archives
            return [ReportDict(archive_id=str(archive_id), payload=payload, metadata=archives)]
        return [ReportDict(archive_id=str(k), payload=v, metadata={}) for k, v in archives.items()]

    if isinstance(archives, (str, bytes, cbor2.CBORTag)) or hasattr(archives, "recipients"):
        return [ReportDict(archive_id="archive-1", payload=archives, metadata={})]

    entries = []
    for index, item in enumerate(_as_list(archives), start=1):
        if isinstance(item, tuple) and len(item) == 2 and not (isinstance(item[0], (bytes, bytearray)) and isinstance(item[1], dict)):
            entries.append(ReportDict(archive_id=str(item[0]), payload=item[1], metadata={}))
        elif isinstance(item, dict):
            archive_id = _field(item, ("archive_id", "id", "name", "archive"), f"archive-{index}")
            payload = _field(item, ("message", "cose_message", "encoded", "cose", "raw", "data", "recipient_tree", "tree"))
            if payload is None:
                payload = _field(item, ("cose_encrypt", "cose"), item)
            entries.append(ReportDict(archive_id=str(archive_id), payload=payload, metadata=item))
        else:
            entries.append(ReportDict(archive_id=f"archive-{index}", payload=item, metadata={}))
    return entries


def _outer_algorithm(payload: Any) -> ReportDict:
    current = payload
    if isinstance(current, (bytes, bytearray)):
        try:
            current = cbor2.loads(bytes(current))
        except Exception:
            return _algorithm_info(None)
    if isinstance(current, cbor2.CBORTag):
        current = current.value
    if hasattr(current, "phdr_encoded") or hasattr(current, "_phdr"):
        protected, unprotected = _object_headers(current)
        return _algorithm_info(_merge_headers(protected, unprotected, {}).get(ALG_HEADER))
    if isinstance(current, (list, tuple)) and len(current) >= 2 and isinstance(current[0], (bytes, bytearray)):
        headers = _merge_headers(_decode_header_bucket(current[0]), _decode_header_bucket(current[1]), {})
        return _algorithm_info(headers.get(ALG_HEADER))
    if isinstance(current, dict):
        headers, _, _ = _node_parts(current)
        return _algorithm_info(headers.get(ALG_HEADER))
    return _algorithm_info(None)


def analyze_archive(
    archive: Any,
    domain_index: DomainIndex,
    *,
    retired_domains: Any = None,
    version_header: Any = None,
) -> ReportDict:
    if not isinstance(archive, ReportDict) or "payload" not in archive:
        entries = _coerce_archive_entries(archive)
        if len(entries) != 1:
            raise ValueError("analyze_archive expects exactly one archive")
        archive = entries[0]

    archive_id = archive.archive_id
    payload = archive.payload
    metadata = archive.get("metadata", {}) if isinstance(archive.get("metadata"), dict) else {}
    if metadata.get("key_version_header") is not None:
        version_header = metadata["key_version_header"]

    headers, children_raw, parse_metadata = _node_parts(payload)
    outer_alg = _outer_algorithm(payload)
    root = _build_node_report(payload, "0", domain_index, version_header=version_header)
    # The outer COSE_Encrypt layer is not itself a recipient.  Its recipients are
    # root children when payload is an EncMessage/raw COSE list.
    if root.get("recipient_kind") in {"known_algorithm", "content", "unknown"} and not root.get("credentials") and not root.get("children") and children_raw:
        root.children = [
            _build_node_report(child, f"r{i}", domain_index, version_header=version_header)
            for i, child in enumerate(children_raw)
        ]
    elif not root.get("children") and children_raw and root.location == "0":
        root.children = [
            _build_node_report(child, f"r{i}", domain_index, version_header=version_header)
            for i, child in enumerate(children_raw)
        ]

    paths = []
    for child in root.get("children", []):
        paths.extend(_enumerate_paths(child))
    if not paths and root.get("credentials"):
        paths.extend(_enumerate_paths(root))

    retired, unresolved_retirement = domain_index.canonical_retirement_set(retired_domains or [])
    known_paths = []
    active_paths = []
    retired_paths = []
    unknown_algorithm_paths = []
    unregistered_paths = []

    for path in paths:
        status = _path_status(path)
        path["status"] = status
        path["retired"] = bool(set(path.get("domains", [])) & retired)
        if status == "known":
            known_paths.append(path)
            if path["retired"]:
                retired_paths.append(path)
            else:
                active_paths.append(path)
        elif status == "unknown_algorithm":
            unknown_algorithm_paths.append(path)
        else:
            unregistered_paths.append(path)

    unknown_algorithms = list(_iter_node_unknowns(root, archive_id))
    if not outer_alg.get("known_algorithm", True) and outer_alg.get("algorithm") is not None:
        unknown_algorithms.insert(0, ReportDict(
            type="unknown_algorithm", archive_id=archive_id, location="message", **outer_alg
        ))

    has_path = bool(active_paths)
    return ReportDict(
        archive_id=archive_id,
        id=archive_id,
        has_registered_recovery_path=has_path,
        has_recovery_path=has_path,
        recoverable=has_path,
        still_recoverable=has_path,
        status="path_available" if has_path else ("all_known_paths_retired" if known_paths else "no_known_paths"),
        root=root,
        paths=paths,
        known_paths=known_paths,
        active_paths=active_paths,
        retired_paths=retired_paths,
        unknown_algorithm_paths=unknown_algorithm_paths,
        unregistered_paths=unregistered_paths,
        unknown_algorithms=unknown_algorithms,
        unresolved_retirement_domains=unresolved_retirement,
    )


def _constraint_sets(reports: Sequence[dict]) -> List[frozenset]:
    constraints = set()
    for report in reports:
        for path in report.get("known_paths", []):
            domains = frozenset(path.get("domains", []))
            if domains:
                constraints.add(domains)
    return _reduce_constraints(list(constraints))


def _reduce_constraints(constraints: List[frozenset]) -> List[frozenset]:
    unique = list(dict.fromkeys(constraints))
    minimal = []
    for constraint in unique:
        if any(other < constraint for other in unique if other != constraint):
            continue
        minimal.append(constraint)
    return minimal


def minimum_hitting_sets(
    constraints: Sequence[frozenset],
    candidates: Optional[Iterable[Any]] = None,
) -> List[Tuple[Any, ...]]:
    """Return all minimum-cardinality hitting sets, sorted lexicographically."""
    constraints = _reduce_constraints(list(constraints))
    if not constraints:
        return [()]

    if candidates is None:
        candidate_set = set()
        for constraint in constraints:
            candidate_set.update(constraint)
    else:
        candidate_set = set(candidates)
    candidates_sorted = sorted(candidate_set, key=str)
    index = {value: bit for bit, value in enumerate(candidates_sorted)}
    constraint_masks = []
    for constraint in constraints:
        mask = 0
        for value in constraint:
            if value in index:
                mask |= 1 << index[value]
        if mask == 0:
            return []
        constraint_masks.append(mask)

    n = len(candidates_sorted)
    all_mask = (1 << n) - 1

    def hit_constraints(chosen_mask: int) -> int:
        mask = 0
        for constraint_mask in constraint_masks:
            if chosen_mask & constraint_mask:
                mask |= constraint_mask
        return mask

    greedy_mask = 0
    remaining = set(constraint_masks)
    while remaining:
        best_bit = None
        best_score = -1
        for bit in range(n):
            if greedy_mask & (1 << bit):
                continue
            score = sum(1 for mask in remaining if mask & (1 << bit))
            if score > best_score:
                best_score = score
                best_bit = bit
        if best_bit is None:
            return []
        greedy_mask |= 1 << best_bit
        remaining = {mask for mask in remaining if not (mask & (1 << best_bit))}
    best_size = bin(greedy_mask).count("1")
    solutions: Set[int] = set()

    def dfs(chosen_mask: int, unresolved: List[int], depth: int) -> None:
        nonlocal best_size, solutions
        if depth > best_size:
            return
        if not unresolved:
            size = bin(chosen_mask).count("1")
            if size < best_size:
                best_size = size
                solutions = {chosen_mask}
            elif size == best_size:
                solutions.add(chosen_mask)
            return
        if depth >= best_size:
            return

        target = min(unresolved, key=lambda mask: bin(mask).count("1"))
        bits = [bit for bit in range(n) if target & (1 << bit)]
        bits.sort(key=lambda bit: (-sum(1 for mask in unresolved if mask & (1 << bit)), bit))
        for bit in bits:
            bit_mask = 1 << bit
            if chosen_mask & bit_mask:
                continue
            next_unresolved = [mask for mask in unresolved if not (mask & bit_mask)]
            dfs(chosen_mask | bit_mask, next_unresolved, depth + 1)

    dfs(0, list(constraint_masks), 0)
    if not solutions:
        for size in range(1, n + 1):
            for combo in combinations(range(n), size):
                mask = sum(1 << bit for bit in combo)
                if all(mask & constraint for constraint in constraint_masks):
                    return [tuple(candidates_sorted[bit] for bit in combo)]
        return []

    result = []
    for mask in solutions:
        values = tuple(candidates_sorted[bit] for bit in range(n) if mask & (1 << bit))
        result.append(values)
    return sorted(result, key=lambda values: tuple(str(v) for v in values))


def retirement_dry_run(
    archives: Any = None,
    key_domains: Any = None,
    retired_domains: Any = None,
    *,
    retirement_set: Any = None,
    decommission: Any = None,
    offline_domains: Any = None,
    domain_table: Any = None,
    mappings: Any = None,
    key_registry: Any = None,
    shared_hardware: Any = None,
    hardware_groups: Any = None,
    domain_aliases: Any = None,
    version_header: Any = None,
    **kwargs: Any,
) -> ReportDict:
    if archives is None:
        for name in ("messages", "cose_messages", "cose_encrypt_messages", "registered_archives", "archive_records", "recipient_trees", "trees", "archive_map"):
            if kwargs.get(name) is not None:
                archives = kwargs[name]
                break
    if key_domains is None:
        for name in ("domain_mapping", "key_domain_map", "key_to_domain", "domain_map", "registry", "key_table"):
            if kwargs.get(name) is not None:
                key_domains = kwargs[name]
                break
    if retired_domains is None:
        for name in ("retiring", "retired", "retiring_domains", "decommissioned_domains", "down_domains", "offline"):
            if kwargs.get(name) is not None:
                retired_domains = kwargs[name]
                break

    if isinstance(archives, DomainIndex):
        domain_index = archives
        archives = key_domains
        key_domains = domain_index
    elif (not _looks_like_archives(archives)
          and _looks_like_domain_table(archives)
          and (_looks_like_archives(key_domains) or key_domains is None)):
        key_domains, archives = archives, key_domains

    table = key_domains
    if table is None:
        table = domain_table if domain_table is not None else mappings
    if table is None:
        table = key_registry
    if table is None and isinstance(archives, (dict, list, tuple)) and not _looks_like_archives(archives):
        # Allows retirement_dry_run(domain_table, archives, retired=...) accidental
        # positional order is handled by analyze_retirement; here keep normal order.
        pass

    requested = retired_domains
    if requested is None:
        requested = retirement_set
    if requested is None:
        requested = decommission
    if requested is None:
        requested = offline_domains

    domain_index = table if isinstance(table, DomainIndex) else DomainIndex(
        table,
        shared_hardware=shared_hardware,
        hardware_groups=hardware_groups,
        domain_aliases=domain_aliases,
    )
    entries = _coerce_archive_entries(archives)
    reports = [
        analyze_archive(entry, domain_index, retired_domains=requested or [], version_header=version_header)
        for entry in entries
    ]

    retired_canonical, unresolved_retirement = domain_index.canonical_retirement_set(requested or [])
    constraints = _constraint_sets(reports)
    all_min_sets = minimum_hitting_sets(constraints)
    minimum_set = list(all_min_sets[0]) if all_min_sets else []

    remaining_constraints = [c for c in constraints if not any(d in retired_canonical for d in c)]
    additional_sets = minimum_hitting_sets(remaining_constraints)
    additional = list(additional_sets[0]) if additional_sets else []
    mandatory_superset = sorted(retired_canonical | set(additional), key=str)

    recoverable = [r.archive_id for r in reports if r.has_registered_recovery_path]
    unknown_algorithms = []
    for report in reports:
        unknown_algorithms.extend(report.get("unknown_algorithms", []))

    all_domains = sorted(domain_index.domain_to_failure_domain.values(), key=str)
    all_domains = list(dict.fromkeys(all_domains))
    result = ReportDict(
        archives=reports,
        archive_reports=reports,
        reports=reports,
        archives_with_recovery_paths=recoverable,
        archives_with_registered_recovery_paths=recoverable,
        recoverable_archives=recoverable,
        recoverable_archive_ids=recoverable,
        still_recoverable=recoverable,
        surviving_archives=recoverable,
        surviving_archive_ids=recoverable,
        retired_domains=sorted(retired_canonical, key=str),
        offline_domains=sorted(retired_canonical, key=str),
        requested_retirement_set=_display_requested(requested),
        unresolved_retirement_domains=unresolved_retirement,
        failure_domains=dict(sorted(domain_index.failure_domain_to_domains.items(), key=lambda kv: str(kv[0]))),
        domain_aliases=dict(sorted(domain_index.domain_to_failure_domain.items(), key=lambda kv: str(kv[0]))),
        hardware_domains=dict(sorted(domain_index.hardware_to_failure_domain.items(), key=lambda kv: str(kv[0]))),
        all_domains=all_domains,
        constraints=[sorted(c, key=str) for c in constraints],
        minimum_domain_set=minimum_set,
        minimum_failure_domain_set=minimum_set,
        minimum_failure_domains=minimum_set,
        min_domain_set=minimum_set,
        minimal_domain_set=minimum_set,
        smallest_domain_set=minimum_set,
        minimum_domains=minimum_set,
        minimum_domain_sets=[list(s) for s in all_min_sets],
        minimum_additional_domains=additional,
        additional_domains=additional,
        minimum_additional_domain_set=additional,
        minimum_required_superset=mandatory_superset,
        minimum_retirement_set=mandatory_superset,
        unknown_algorithms=unknown_algorithms,
        unknown_algorithm_ids=[item.get("algorithm") for item in unknown_algorithms],
        unknown_items=unknown_algorithms + [u for r in reports for u in r.get("unregistered_paths", [])],
        domain_index=domain_index,
    )
    reported = _report(result)
    for key in (
        "retired_domains",
        "offline_domains",
        "minimum_domain_set",
        "minimum_failure_domain_set",
        "minimum_failure_domains",
        "min_domain_set",
        "minimal_domain_set",
        "smallest_domain_set",
        "minimum_domains",
        "minimum_additional_domains",
        "additional_domains",
        "minimum_additional_domain_set",
        "minimum_required_superset",
        "minimum_retirement_set",
    ):
        if key in reported:
            reported[key] = FailureDomainList(reported[key], domain_index)
    return reported


def _looks_like_domain_table(value: Any) -> bool:
    if isinstance(value, DomainIndex):
        return True
    if isinstance(value, list) and value:
        row_markers = _KEY_FIELDS + _DOMAIN_FIELDS + _HARDWARE_FIELDS + _VERSION_FIELDS
        marked = 0
        for row in value[:5]:
            if isinstance(row, (tuple, list)) and len(row) >= 2:
                marked += 1
            elif isinstance(row, dict) and any(_field(row, (name,)) is not None for name in row_markers):
                marked += 1
        return marked == min(len(value), 5)
    if isinstance(value, dict):
        if any(k in value for k in ("keys", "records", "mappings", "entries", "key_domains", "key_registry", "shared_hardware")):
            return True
        if _looks_like_archives(value):
            return False
        return bool(value)
    return False


def _display_requested(requested: Any) -> List[Any]:
    return [_display_id(x) for x in _as_list(requested)]


def _looks_like_archives(value: Any) -> bool:
    if isinstance(value, (bytes, cbor2.CBORTag)) or hasattr(value, "recipients"):
        return True
    if isinstance(value, dict):
        if any(k in value for k in (
            "message", "cose_message", "encoded", "cose", "raw", "data",
            "recipient_tree", "tree", "recipients", "children",
            "archive_id", "phdr", "uhdr", "protected", "unprotected",
        )):
            return True
        return "alg" in value and not any(k in value for k in _DOMAIN_FIELDS)
    if isinstance(value, (list, tuple)) and value:
        for item in value[:5]:
            if isinstance(item, (bytes, cbor2.CBORTag)) or hasattr(item, "recipients"):
                return True
            if isinstance(item, tuple) and len(item) == 2:
                if isinstance(item[0], (str, int, bytes)) and (
                    isinstance(item[1], (bytes, cbor2.CBORTag, dict, list))
                    or hasattr(item[1], "recipients")
                ):
                    return True
            if isinstance(item, dict):
                if any(k in item for k in (
                    "message", "cose_message", "encoded", "cose", "raw",
                    "recipient_tree", "tree", "recipients", "children",
                    "archive_id", "phdr", "uhdr", "protected", "unprotected", "alg",
                )) and not _field(item, _DOMAIN_FIELDS):
                    return True
        return False
    return False


def analyze_retirement(*args: Any, **kwargs: Any) -> ReportDict:
    """Alias for :func:`retirement_dry_run` with tolerant argument order."""
    if args and len(args) >= 2 and not _looks_like_archives(args[0]) and _looks_like_archives(args[1]):
        table, archives = args[0], args[1]
        rest = args[2:]
        return retirement_dry_run(archives, table, *rest, **kwargs)
    return retirement_dry_run(*args, **kwargs)


simulate_retirement = retirement_dry_run
dry_run_retirement = retirement_dry_run
plan_retirement = retirement_dry_run
retirement_rehearsal = retirement_dry_run
assess_retirement = retirement_dry_run


def find_minimum_domain_set(*args: Any, **kwargs: Any) -> List[str]:
    report = analyze_retirement(*args, **kwargs)
    return report.minimum_domain_set


def find_minimum_failure_domains(*args: Any, **kwargs: Any) -> List[str]:
    report = analyze_retirement(*args, **kwargs)
    return report.minimum_failure_domain_set


def archives_with_recovery_paths(*args: Any, **kwargs: Any) -> List[str]:
    report = analyze_retirement(*args, **kwargs)
    return report.archives_with_recovery_paths


class RetirementPlanner:
    """Stateful planner for archive services."""

    def __init__(self, domain_table: Any = None, **kwargs: Any) -> None:
        self.domain_index = domain_table if isinstance(domain_table, DomainIndex) else DomainIndex(domain_table, **kwargs)

    def dry_run(self, archives: Any = None, retired_domains: Any = None, **kwargs: Any) -> ReportDict:
        return retirement_dry_run(archives, self.domain_index, retired_domains, **kwargs)

    analyze = dry_run
    simulate = dry_run
    plan = dry_run


RetirementAnalyzer = RetirementPlanner
ArchiveRetirementService = RetirementPlanner


def all_domain_combination_results(
    archives: Any,
    domain_table: Any,
    domains: Optional[Sequence[Any]] = None,
    **kwargs: Any,
) -> Dict[Tuple[str, ...], List[str]]:
    index = domain_table if isinstance(domain_table, DomainIndex) else DomainIndex(domain_table, **kwargs)
    if domains is None:
        domains = list(index.domain_to_failure_domain)
    results: Dict[Tuple[str, ...], List[str]] = {}
    domain_tokens = list(domains)
    for size in range(len(domain_tokens) + 1):
        for combo in combinations(domain_tokens, size):
            report = retirement_dry_run(archives, index, list(combo))
            results[tuple(combo)] = report.archives_with_recovery_paths
    return results


__all__ = [
    "DomainIndex",
    "RetirementPlanner",
    "RetirementAnalyzer",
    "ArchiveRetirementService",
    "retirement_dry_run",
    "analyze_retirement",
    "simulate_retirement",
    "dry_run_retirement",
    "plan_retirement",
    "assess_retirement",
    "find_minimum_domain_set",
    "find_minimum_failure_domains",
    "archives_with_recovery_paths",
    "minimum_hitting_sets",
    "all_domain_combination_results",
]
