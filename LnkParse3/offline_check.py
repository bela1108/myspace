"""Offline cross-check of Darwin LNK blocks against MSI registration excerpts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from LnkParse3.extra.darwin import Darwin
from LnkParse3.extra.darwin import DARWIN_ANSI_START
from LnkParse3.extra.darwin import DARWIN_UNICODE_START
from LnkParse3.lnk_file import LnkFile
from LnkParse3.utils import parse_packed_uuid


SCHEMA_VERSION = "lnkparse.msi_offline_check/v1"
MACHINE_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
GUID_RE = __import__("re").compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)


def canonical_guid(value):
    """Normalize a plain, braced, or packed Darwin/MSI GUID."""
    if value is None:
        return None

    if isinstance(value, bytes):
        value = value.decode("ascii", errors="ignore")

    text = str(value).strip()
    if not text:
        return None

    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1].strip()

    if len(text) == 20 and "-" not in text:
        try:
            text = parse_packed_uuid(text)
        except (IndexError, ValueError):
            return None

    text = text.upper()
    return text if GUID_RE.fullmatch(text) else None


def _ci_get(obj, *keys, default=None):
    if not isinstance(obj, dict):
        return default
    lowered = {str(key).lower(): value for key, value in obj.items()}
    for key in keys:
        if key.lower() in lowered and lowered[key.lower()] is not None:
            return lowered[key.lower()]
    return default


def _as_nodes(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        nodes = []
        for key, item in value.items():
            if isinstance(item, dict):
                node = dict(item)
                node.setdefault("_key", key)
            else:
                node = {"_key": key, "value": item}
            nodes.append(node)
        return nodes
    return [{"value": value}]


def _line_of(node):
    value = _ci_get(
        node,
        "line",
        "line_number",
        "lineno",
        "line_no",
        "source_line",
        "registry_line",
    )
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return value


def _pointer(parent, key=None, index=None):
    pointer = parent or ""
    if key is not None:
        pointer += f"/{key}"
    if index is not None:
        pointer += f"/{index}"
    return pointer or "/"


def _tri_state(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "present", "installed", "local"}:
        return True
    if text in {"0", "false", "no", "absent", "uninstalled"}:
        return False
    return None


def _scope(explicit=None, sid=None, name=None):
    if explicit:
        text = str(explicit).strip().lower()
        if text in {"machine", "computer", "localmachine", "system", "hklm", "all-users"}:
            return "machine"
        if text in {"user", "currentuser", "hkcu", "per-user"}:
            return "user"
    if sid and str(sid).upper() in MACHINE_SIDS:
        return "machine"
    if name and str(name).strip().lower() in {
        "machine",
        "localmachine",
        "system",
        "nt authority\\system",
        "s-1-5-18",
    }:
        return "machine"
    return "user" if sid or name else "machine"


def _clean_path(value):
    if value is None:
        return None
    text = str(value).strip()
    return text or None


class MsiExcerpt:
    """Normalized computer/user/product/feature/component MSI excerpt."""

    def __init__(self, data, source=None):
        self.data = data if isinstance(data, (dict, list)) else {}
        self.source = source
        self.source_path = str(source) if isinstance(source, (str, Path)) else None
        self.line_file = None
        self.products = []
        self.features = []
        self.components = []
        self._index()

    @classmethod
    def load(cls, source):
        if isinstance(source, MsiExcerpt):
            return source
        data, source_name = _load_structured(source)
        return cls(data, source=source_name)

    def _index(self):
        data = self.data
        if isinstance(data, list):
            if data and all(isinstance(row, dict) and _looks_flat_row(row) for row in data[:3]):
                for index, row in enumerate(data):
                    self._index_flat_row(row, line=index + 1)
                return
            data = {"computers": data}

        self.line_file = _ci_get(data, "line_file", "source_file", "registry_source")
        flat_rows = _ci_get(data, "rows", "records", "entries", "registration_lines")
        if flat_rows is not None:
            for row in _as_nodes(flat_rows):
                self._index_flat_row(row)
            return

        computer_nodes = _as_nodes(_ci_get(data, "computers", "computer", "machines", "hosts"))
        if not computer_nodes and (_ci_get(data, "users") is not None or _ci_get(data, "products") is not None):
            computer_nodes = [data]
        if not computer_nodes:
            computer_nodes = self._mapping_like_nodes(data, ("users", "products"))

        for computer_index, computer in enumerate(computer_nodes):
            self._index_computer(computer, computer_index)

    @staticmethod
    def _mapping_like_nodes(data, required_keys):
        nodes = []
        if not isinstance(data, dict):
            return nodes
        for key, value in data.items():
            if key.lower() in {"computers", "rows", "records", "entries"} or not isinstance(value, dict):
                continue
            if any(_ci_get(value, required) is not None for required in required_keys) or _ci_get(
                value, "name", "computer_name"
            ):
                node = dict(value)
                node.setdefault("_key", key)
                nodes.append(node)
        return nodes

    def _index_computer(self, computer, index):
        computer_name = _ci_get(
            computer, "name", "computer_name", "computer", "host", "hostname", "machine"
        ) or computer.get("_key", f"computer-{index + 1}")
        computer_line = _line_of(computer)
        computer_pointer = _pointer("/computers", index=index)

        user_nodes = _as_nodes(
            _ci_get(computer, "users", "user", "principals", "UserData", "user_data")
        )
        if not user_nodes and _ci_get(computer, "products") is not None:
            user_nodes = [computer]

        for user_index, user in enumerate(user_nodes):
            self._index_user(
                user,
                computer_name,
                computer_line,
                computer_pointer,
                user_index,
            )

    def _index_user(self, user, computer_name, computer_line, computer_pointer, index):
        user_name = _ci_get(user, "name", "user", "user_name", "username", "account")
        sid = _ci_get(user, "sid", "user_sid", "SID") or user.get("_key")
        explicit_scope = _ci_get(user, "scope", "level", "context", "installation_scope")
        scope = _scope(explicit_scope, sid, user_name)
        if scope == "machine" and not user_name:
            user_name = "MACHINE"
        user_line = _line_of(user)
        user_pointer = _pointer(computer_pointer + "/users", index=index)

        product_nodes = _as_nodes(_ci_get(user, "products", "product", "Products"))
        for product_index, product in enumerate(product_nodes):
            self._index_product(
                product,
                computer_name,
                computer_line,
                user_name,
                sid,
                scope,
                user_line,
                user_pointer,
                product_index,
            )

    def _base(self, computer_name, computer_line, user_name, sid, scope, user_line):
        return {
            "computer": computer_name,
            "computer_line": computer_line,
            "user": user_name,
            "sid": sid,
            "scope": scope,
            "user_line": user_line,
            "line_file": self.line_file,
        }

    def _index_product(
        self,
        product,
        computer_name,
        computer_line,
        user_name,
        sid,
        scope,
        user_line,
        user_pointer,
        index,
    ):
        base = self._base(computer_name, computer_line, user_name, sid, scope, user_line)
        raw_code = _ci_get(
            product,
            "product_code",
            "ProductCode",
            "code",
            "guid",
            "ProductCodeID",
            "compressed_product_code",
            "product",
        ) or product.get("_key")
        product_line = _line_of(product)
        product_pointer = _pointer(user_pointer + "/products", index=index)
        product_record = {
            **base,
            "product_code": canonical_guid(raw_code),
            "product_code_raw": raw_code,
            "product_line": product_line,
            "line": product_line,
            "pointer": product_pointer,
            "advertised": _tri_state(_ci_get(product, "advertised", "is_advertised")),
            "install_location": _clean_path(
                _ci_get(product, "install_location", "InstallLocation", "location")
            ),
        }
        self.products.append(product_record)

        feature_nodes = _as_nodes(_ci_get(product, "features", "feature", "Features"))
        for feature_index, feature in enumerate(feature_nodes):
            self._index_feature(feature, product_record, product_pointer, feature_index)

        direct_components = _as_nodes(
            _ci_get(product, "components", "component", "Components")
        )
        for component_index, component in enumerate(direct_components):
            self._index_component(
                component,
                product_record,
                None,
                product_pointer + "/components",
                component_index,
            )

    def _index_feature(self, feature, product_record, product_pointer, index):
        feature_name = _ci_get(
            feature, "name", "feature_name", "FeatureName", "Feature", "id", "key"
        ) or feature.get("_key")
        state = _ci_get(feature, "state", "install_state", "installation_state", "status")
        advertised = _tri_state(_ci_get(feature, "advertised", "is_advertised"))
        if advertised is None and state is not None:
            advertised = "advert" in str(state).lower()
        feature_line = _line_of(feature)
        feature_pointer = _pointer(product_pointer + "/features", index=index)
        feature_record = {
            **{key: product_record[key] for key in (
                "computer",
                "computer_line",
                "user",
                "sid",
                "scope",
                "user_line",
                "line_file",
                "product_code",
                "product_code_raw",
                "product_line",
            )},
            "feature_name": feature_name,
            "feature_line": feature_line,
            "state": state,
            "advertised": advertised,
            "component_codes": [],
            "installed_paths": [],
            "line": feature_line or product_record.get("product_line"),
            "pointer": feature_pointer,
        }
        self.features.append(feature_record)

        component_nodes = _as_nodes(
            _ci_get(feature, "components", "component", "Components", "component_codes")
        )
        for component_index, component in enumerate(component_nodes):
            record = self._index_component(
                component,
                product_record,
                feature_record,
                feature_pointer + "/components",
                component_index,
            )
            if record["component_code"]:
                feature_record["component_codes"].append(record["component_code"])
            if record["installed_path"]:
                feature_record["installed_paths"].append(record["installed_path"])

    def _index_component(self, component, product_record, feature_record, parent_pointer, index):
        if not isinstance(component, dict):
            component = {"component_code": component}
        raw_code = _ci_get(
            component,
            "component_code",
            "ComponentCode",
            "code",
            "guid",
            "ComponentId",
            "id",
            "compressed_component_code",
        ) or component.get("_key")
        path = _clean_path(
            _ci_get(
                component,
                "installed_path",
                "install_path",
                "key_path",
                "keypath",
                "KeyPath",
                "file_path",
                "local_path",
                "path",
            )
        )
        explicit_installed = _tri_state(
            _ci_get(component, "installed", "is_installed", "present", "exists")
        )
        installed = explicit_installed
        if installed is None and path:
            installed = True
        component_line = _line_of(component)
        component_record = {
            **{key: product_record[key] for key in (
                "computer",
                "computer_line",
                "user",
                "sid",
                "scope",
                "user_line",
                "line_file",
                "product_code",
                "product_code_raw",
                "product_line",
            )},
            "feature_name": (feature_record or {}).get("feature_name")
            or _ci_get(component, "feature_name", "feature"),
            "feature_line": (feature_record or {}).get("feature_line"),
            "component_code": canonical_guid(raw_code),
            "component_code_raw": raw_code,
            "component_line": component_line,
            "installed": installed,
            "installed_path": path if installed is not False else None,
            "key_path": path,
            "registry_key": _ci_get(component, "registry_key", "key", "reg_key"),
            "value_name": _ci_get(component, "value_name", "name"),
            "line": component_line
            or (feature_record or {}).get("feature_line")
            or product_record.get("product_line"),
            "pointer": _pointer(parent_pointer, index=index),
        }
        self.components.append(component_record)
        return component_record

    def _index_flat_row(self, row, line=None):
        if not isinstance(row, dict):
            return
        row = dict(row)
        if line is not None:
            row.setdefault("line", line)
        computer_name = _ci_get(row, "computer", "computer_name", "host", "hostname", "machine") or "*"
        sid = _ci_get(row, "sid", "user_sid", "SID")
        user_name = _ci_get(row, "user", "user_name", "username", "account", "principal")
        scope = _scope(_ci_get(row, "scope", "level", "context"), sid, user_name)
        base = {
            "computer": computer_name,
            "computer_line": _ci_get(row, "computer_line"),
            "user": user_name or ("MACHINE" if scope == "machine" else None),
            "sid": sid,
            "scope": scope,
            "user_line": _ci_get(row, "user_line"),
            "line_file": self.line_file or _ci_get(row, "line_file", "source_file"),
        }
        raw_product = _ci_get(row, "product_code", "ProductCode", "product", "guid")
        product_record = {
            **base,
            "product_code": canonical_guid(raw_product),
            "product_code_raw": raw_product,
            "product_line": _ci_get(row, "product_line") or _line_of(row),
            "line": _ci_get(row, "product_line") or _line_of(row),
            "pointer": _ci_get(row, "pointer") or "/rows",
            "advertised": _tri_state(_ci_get(row, "product_advertised", "advertised")),
            "install_location": _clean_path(_ci_get(row, "install_location")),
        }
        self.products.append(product_record)

        feature_name = _ci_get(row, "feature_name", "feature", "FeatureName")
        if feature_name is not None:
            feature_record = {
                **{key: product_record[key] for key in (
                    "computer", "computer_line", "user", "sid", "scope", "user_line",
                    "line_file", "product_code", "product_code_raw", "product_line",
                )},
                "feature_name": feature_name,
                "feature_line": _ci_get(row, "feature_line") or _line_of(row),
                "state": _ci_get(row, "feature_state", "state"),
                "advertised": _tri_state(_ci_get(row, "advertised"))
                if _ci_get(row, "advertised") is not None
                else "advert" in str(_ci_get(row, "feature_state", "state", default="")).lower(),
                "component_codes": [],
                "installed_paths": [],
                "line": _ci_get(row, "feature_line") or _line_of(row),
                "pointer": _ci_get(row, "pointer") or "/rows",
            }
            self.features.append(feature_record)
        else:
            feature_record = None

        raw_component = _ci_get(row, "component_code", "ComponentCode", "component")
        if raw_component is not None:
            component_record = self._index_component(
                row, product_record, feature_record, "/rows/components", 0
            )
            component_record["line"] = _line_of(row) or component_record["line"]
            if feature_record:
                feature_record["component_codes"].append(component_record["component_code"])
                if component_record["installed_path"]:
                    feature_record["installed_paths"].append(component_record["installed_path"])

    def locator_for(self, record):
        line = record.get("line") if isinstance(record, dict) else None
        line_file = record.get("line_file") if isinstance(record, dict) else None
        if line is not None and line_file:
            return f"{line_file}:{line}"
        if line is not None and self.source_path:
            return f"{self.source_path}#L{line}"
        if line is not None:
            return f"registration-line:{line}"
        pointer = record.get("pointer") if isinstance(record, dict) else None
        if pointer and self.source_path:
            return f"{self.source_path}#{pointer}"
        return pointer or self.source or "registration-excerpt"


def _looks_flat_row(row):
    return any(
        _ci_get(row, key) is not None
        for key in ("product_code", "ProductCode", "component_code", "feature_name")
    ) and not any(_ci_get(row, key) is not None for key in ("products", "users", "computers"))


def _load_structured(source):
    if isinstance(source, MsiExcerpt):
        return source.data, source.source
    if hasattr(source, "read"):
        text = source.read()
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        return _parse_text(text), getattr(source, "name", "<file>")
    if isinstance(source, bytes):
        return _parse_text(source.decode("utf-8")), None

    if isinstance(source, (str, Path)):
        path = Path(source)
        if path.exists():
            text = path.read_text(encoding="utf-8")
            return _parse_text(text, path.suffix.lower()), str(path)
        text = str(source).lstrip()
        if text[:1] in "{[":
            return _parse_text(str(source)), None
        raise FileNotFoundError(f"MSI registration excerpt not found: {source}")

    if isinstance(source, (dict, list)):
        return source, None
    raise TypeError(f"unsupported MSI excerpt source: {type(source)!r}")


def _parse_text(text, suffix=None):
    if suffix == ".jsonl":
        return {
            "rows": [json.loads(line) for line in text.splitlines() if line.strip()]
        }
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


def _principal_applies(record, user=None, sid=None):
    if not user and not sid:
        return None
    if record.get("scope") == "machine":
        return True
    record_sid = (record.get("sid") or "").lower()
    if sid and record_sid and record_sid == sid.lower():
        return True
    requested_user = str(user or "").lower()
    record_user = str(record.get("user") or "").lower()
    record_short_user = record_user.rsplit("\\", 1)[-1]
    requested_short_user = requested_user.rsplit("\\", 1)[-1]
    if requested_user and requested_user in {record_user, record_short_user}:
        return True
    return bool(requested_short_user and requested_short_user == record_short_user)


def _computer_applies(record, computer=None):
    if not computer:
        return True
    return str(record.get("computer") or "").lower() == str(computer).lower()


def _public_registration(record, excerpt, match_level, user, sid):
    keys = (
        "computer", "user", "sid", "scope", "product_code", "feature_name",
        "component_code", "installed", "installed_path", "key_path",
        "registry_key", "value_name", "state", "advertised", "line",
        "computer_line", "user_line", "product_line", "feature_line",
        "component_line", "pointer",
    )
    result = {key: record.get(key) for key in keys if key in record}
    result["match_level"] = match_level
    result["subject_applicable"] = _principal_applies(record, user, sid)
    result["locator"] = excerpt.locator_for(record)
    return result


def _feature_matches(feature_name, requested):
    if not requested:
        return True
    if not feature_name:
        return False
    return str(feature_name).lower() == str(requested).lower()


def find_claim_evidence(claim, excerpt, computer=None, user=None, sid=None):
    product_code = canonical_guid(claim.get("product_code_id"))
    component_code = canonical_guid(claim.get("component_id"))
    feature_name = claim.get("feature_name")

    products = []
    for record in excerpt.products:
        if product_code and record.get("product_code") != product_code:
            continue
        if not _computer_applies(record, computer):
            continue
        item = _public_registration(record, excerpt, "product", user, sid)
        products.append(item)

    features = []
    for record in excerpt.features:
        if product_code and record.get("product_code") != product_code:
            continue
        if not _computer_applies(record, computer):
            continue
        level = "feature" if _feature_matches(record.get("feature_name"), feature_name) else "related_feature"
        item = _public_registration(record, excerpt, level, user, sid)
        item["installed_paths"] = record.get("installed_paths", [])
        features.append(item)

    components = []
    for record in excerpt.components:
        if product_code and record.get("product_code") != product_code:
            continue
        if component_code and record.get("component_code") != component_code:
            continue
        if not _computer_applies(record, computer):
            continue
        feature_ok = _feature_matches(record.get("feature_name"), feature_name)
        level = "component" if feature_ok or not feature_name else "component_code_feature_mismatch"
        components.append(_public_registration(record, excerpt, level, user, sid))

    exact_features = [item for item in features if item["match_level"] == "feature"]
    exact_components = [
        item for item in components if item["match_level"] in {"component", "component_code_feature_mismatch"}
    ]
    if component_code:
        exact = exact_components
    elif feature_name:
        exact = exact_features
    else:
        exact = [item for item in products if item.get("advertised") is not False]

    return {
        "products": products,
        "features": features,
        "components": components,
        "exact": exact,
    }


def _applicable(items):
    return [item for item in items if item.get("subject_applicable") is not False]


def resolve_claim(claim, evidence):
    exact = evidence["exact"]
    applicable = _applicable(exact)
    paths = []
    for item in applicable:
        path = item.get("installed_path")
        if path and item.get("installed") is not False:
            paths.append(path)
    paths = list(dict.fromkeys(paths))

    result = {
        "classification": "no_matching_registration",
        "installed": False,
        "installed_paths": paths,
        "advertised_feature": False,
        "registration_locators": [item.get("locator") for item in applicable if item.get("locator")],
        "other_subject_locators": [
            item.get("locator") for item in exact if item.get("subject_applicable") is False
        ],
    }

    if paths:
        result["classification"] = "installed_component"
        result["installed"] = True
        return result

    if claim.get("has_component"):
        if applicable:
            result["classification"] = "component_registered_without_installed_path"
        elif exact:
            result["classification"] = "registered_to_other_subject"
        return result

    advertised = [
        item for item in applicable
        if item.get("match_level") == "feature" or item.get("advertised") is True
    ]
    if advertised:
        result["classification"] = "advertised_feature_only"
        result["advertised_feature"] = True
        return result

    if applicable:
        result["classification"] = "feature_or_product_registration_without_installed_path"
        result["advertised_feature"] = True
    elif exact:
        result["classification"] = "registered_to_other_subject"
    return result


def _coerce_lnk(source):
    if isinstance(source, LnkFile):
        return source, None
    if hasattr(source, "read"):
        data = source.read()
        return LnkFile(indata=data), getattr(source, "name", None)
    if isinstance(source, bytes):
        return LnkFile(indata=source), None
    if isinstance(source, (str, Path)):
        path = Path(source)
        return LnkFile(indata=path.read_bytes()), str(path)
    raise TypeError(f"unsupported LNK source: {type(source)!r}")


def _darwin_blocks(lnk):
    offset = getattr(lnk, "extra_data_offset", 0) or 0
    relative_offset = 0
    block_index = 0
    for extra in getattr(lnk.extras, "data", []):
        size = extra.size()
        if isinstance(extra, Darwin):
            block_offset = offset + relative_offset
            yield block_index, block_offset, extra
            block_index += 1
        relative_offset += size or 0


def verify_lnk_with_msi(lnk_source, excerpt_source, *, user=None, sid=None, computer=None):
    """Compare every ANSI/Unicode Darwin claim with a layered MSI excerpt."""
    lnk, detected_lnk_path = _coerce_lnk(lnk_source)
    lnk_path = detected_lnk_path or (str(lnk_source) if isinstance(lnk_source, (str, Path)) else None)
    excerpt = MsiExcerpt.load(excerpt_source)

    blocks = []
    findings = []
    for block_index, block_offset, darwin in _darwin_blocks(lnk):
        encodings = {}
        for encoding, field_name, field_start in (
            ("ansi", "DarwinDataAnsi", DARWIN_ANSI_START),
            ("unicode", "DarwinDataUnicode", DARWIN_UNICODE_START),
        ):
            claim = darwin.descriptor(encoding)
            evidence = find_claim_evidence(
                claim, excerpt, computer=computer, user=user, sid=sid
            )
            resolution = resolve_claim(claim, evidence)
            block_locator = f"{lnk_path or '<lnk-bytes>'}#offset=0x{block_offset:08x}"
            claim_result = {
                **claim,
                "encoding": encoding,
                "field": field_name,
                "decoder": "LnkParse3.utils.parse_packed_uuid",
                "source": {
                    "lnk_path": lnk_path,
                    "block_index": block_index,
                    "block_offset": block_offset,
                    "block_offset_hex": hex(block_offset),
                    "block_size": darwin.size(),
                    "block_signature": "0xA0000006",
                    "field": field_name,
                    "field_offset": block_offset + field_start,
                    "field_offset_hex": hex(block_offset + field_start),
                    "locator": block_locator + f"+{field_name}",
                },
                "evidence": evidence,
                "resolution": resolution,
            }
            encodings[encoding] = claim_result
            findings.append(_finding(block_index, claim_result))

        conflicts = _encoding_conflicts(encodings)
        blocks.append({
            "block_index": block_index,
            "offset": block_offset,
            "offset_hex": hex(block_offset),
            "size": darwin.size(),
            "signature": "0xA0000006",
            "locator": f"{lnk_path or '<lnk-bytes>'}#offset=0x{block_offset:08x}",
            "encodings": encodings,
            "conflicts": conflicts,
        })

    installed_paths = sorted({
        path
        for finding in findings
        if finding["classification"] == "installed_component"
        for path in finding["installed_paths"]
    })
    classifications = [finding["classification"] for finding in findings]
    has_conflict = any(block["conflicts"]["has_conflict"] for block in blocks)
    status = _overall_status(blocks, classifications, installed_paths, has_conflict)

    return {
        "schema": SCHEMA_VERSION,
        "status": status,
        "installed": bool(installed_paths),
        "installed_paths": installed_paths,
        "subject": {"user": user, "sid": sid, "computer": computer},
        "lnk": {
            "path": lnk_path,
            "size": len(lnk.indata),
            "darwin_block_count": len(blocks),
        },
        "excerpt": {
            "source": excerpt.source_path or excerpt.source,
            "computer_count": len({r["computer"] for r in excerpt.products}),
            "product_count": len(excerpt.products),
            "feature_count": len(excerpt.features),
            "component_count": len(excerpt.components),
        },
        "blocks": blocks,
        "findings": findings,
    }


def _finding(block_index, claim):
    resolution = claim["resolution"]
    return {
        "block_index": block_index,
        "encoding": claim["encoding"],
        "form": claim["form"],
        "form_number": claim["form_number"],
        "product_code_id": claim["product_code_id"],
        "feature_name": claim["feature_name"],
        "component_id": claim["component_id"],
        "classification": resolution["classification"],
        "installed": resolution["installed"],
        "installed_paths": resolution["installed_paths"],
        "advertised_feature": resolution["advertised_feature"],
        "block_locator": claim["source"]["locator"],
        "field_offset": claim["source"]["field_offset"],
        "registration_locators": resolution["registration_locators"],
        "other_subject_locators": resolution["other_subject_locators"],
    }


def _encoding_conflicts(encodings):
    ansi = encodings["ansi"]
    unicode_claim = encodings["unicode"]
    fields = ("product_code_id", "feature_name", "component_id", "form_number")
    conflicts = {}
    for field in fields:
        left = ansi.get(field)
        right = unicode_claim.get(field)
        conflicts[field] = left != right and not (left is None and right is None)
    conflicts["component_code"] = conflicts["component_id"]
    conflicts["has_conflict"] = any(
        conflicts[field] for field in ("product_code_id", "feature_name", "component_id")
    )
    return conflicts


def _overall_status(blocks, classifications, installed_paths, has_conflict):
    if not blocks:
        return "no_darwin_block"
    has_decode_error = any(
        claim.get("decode_error")
        for block in blocks
        for claim in block["encodings"].values()
    )
    if has_decode_error and (
        not classifications or all(c == "no_matching_registration" for c in classifications)
    ):
        return "decode_error"
    if has_conflict:
        return "conflicting_darwin_claims"
    if installed_paths:
        return "installed_component"
    if any(c == "advertised_feature_only" for c in classifications):
        return "advertised_feature_only"
    if any(c == "registered_to_other_subject" for c in classifications):
        return "registered_to_other_subject"
    if any(c != "no_matching_registration" for c in classifications):
        return "registration_found_without_installed_path"
    return "no_matching_registration"


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Offline LNK Darwin/MSI registration check")
    parser.add_argument("lnk", help="path to the .lnk file")
    parser.add_argument("excerpt", help="JSON/YAML layered MSI registration excerpt")
    parser.add_argument("--user")
    parser.add_argument("--sid")
    parser.add_argument("--computer")
    args = parser.parse_args(argv)
    result = verify_lnk_with_msi(
        args.lnk, args.excerpt, user=args.user, sid=args.sid, computer=args.computer
    )
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


check_with_msi = verify_lnk_with_msi
verify_offline = verify_lnk_with_msi
cross_check_msi = verify_lnk_with_msi
offline_check = verify_lnk_with_msi
check = verify_lnk_with_msi
verify = verify_lnk_with_msi
verify_lnk = verify_lnk_with_msi
verify_shortcut = verify_lnk_with_msi
check_shortcut = verify_lnk_with_msi
cross_check = cross_check_msi


__all__ = [
    "MsiExcerpt",
    "canonical_guid",
    "find_claim_evidence",
    "load_msi_excerpt",
    "verify_lnk_with_msi",
]


def load_msi_excerpt(source):
    return MsiExcerpt.load(source)


if __name__ == "__main__":
    main()
