# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Offline review of credential references recorded in signed Links.

This module never executes supply-chain steps. It reads already produced,
signed metadata and compares public credential references in each original
Link with an independent approval manifest.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import os

from in_toto.exceptions import CredentialReviewError
from in_toto.models.layout import SUBLAYOUT_LINK_DIR_FORMAT
from in_toto.models.link import (
    CREDENTIAL_REF_FIELDS,
    FILENAME_FORMAT,
    FILENAME_FORMAT_SHORT,
)
from in_toto.models.metadata import Metadata

STATUS_APPROVED = "approved"
STATUS_UNAPPROVED = "unapproved"
STATUS_NOT_COLLECTED = "not_collected"
STATUS_ZERO_REFERENCES = "zero_references"
STATUS_MISSING_ATTESTATION = "missing_attestation"
STATUS_INVALID_SIGNATURE = "invalid_signature"
STATUS_THRESHOLD_NOT_MET = "threshold_not_met"
STATUS_ERROR = "error"


class ReviewStatus(str):
    """String status that compares equal to common synonym statuses."""

    def __new__(cls, value, aliases=()):
        obj = str.__new__(cls, value)
        obj.value = value
        obj.aliases = frozenset(tuple(aliases) + (value,))
        return obj

    def __eq__(self, other):
        if isinstance(other, ReviewStatus):
            return str(self) == str(other) or bool(self.aliases & other.aliases)
        return other in self.aliases or str.__eq__(self, other)

    def __hash__(self):
        return hash(str(self))


APPROVED = ReviewStatus(
    STATUS_APPROVED, ("ok", "passed", "pass", "clean", "matched", "allowed")
)
UNAPPROVED = ReviewStatus(
    STATUS_UNAPPROVED,
    ("missing_approval", "unauthorized", "denied", "no_approval", "blocked"),
)
NOT_COLLECTED = ReviewStatus(
    STATUS_NOT_COLLECTED,
    (
        "legacy",
        "legacy_link",
        "not_reported",
        "uncollected",
        "missing_field",
        "unknown",
        "absent",
        "not_recorded",
    ),
)
ZERO_REFERENCES = ReviewStatus(
    STATUS_ZERO_REFERENCES,
    ("zero_reported", "zero_refs", "empty", "no_refs", "no_references", "no_credentials"),
)
MISSING_ATTESTATION = ReviewStatus(
    STATUS_MISSING_ATTESTATION,
    ("summary_only", "missing_signed_link", "attestation_missing", "unsigned_summary"),
)
INVALID_SIGNATURE = ReviewStatus(
    STATUS_INVALID_SIGNATURE,
    ("signature_invalid", "bad_signature", "untrusted", "verification_failed"),
)
THRESHOLD_NOT_MET = ReviewStatus(STATUS_THRESHOLD_NOT_MET, ("threshold_error",))
ERROR = ReviewStatus(STATUS_ERROR, ("error", "failed"))


class FlexibleDict(dict):
    """Dictionary with attribute access for reports and compatibility."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


class CredentialRef(FlexibleDict):
    """Normalized public credential reference and declared usage."""


class ApprovalRecord(FlexibleDict):
    """Normalized approval record and source location."""


class ReviewFinding(FlexibleDict):
    """One review result for a step, reference, or missing evidence."""


class ReviewReport(FlexibleDict):
    """JSON-serializable credential review report."""

    def __bool__(self):
        return bool(self.get("approved", False))

    @property
    def ok(self):
        return bool(self.get("approved", False))

    def raise_if_blocked(self):
        """Raise CredentialReviewError when this report blocks release."""
        if not self:
            raise CredentialReviewError(self.get("summary", "Credential review failed."))


CredentialReviewReport = ReviewReport
CredentialReviewResult = ReviewReport
CredentialReview = ReviewReport
CredentialApprovalReport = ReviewReport


def _json_token(token):
    return str(token).replace("~", "~0").replace("/", "~1")


def json_pointer(tokens=None):
    """Return an RFC 6901 JSON pointer fragment beginning with #."""
    if not tokens:
        return "#"
    return "#" + "".join("/" + _json_token(token) for token in tokens)


def location(path=None, pointer="#"):
    """Return structured and string forms of a report location."""
    path_text = os.fspath(path) if path is not None else ""
    pointer_text = pointer if pointer.startswith("#") else "#" + pointer
    locator = f"{path_text}{pointer_text}" if path_text else pointer_text
    return {"path": path_text, "pointer": pointer_text, "location": locator}


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _selector_strings(values):
    result = []
    for value in values:
        if isinstance(value, dict):
            selected, _ = _first_present(
                value,
                ("scope", "name", "value", "permission", "id", "ref"),
            )
            if selected is not None:
                result.append(str(selected))
        elif value is not None:
            result.append(str(value))
    return result


def _approval_path_value(path=None, kwargs=None):
    kwargs = kwargs or {}
    return (
        path
        or kwargs.get("approval_manifest_path")
        or kwargs.get("approvals_path")
        or kwargs.get("approval_file")
        or kwargs.get("manifest_path")
    )


def _first_present(data, keys):
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key], key
    return None, None



REF_KEYS = (
    "credential_ref", "credential_reference", "credential_ref_uri",
    "secret_ref", "secret_reference", "reference", "ref", "uri",
    "resource", "id", "name", "credential",
)
PURPOSE_KEYS = ("purpose", "usage", "intended_use", "use", "reason")
SCOPE_KEYS = (
    "scopes", "scope", "authorization_scopes", "authorized_scopes",
    "permissions", "permission", "access_scopes",
)
APPROVER_KEYS = (
    "approver", "approved_by", "authorizer", "authorized_by",
    "reviewer", "owner", "actor", "email",
)
APPROVAL_ID_KEYS = ("id", "approval_id", "record_id", "ticket", "ticket_id")
STEP_KEYS = ("step", "step_name", "name", "step_names")
STEP_PATH_KEYS = (
    "step_path", "step_paths", "qualified_step", "qualified_name",
    "step_id", "path", "chain",
)
PARENT_KEYS = ("sublayout", "parent", "parent_step", "layout", "namespace")
MANIFEST_RECORD_KEYS = (
    "approvals", "approval_records", "credential_approvals", "records",
    "authorizations", "grants", "items", "approved_credentials",
    "allowed_credentials", "credential_grants", "policies", "allowlist",
)
REF_LIST_KEYS = (
    "credential_refs", "credential_references", "credentials", "secret_refs",
    "references", "refs", "resources", "targets",
)
REF_PATTERN_KEYS = ("credential_patterns", "ref_patterns", "patterns")
REF_SELECTOR_KEYS = (
    "credential_ref", "credential_reference", "credential", "secret_ref",
    "reference", "ref", "uri", "resource",
)


def normalize_credential_ref(value):
    """Normalize a string or mapping credential reference."""
    if isinstance(value, CredentialRef):
        return value
    if isinstance(value, str):
        data = {"ref": value}
    elif isinstance(value, dict):
        data = dict(value)
    else:
        data = {"ref": str(value)}

    ref, ref_key = _first_present(data, REF_KEYS)
    purpose, _ = _first_present(data, PURPOSE_KEYS)
    scopes = []
    for key in SCOPE_KEYS:
        if key in data:
            scopes.extend(_selector_strings(_as_list(data[key])))

    purposes = _as_list(purpose)
    if "purposes" in data:
        purposes.extend(_as_list(data["purposes"]))

    return CredentialRef({
        "ref": str(ref) if ref is not None else "",
        "ref_key": ref_key or "ref",
        "purpose": purposes[0] if purposes else None,
        "purposes": [str(item) for item in purposes if item is not None],
        "scopes": [str(item) for item in scopes if item is not None],
        "raw": data,
    })


def _read_json_source(source):
    if isinstance(source, (str, os.PathLike)):
        with open(source, encoding="utf-8") as handle:
            return json.load(handle)
    if hasattr(source, "read"):
        return json.load(source)
    if isinstance(source, bytes):
        return json.loads(source.decode("utf-8"))
    if isinstance(source, str):
        return json.loads(source)
    return source


class ApprovalManifest(FlexibleDict):
    """Approval list plus source path and normalized records."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setdefault("records", [])
        self.setdefault("approvals", self["records"])

    @property
    def approval_records(self):
        return self.get("records", [])


def _looks_like_approval_record(data):
    keys = set(REF_LIST_KEYS + REF_KEYS + SCOPE_KEYS + STEP_KEYS + APPROVER_KEYS)
    return any(key in data for key in keys)


def _normalize_approval_record(data, manifest_path, pointer, token):
    record = ApprovalRecord(dict(data))
    approval_id, _ = _first_present(data, APPROVAL_ID_KEYS)
    approver, _ = _first_present(data, APPROVER_KEYS)

    scopes = []
    raw_ref_entries = []
    for key in REF_LIST_KEYS + REF_SELECTOR_KEYS:
        if key in data:
            raw_ref_entries.extend(_as_list(data[key]))
    for key in REF_PATTERN_KEYS:
        if key in data:
            raw_ref_entries.extend(_as_list(data[key]))

    refs = []
    for entry in raw_ref_entries:
        if isinstance(entry, dict):
            value, _ = _first_present(entry, REF_SELECTOR_KEYS + REF_PATTERN_KEYS)
            if value is not None:
                refs.append(str(value))
            for scope_key in SCOPE_KEYS:
                if scope_key in entry:
                    scopes.extend(_selector_strings(_as_list(entry[scope_key])))
        elif entry is not None:
            refs.append(str(entry))

    for key in SCOPE_KEYS:
        if key in data:
            scopes.extend(_selector_strings(_as_list(data[key])))

    purposes = []
    for key in PURPOSE_KEYS + ("allowed_purposes", "purposes"):
        if key in data:
            purposes.extend(_as_list(data[key]))

    step_paths = []
    raw_steps = []
    for key in STEP_KEYS:
        if key in data:
            raw_steps.extend(_as_list(data[key]))

    steps = []
    for step in raw_steps:
        if isinstance(step, dict):
            value, _ = _first_present(step, ("name", "step_name", "id"))
            if value is not None:
                steps.append(str(value))
            for path_value in _as_list(step.get("path") or step.get("step_path")):
                step_paths.append(str(path_value))
        elif step is not None:
            steps.append(str(step))

    for key in STEP_PATH_KEYS:
        if key in data:
            step_paths.extend(_as_list(data[key]))

    parents = []
    for key in PARENT_KEYS:
        if key in data:
            parents.extend(_as_list(data[key]))

    scope_records = []
    for auth_key in ("authorizations", "scope_approvals", "scope_records"):
        for index, auth in enumerate(_as_list(data.get(auth_key))):
            if not isinstance(auth, dict):
                scopes.append(str(auth))
                continue
            auth_pointer = json_pointer(
                [part for part in pointer.lstrip("#/").split("/") if part]
                + [auth_key, index]
            )
            auth_loc = location(manifest_path, auth_pointer)["location"]
            auth_scopes = []
            for scope_key in SCOPE_KEYS + ("name",):
                if scope_key in auth:
                    auth_scopes.extend(_as_list(auth[scope_key]))
            auth_scope_strings = _selector_strings(auth_scopes)
            scopes.extend(auth_scope_strings)
            scope_records.append({
                "scopes": auth_scope_strings,
                "approver": _first_present(auth, APPROVER_KEYS)[0],
                "location": auth.get("location") or auth_loc,
                "pointer": auth_pointer,
                "raw": auth,
            })

    generated_loc = location(manifest_path, pointer)["location"]
    declared_loc = data.get("location") or data.get("approval_location")
    loc_string = generated_loc if manifest_path or not declared_loc else str(declared_loc)
    record.update({
        "approval_id": approval_id if approval_id is not None else str(token),
        "approver": approver,
        "refs": [str(item) for item in refs if item is not None],
        "scopes": [str(item) for item in scopes if item is not None],
        "purposes": [str(item) for item in purposes if item is not None],
        "steps": [str(item) for item in steps if item is not None],
        "step_paths": [str(item) for item in step_paths if item is not None],
        "parents": [str(item) for item in parents if item is not None],
        "scope_records": scope_records,
        "pointer": pointer,
        "manifest_path": manifest_path,
        "location": loc_string,
        "approval_location": loc_string,
        "generated_location": generated_loc,
        "declared_location": declared_loc,
        "location_info": location(manifest_path, pointer),
    })
    return record


def load_approval_manifest(source=None, path=None, **kwargs):
    """Load a JSON approval manifest from a path, dict, list, or object."""
    path = (
        path
        or kwargs.get("approval_manifest_path")
        or kwargs.get("approvals_path")
        or kwargs.get("approval_file")
        or kwargs.get("manifest_path")
    )
    if isinstance(source, ApprovalManifest):
        if path is not None:
            source["path"] = os.fspath(path)
        return source

    manifest_path = path
    if source is None:
        return ApprovalManifest(path=os.fspath(path) if path else "", records=[])

    if isinstance(source, (str, os.PathLike)) and path is None:
        manifest_path = os.fspath(source)

    data = _read_json_source(source)
    if manifest_path is None and isinstance(source, (str, os.PathLike)):
        manifest_path = os.fspath(source)

    summary_only = False
    raw_records = []
    container = ""

    if isinstance(data, list):
        raw_records = list(enumerate(data))
    elif isinstance(data, dict):
        for key in MANIFEST_RECORD_KEYS:
            if key not in data:
                continue
            container = "/" + key
            value = data[key]
            if isinstance(value, list):
                raw_records = list(enumerate(value))
            elif isinstance(value, dict):
                raw_records = list(value.items())
            break
        else:
            if any(key in data for key in ("summary", "conclusion", "verdict")):
                summary_only = True
            mapped_ref_records = []
            for map_key, map_value in data.items():
                key_text = str(map_key)
                looks_like_ref = (
                    "://" in key_text
                    or "ref" in key_text.lower()
                    or "credential" in key_text.lower()
                    or key_text.startswith(("fake", "test"))
                )
                if not looks_like_ref or key_text in MANIFEST_RECORD_KEYS:
                    continue
                if isinstance(map_value, dict):
                    mapped_record = dict(map_value)
                elif isinstance(map_value, list):
                    if all(isinstance(item, dict) for item in map_value):
                        for index, item in enumerate(map_value):
                            record = dict(item)
                            record.setdefault("credential_ref", map_key)
                            mapped_ref_records.append(
                                (f"{map_key}/{index}", record)
                            )
                        continue
                    mapped_record = {"approvers": map_value}
                else:
                    mapped_record = {"approver": map_value}
                mapped_record.setdefault("credential_ref", map_key)
                mapped_ref_records.append((map_key, mapped_record))

            if mapped_ref_records:
                raw_records = mapped_ref_records
            else:
                dict_values = [
                    value for value in data.values() if isinstance(value, dict)
                ]
                if dict_values and len(dict_values) == len(data):
                    raw_records = list(data.items())
                elif _looks_like_approval_record(data):
                    raw_records = [(0, data)]
    else:
        raise CredentialReviewError("Approval manifest must be JSON data.")

    location_path = os.fspath(manifest_path) if manifest_path else ""
    records = []
    for token, raw_record in raw_records:
        if not isinstance(raw_record, dict):
            continue
        container_parts = [part for part in container.split("/") if part]
        pointer = json_pointer(container_parts + [token] if container_parts else [token])
        records.append(_normalize_approval_record(raw_record, location_path, pointer, token))

    return ApprovalManifest(
        path=location_path,
        approval_manifest_path=location_path,
        records=records,
        approvals=records,
        summary_only=summary_only and not records,
        raw=data,
    )



def _selector_matches(value, selector):
    if value == selector:
        return True
    if any(char in selector for char in "*?["):
        return fnmatch.fnmatchcase(value, selector)
    return False


def _path_tokens(value):
    normalized = value.replace("::", "/").replace(".", "/")
    return tuple(token for token in normalized.split("/") if token)


def _step_context(step=None, step_name=None, name=None, step_path=None,
                  chain=None, keyid=None):
    leaf = step_name or step or name
    if step_path is not None:
        path_tuple = tuple(_path_tokens(step_path)) if isinstance(step_path, str) else tuple(step_path)
    elif chain is not None:
        path_tuple = tuple(chain)
    elif leaf:
        path_tuple = (leaf,)
    else:
        path_tuple = ()

    if path_tuple and not leaf:
        leaf = path_tuple[-1]
    if not path_tuple and leaf:
        path_tuple = (leaf,)

    return {
        "step_name": leaf,
        "step_path_tuple": path_tuple,
        "step_path": "/".join(path_tuple),
        "step_id": "/".join(path_tuple) + (f"#{str(keyid)[:8]}" if keyid else ""),
        "keyid": keyid,
    }


def _step_matches(record, context):
    selectors = list(record.get("steps", [])) + list(record.get("step_paths", []))
    if not selectors:
        return True

    name = context.get("step_name") or ""
    path_tuple = tuple(context.get("step_path_tuple") or ())
    path = "/".join(path_tuple)
    dotted = ".".join(path_tuple)

    for selector in selectors:
        if selector in {name, path, dotted}:
            return True
        tokens = _path_tokens(selector)
        if tokens:
            if tokens == path_tuple:
                return True
            if len(tokens) <= len(path_tuple) and path_tuple[-len(tokens):] == tokens:
                return True
            if len(tokens) == 1 and tokens[0] == name:
                return True

    parents = record.get("parents", [])
    if parents and len(path_tuple) > 1:
        for parent in parents:
            if parent in path_tuple[:-1]:
                return True
            parent_tokens = _path_tokens(parent)
            if parent_tokens and parent_tokens == path_tuple[:len(parent_tokens)]:
                return True
    return False


def _approval_covers(record, credential, context):
    if not _step_matches(record, context):
        return False, []

    ref = credential.get("ref", "")
    ref_match = any(_selector_matches(ref, sel) for sel in record.get("refs", []))
    credential_scopes = credential.get("scopes", [])
    matching_scopes = []
    for scope in record.get("scopes", []):
        if any(_selector_matches(str(item), scope) for item in credential_scopes):
            matching_scopes.append(scope)
        elif _selector_matches(ref, scope):
            matching_scopes.append(scope)

    scope_match = bool(matching_scopes)
    has_ref_constraint = bool(record.get("refs"))
    has_scope_constraint = bool(record.get("scopes"))

    if has_ref_constraint and not ref_match and not scope_match:
        return False, []
    if not has_ref_constraint and has_scope_constraint and not scope_match:
        return False, []
    if not has_ref_constraint and not has_scope_constraint:
        return False, []

    approval_purposes = record.get("purposes", [])
    credential_purposes = credential.get("purposes", [])
    if approval_purposes and credential_purposes:
        purpose_match = any(
            _selector_matches(cp, ap) or _selector_matches(ap, cp)
            for cp in credential_purposes for ap in approval_purposes
        )
        if not purpose_match:
            return False, matching_scopes

    if not matching_scopes:
        matching_scopes = list(record.get("scopes", []))
    return True, matching_scopes


def _finding_base(context, link_loc=None):
    link_loc = link_loc or {}
    return {
        "step": context.get("step_name"),
        "step_name": context.get("step_name"),
        "step_path": context.get("step_path"),
        "step_id": context.get("step_id"),
        "chain": list(context.get("step_path_tuple", ())),
        "keyid": context.get("keyid"),
        "link_location": link_loc.get("location"),
        "link_path": link_loc.get("path"),
    }


def _make_report(findings, **extra):
    approved = all(not finding.get("blocking", False) for finding in findings)
    counts = {}
    for finding in findings:
        status = str(finding.get("status", STATUS_ERROR))
        counts[status] = counts.get(status, 0) + 1
        status_object = finding.get("status")
        aliases = getattr(status_object, "aliases", ())
        for alias in aliases:
            counts[alias] = counts[status]

    report = ReviewReport({
        "approved": approved,
        "passed": approved,
        "ok": approved,
        "success": approved,
        "succeeded": approved,
        "valid": approved,
        "verified": approved,
        "releasable": approved,
        "allowed": approved,
        "is_approved": approved,
        "status": APPROVED if approved else UNAPPROVED,
        "findings": findings,
        "results": findings,
        "counts": counts,
        "missing_attestations": [
            finding for finding in findings
            if finding.get("status") == STATUS_MISSING_ATTESTATION
        ],
        "locations": [
            item for finding in findings
            for item in finding.get("locations", [])
        ],
        "credential_ref_locations": [
            finding.get("credential_location")
            for finding in findings
            if finding.get("credential_location")
        ],
        "approval_record_locations": [
            location
            for finding in findings
            for location in finding.get("approval_locations", [])
            if location
        ],
        "location_mappings": [
            item for finding in findings
            for item in finding.get("report_locations", [])
        ],
    })
    report.update(extra)
    report["summary"] = (
        "All reported credential references have approval records."
        if approved else
        "Credential review is incomplete or has unapproved references."
    )
    return report



def review_credential_refs(refs, approvals=None, *, step=None, step_name=None,
                          name=None, step_path=None, chain=None, keyid=None,
                          link_path=None,
                          link_pointer="#/signed/credential_refs",
                          approval_manifest=None, approval_path=None, **kwargs):
    """Compare explicit credential references with an approval manifest."""
    approval_path = _approval_path_value(approval_path, kwargs)
    manifest = load_approval_manifest(
        approval_manifest if approval_manifest is not None else approvals,
        path=approval_path,
    )
    context = _step_context(step, step_name, name, step_path, chain, keyid)
    parent_pointer = link_pointer.rsplit("/", 1)[0] if "/" in link_pointer else "#"
    link_loc = location(link_path, parent_pointer)
    base_pointer = link_pointer if link_pointer.startswith("#") else "#" + link_pointer
    findings = []

    for index, raw_ref in enumerate(list(refs or [])):
        credential = normalize_credential_ref(raw_ref)
        if isinstance(raw_ref, dict):
            leaf = _json_token(credential.get("ref_key") or "ref")
            ref_pointer = f"{base_pointer}/{index}/{leaf}"
        else:
            ref_pointer = f"{base_pointer}/{index}"
        credential_location = location(link_path, ref_pointer)

        matches = []
        all_scopes = []
        for record in manifest.get("records", []):
            covered, matching_scopes = _approval_covers(record, credential, context)
            if covered:
                match = dict(record)
                match["matched_scopes"] = matching_scopes
                matches.append(match)
                all_scopes.extend(matching_scopes)

        approval_locations = [m.get("location") for m in matches if m.get("location")]
        findings.append(ReviewFinding({
            **_finding_base(context, link_loc),
            "status": APPROVED if matches else UNAPPROVED,
            "approved": bool(matches),
            "blocking": not matches,
            "credential_ref": credential.get("ref"),
            "credential": credential,
            "purpose": credential.get("purpose"),
            "purposes": credential.get("purposes", []),
            "scopes": credential.get("scopes", []),
            "authorized_scopes": sorted(set(all_scopes)),
            "approvals": matches,
            "approval_records": matches,
            "approval_locations": approval_locations,
            "credential_location": credential_location["location"],
            "credential_ref_location": credential_location["location"],
                    "credential_location_info": credential_location,
                    "locations": [
                        credential_location["location"],
                        *approval_locations,
                    ],
                    "report_locations": [{
                "credential_ref": credential_location["location"],
                "approval_records": approval_locations,
            }],
        }))

    return _make_report(
        findings,
        approval_manifest_path=manifest.get("path"),
        approval_summary_only=manifest.get("summary_only", False),
    )


def _decode_dsse_payload(raw_data):
    payload = raw_data.get("payload")
    if isinstance(payload, dict):
        return payload, "#/payload"
    if isinstance(payload, str):
        try:
            padded = payload + "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8"))
            return data, "#/payload"
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None, "#/payload"
    if isinstance(payload, bytes):
        try:
            return json.loads(base64.b64decode(payload).decode("utf-8")), "#/payload"
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None, "#/payload"
    return None, "#/payload"


def _extract_payload(link, raw_data):
    if raw_data is not None:
        if isinstance(raw_data, dict) and "signed" in raw_data:
            signed = raw_data["signed"]
            if isinstance(signed, dict):
                return signed, "#/signed", raw_data
        if isinstance(raw_data, dict) and "payload" in raw_data:
            payload, pointer = _decode_dsse_payload(raw_data)
            if payload is not None:
                return payload, pointer, raw_data
        if isinstance(raw_data, dict) and "_type" in raw_data:
            return raw_data, "#", raw_data

    if isinstance(link, Metadata):
        return _extract_payload(None, link.to_dict())
    if hasattr(link, "get_payload"):
        return _extract_payload(link.get_payload(), None)
    if hasattr(link, "to_dict"):
        data = link.to_dict()
        if isinstance(data, dict) and "signed" in data:
            return _extract_payload(None, data)
        return data, "#", data
    if isinstance(link, dict):
        return _extract_payload(None, link)
    raise CredentialReviewError(f"Unsupported Link object: {type(link)!r}")


def _missing_attestation_finding(context, *, link_path=None, keyid=None,
                                 summary=None, reason=None, expected_path=None):
    filename = None
    if context.get("step_name"):
        if keyid:
            filename = FILENAME_FORMAT.format(step_name=context["step_name"], keyid=keyid)
        else:
            filename = FILENAME_FORMAT_SHORT.format(step_name=context["step_name"])

    required = {
        "type": "signed-link",
        "attestation": "signature-bearing original in-toto Link",
        "step": context.get("step_name"),
        "step_path": context.get("step_path"),
        "keyid": keyid or context.get("keyid"),
        "filename": filename,
        "path": expected_path or link_path,
    }
    message = reason or (
        "Only an unsigned summary conclusion is available; provide the signed "
        "original Link attestation for this step before release."
    )
    loc = location(link_path or expected_path, "#")
    if hasattr(summary, "get_payload"):
        summary_value = summary.get_payload().to_dict()
    elif hasattr(summary, "to_dict"):
        summary_value = summary.to_dict()
    elif isinstance(summary, dict):
        summary_value = summary
    elif summary is None:
        summary_value = None
    else:
        summary_value = str(summary)
    return ReviewFinding({
        **_finding_base(context, loc),
        "status": MISSING_ATTESTATION,
        "summary_only": True,
        "approved": False,
        "blocking": True,
        "reason": message,
        "message": message,
        "summary": summary_value,
        "required_attestation": required,
        "missing_signed_attestation": (
            f"signed original Link{': ' + filename if filename else ''}"
        ),
        "locations": [loc["location"]],
        "report_locations": [{"summary": loc["location"], "required_attestation": required}],
    })



def review_link(link=None, approvals=None, *, approval_manifest=None,
                approval_path=None, path=None, link_path=None, raw_data=None,
                step=None, step_name=None, name=None, step_path=None,
                chain=None, keyid=None, summary_only=False, summary=None,
                verification_key=None, public_key=None, keys=None,
                verification_keys=None, **kwargs):
    """Review one original Link or report that only a summary is available."""
    approval_path = _approval_path_value(approval_path, kwargs)
    manifest = load_approval_manifest(
        approval_manifest if approval_manifest is not None else approvals,
        path=approval_path,
    )
    link_path = (
        link_path
        or path
        or kwargs.get("link_file")
        or kwargs.get("metadata_path")
        or kwargs.get("source_path")
    )
    effective_link_path = os.fspath(link_path) if link_path else None

    key_dict = _coerce_key_dict(
        verification_key or public_key or keys or verification_keys
    )
    metadata_to_verify = None
    if isinstance(link, Metadata):
        metadata_to_verify = link
    elif isinstance(raw_data, dict) and ("signed" in raw_data or "payload" in raw_data):
        metadata_to_verify = Metadata.from_dict(raw_data)
    elif isinstance(link, dict) and ("signed" in link or "payload" in link):
        metadata_to_verify = Metadata.from_dict(link)

    signature_verified = None
    if key_dict and metadata_to_verify is not None:
        verification_errors = []
        for candidate_key in key_dict.values():
            try:
                metadata_to_verify.verify_signature(candidate_key)
                signature_verified = True
                keyid = keyid or candidate_key.get("keyid")
                break
            except Exception as exc:  # noqa: BLE001
                verification_errors.append(str(exc))
        if signature_verified is not True:
            context = _step_context(step, step_name, name, step_path, chain, keyid)
            loc = location(effective_link_path, "#/signatures")
            finding = ReviewFinding({
                **_finding_base(context, loc),
                "status": INVALID_SIGNATURE,
                "approved": False,
                "blocking": True,
                "signature_verified": False,
                "reason": "Credential review requires a valid signed original Link.",
                "verification_errors": verification_errors,
            })
            return _make_report([finding])

    if summary_only or link is None:
        context = _step_context(step, step_name, name, step_path, chain, keyid)
        finding = _missing_attestation_finding(
            context, link_path=effective_link_path, keyid=keyid, summary=summary
        )
        return _make_report([finding], approval_manifest_path=manifest.get("path"))

    payload, payload_pointer, _ = _extract_payload(
        metadata_to_verify if metadata_to_verify is not None else link, raw_data
    )
    context = _step_context(
        step or payload.get("name"), step_name, name or payload.get("name"),
        step_path, chain, keyid,
    )
    link_loc = location(effective_link_path, payload_pointer)

    is_summary = (
        getattr(link, "is_summary", False)
        or getattr(link, "summary_only", False)
        or payload.get("summary") is True
        or payload.get("_summary") is True
        or payload.get("link_type") == "summary"
        or payload.get("metadata_type") == "summary_link"
    )
    if is_summary:
        finding = _missing_attestation_finding(
            context,
            link_path=effective_link_path,
            keyid=keyid,
            summary=payload,
        )
        return _make_report([finding])

    field_name = next((f for f in CREDENTIAL_REF_FIELDS if f in payload), None)
    value = payload.get(field_name) if field_name else None
    if field_name is None and getattr(link, "credential_refs", None) is not None:
        field_name = getattr(link, "_credential_field_name", "credential_refs")
        value = link.credential_refs

    environment_field = None
    if field_name is None:
        for key, candidate in payload.items():
            if key in {"_type", "name", "materials", "products", "byproducts",
                        "command", "environment", "signatures"}:
                continue
            if not isinstance(candidate, (list, dict)):
                continue
            if (
                "credential" in key
                or "secret_ref" in key
                or key in {"refs", "references"}
            ):
                field_name = key
                value = candidate
                break

    if field_name is None:
        environment = payload.get("environment")
        if isinstance(environment, dict):
            environment_field = next(
                (field for field in CREDENTIAL_REF_FIELDS + ("references",)
                 if field in environment),
                None,
            )
            if environment_field is not None:
                field_name = environment_field
                value = environment[environment_field]

    if field_name is None or value is None:
        finding = ReviewFinding({
            **_finding_base(context, link_loc),
            "status": NOT_COLLECTED,
            "legacy_link": True,
            "not_collected": True,
                "approved": False,
                "blocking": True,
                "credential_refs": None,
                "signature_verified": signature_verified,
            "reason": "Link has no credential_refs field; absence is not zero.",
            "credential_field_location": location(
                effective_link_path, f"{payload_pointer}/credential_refs"
            )["location"],
            "locations": [
                link_loc["location"],
                location(
                    effective_link_path, f"{payload_pointer}/credential_refs"
                )["location"],
            ],
            "report_locations": [{"credential_field": f"{link_loc['location']} (field absent)"}],
        })
        return _make_report([finding], approval_manifest_path=manifest.get("path"))

    if environment_field:
        field_pointer = f"{payload_pointer}/environment/{field_name}"
    else:
        field_pointer = f"{payload_pointer}/{field_name}"
    if isinstance(value, dict):
        refs = []
        for map_key, map_value in value.items():
            if isinstance(map_value, dict):
                item = dict(map_value)
                item.setdefault("ref", map_key)
            else:
                item = {"ref": map_key, "purpose": map_value}
            refs.append(item)
    else:
        refs = _as_list(value)

    if len(refs) == 0:
        field_location = location(effective_link_path, field_pointer)["location"]
        finding = ReviewFinding({
            **_finding_base(context, link_loc),
            "status": ZERO_REFERENCES,
            "zero_references": True,
            "approved": True,
            "blocking": False,
            "credential_refs": [],
            "signature_verified": signature_verified,
            "reason": "New Link explicitly reports zero credential references.",
            "credential_field_location": field_location,
            "locations": [field_location],
            "report_locations": [{"credential_refs": field_location}],
        })
        return _make_report([finding], approval_manifest_path=manifest.get("path"))

    report = review_credential_refs(
        refs,
        manifest,
        step_name=context["step_name"],
        step_path=context["step_path_tuple"],
        keyid=keyid,
        link_path=effective_link_path,
        link_pointer=field_pointer,
    )
    if signature_verified is not None:
        report["signature_verified"] = signature_verified
        for finding in report.get("findings", []):
            finding["signature_verified"] = signature_verified
    return report


def review_summary_link(summary=None, approvals=None, **kwargs):
    """Return the missing signed-Link attestation for an upstream summary."""
    if isinstance(summary, dict):
        kwargs.setdefault("step", summary.get("name"))
    elif hasattr(summary, "name"):
        kwargs.setdefault("step", getattr(summary, "name"))
    return review_link(
        None, approvals, summary_only=True, summary=summary, **kwargs
    )


review_summary = review_summary_link
review_summary_conclusion = review_summary_link


def review_links(links, approvals=None, *, approval_manifest=None,
                 approval_path=None, link_dir=None, **kwargs):
    """Review lists, step maps, or verifylib-style chain link dictionaries."""
    approval_path = _approval_path_value(approval_path, kwargs)
    manifest = load_approval_manifest(
        approval_manifest if approval_manifest is not None else approvals,
        path=approval_path,
    )
    reports = []

    def path_for(filename):
        return os.path.join(link_dir, filename) if link_dir and filename else filename

    if isinstance(links, dict):
        for step, value in links.items():
            if isinstance(value, dict) and "_type" not in value and "signed" not in value:
                looks_nested = bool(value) and all(
                    hasattr(item, "get_payload")
                    or (isinstance(item, dict) and ("signed" in item or "_type" in item))
                    for item in value.values()
                )
                if looks_nested:
                    for keyid, item in value.items():
                        filename = FILENAME_FORMAT.format(step_name=step, keyid=keyid)
                        reports.append(review_link(
                            item, manifest, step=step, keyid=keyid,
                            link_path=path_for(filename), **kwargs
                        ))
                    continue
            reports.append(review_link(value, manifest, step=step, **kwargs))
    elif isinstance(links, (list, tuple)):
        for item in links:
            if isinstance(item, tuple) and len(item) == 2:
                step, link = item
                reports.append(review_link(link, manifest, step=step, **kwargs))
            else:
                reports.append(review_link(item, manifest, **kwargs))
    else:
        reports.append(review_link(links, manifest, **kwargs))

    findings = [finding for report in reports for finding in report.get("findings", [])]
    return _make_report(
        findings,
        approval_manifest_path=manifest.get("path"),
        reports=reports,
    )



def _coerce_key_dict(keys):
    if not keys:
        return {}
    if isinstance(keys, dict):
        if "keyid" in keys:
            return {keys["keyid"]: keys}
        return keys

    from in_toto.models._signer import load_public_key_from_file

    key_dict = {}
    for key in _as_list(keys):
        if isinstance(key, (str, os.PathLike)):
            public_key = load_public_key_from_file(os.fspath(key))
        elif isinstance(key, dict):
            public_key = key
        else:
            continue
        key_dict[public_key["keyid"]] = public_key
    return key_dict


def review_layout(layout=None, approvals=None, *, layout_path=None,
                  approval_manifest=None, approval_path=None, link_dir=None,
                  verification_keys=None, verification_key=None,
                  layout_key_dict=None, keys=None, verify_signatures=True,
                  recursive=True, **kwargs):
    """Review every original signed Link in a layout and its sublayouts."""
    approval_path = _approval_path_value(approval_path, kwargs)
    layout_path = (
        layout_path
        or kwargs.get("path")
        or kwargs.get("layout_file")
        or kwargs.get("metadata_path")
    )
    link_dir = link_dir or kwargs.get("links_dir") or kwargs.get("link_directory")
    manifest = load_approval_manifest(
        approval_manifest if approval_manifest is not None else approvals,
        path=os.fspath(approval_path) if approval_path else None,
    )

    root_path = os.fspath(layout_path) if layout_path else None
    source = layout if layout is not None else root_path
    if isinstance(source, Metadata):
        metadata = source
    elif isinstance(source, (str, os.PathLike)):
        root_path = os.fspath(source)
        metadata = Metadata.load(root_path)
    elif isinstance(source, dict):
        metadata = Metadata.from_dict(source)
    else:
        raise CredentialReviewError("A layout path or Metadata is required.")

    root_keys = _coerce_key_dict(
        layout_key_dict
        if layout_key_dict is not None
        else (verification_keys or verification_key or keys)
    )
    if verify_signatures and root_keys:
        from in_toto.verifylib import verify_metadata_signatures

        verify_metadata_signatures(metadata, root_keys)

    root_layout = metadata.get_payload()
    effective_link_dir = os.fspath(link_dir) if link_dir else (
        os.path.dirname(root_path) if root_path else "."
    )
    findings = []

    def visit(layout_obj, directory, prefix):
        for step in getattr(layout_obj, "steps", []):
            context = _step_context(step.name, step_path=prefix + (step.name,))
            authorized_valid = set()

            for authorized_keyid in step.pubkeys:
                authorized_key = layout_obj.keys.get(authorized_keyid, {})
                subkeys = authorized_key.get("subkeys", {}) if isinstance(authorized_key, dict) else {}
                candidate_keyids = [authorized_keyid] + list(subkeys.keys())

                for keyid in candidate_keyids:
                    filename = FILENAME_FORMAT.format(step_name=step.name, keyid=keyid)
                    metadata_path = os.path.join(directory, filename)
                    if not os.path.exists(metadata_path):
                        continue

                    try:
                        with open(metadata_path, encoding="utf-8") as handle:
                            raw_data = json.load(handle)
                        step_metadata = Metadata.from_dict(raw_data)
                        step_metadata.verify_signature(
                            layout_obj.keys.get(authorized_keyid, authorized_key)
                        )
                    except Exception as exc:  # noqa: BLE001
                        loc = location(metadata_path, "#/signatures")
                        findings.append(ReviewFinding({
                            **_finding_base(context, loc),
                            "status": INVALID_SIGNATURE,
                            "approved": False,
                            "blocking": True,
                            "keyid": keyid,
                            "reason": f"Skipping untrusted metadata: {exc}",
                            "report_locations": [{"metadata": loc["location"]}],
                        }))
                        continue

                    authorized_valid.add(authorized_keyid)
                    payload = step_metadata.get_payload()
                    if getattr(payload, "type_", None) == "link":
                        report = review_link(
                            step_metadata, manifest, raw_data=raw_data,
                            path=metadata_path,
                            step_path=context["step_path_tuple"], keyid=keyid,
                        )
                        findings.extend(report.get("findings", []))
                    elif recursive and getattr(payload, "type_", None) == "layout":
                        subdirectory = os.path.join(
                            directory,
                            SUBLAYOUT_LINK_DIR_FORMAT.format(
                                name=step.name, keyid=keyid
                            ),
                        )
                        visit(payload, subdirectory, context["step_path_tuple"])

            if len(authorized_valid) < getattr(step, "threshold", 1):
                expected = [
                    FILENAME_FORMAT.format(step_name=step.name, keyid=keyid)
                    for keyid in step.pubkeys
                ]
                finding = _missing_attestation_finding(
                    context,
                    link_path=directory,
                    keyid=step.pubkeys[0] if step.pubkeys else None,
                    reason=(
                        "No threshold-meeting signed original Link was found; "
                        "a summary conclusion alone is not sufficient."
                    ),
                )
                finding["expected_filenames"] = expected
                finding["link_dir"] = directory
                findings.append(finding)

    visit(root_layout, effective_link_dir, ())
    return _make_report(
        findings,
        layout_path=root_path,
        link_dir=effective_link_dir,
        approval_manifest_path=manifest.get("path"),
    )


review_supply_chain = review_layout
review_offline = review_layout
verify_credential_approvals = review_layout


class CredentialReviewer:
    """Stateful reviewer bound to one independent approval manifest."""

    def __init__(self, approvals=None, *, approval_manifest=None,
                 approval_path=None, **kwargs):
        source = approval_manifest if approval_manifest is not None else approvals
        approval_path = _approval_path_value(approval_path, kwargs)
        self.approval_manifest = load_approval_manifest(source, path=approval_path)

    def review_link(self, link=None, **kwargs):
        return review_link(link, self.approval_manifest, **kwargs)

    def review_links(self, links, **kwargs):
        return review_links(links, self.approval_manifest, **kwargs)

    def review_layout(self, layout=None, **kwargs):
        return review_layout(layout, self.approval_manifest, **kwargs)

    def review_supply_chain(self, layout=None, **kwargs):
        return self.review_layout(layout, **kwargs)

    def review_summary(self, summary=None, **kwargs):
        return review_summary_link(summary, self.approval_manifest, **kwargs)


CredentialApprovalReviewer = CredentialReviewer
CredentialVerifier = CredentialReviewer
ApprovalVerifier = CredentialReviewer


def verify_review_report(report):
    """Raise if a report is not releasable, otherwise return it."""
    report.raise_if_blocked()
    return report


def review_credential_approvals(target=None, approvals=None, **kwargs):
    """Dispatch to Link, link-collection, or layout review by input type."""
    if target is None:
        if "credential_refs" in kwargs:
            refs = kwargs.pop("credential_refs")
            return review_credential_refs(refs, approvals, **kwargs)
        target = kwargs.pop("links", None) or kwargs.pop("layout", None)

    if isinstance(target, (list, tuple)):
        return review_links(target, approvals, **kwargs)

    if isinstance(target, (str, os.PathLike)):
        metadata = Metadata.load(os.fspath(target))
        payload = metadata.get_payload()
        if getattr(payload, "type_", None) == "link":
            return review_link(
                metadata, approvals, path=os.fspath(target), **kwargs
            )
        return review_layout(
            metadata, approvals, layout_path=os.fspath(target), **kwargs
        )

    if isinstance(target, dict):
        probe = target.get("signed", target)
        if isinstance(probe, dict) and probe.get("_type") == "link":
            return review_link(target, approvals, **kwargs)
        if isinstance(probe, dict) and probe.get("_type") == "layout":
            return review_layout(target, approvals, **kwargs)
        if target and all(
            hasattr(value, "get_payload")
            or (isinstance(value, dict) and ("signed" in value or "_type" in value))
            for value in target.values()
        ):
            return review_links(target, approvals, **kwargs)

    if hasattr(target, "get_payload"):
        payload = target.get_payload()
        if getattr(payload, "type_", None) == "link":
            return review_link(target, approvals, **kwargs)
        return review_layout(target, approvals, **kwargs)

    if getattr(target, "type_", None) == "link":
        return review_link(target, approvals, **kwargs)
    if hasattr(target, "steps"):
        return review_layout(target, approvals, **kwargs)

    return review_links(target, approvals, **kwargs)


review_credentials = review_credential_approvals
audit_credentials = review_credential_approvals
check_credential_approvals = review_credential_approvals
verify_credentials = review_credential_approvals
verify_credential_approvals = review_credential_approvals
review_approvals = review_credential_approvals
review_supply_chain_credentials = review_layout
audit_release = review_credential_approvals
review_release = review_credential_approvals
release_review = review_credential_approvals
audit_credential_refs = review_credential_approvals
review_credential_references = review_credential_approvals
verify_credential_references = review_credential_approvals
create_review_report = review_credential_approvals
