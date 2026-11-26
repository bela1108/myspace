"""Offline cross-hive identity and path correlation helpers.

regipy's plugins intentionally parse one hive at a time.  This module combines
their plain dictionary output with a caller-confirmed collection chain.  It is
deliberately conservative: user names and similar paths produce leads, while a
subject attribution also requires a SID and matching confirmed device chain.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Optional, Union

SUBJECT_MATCH = "subject_match"
PATH_SIMILAR_ONLY = "path_similar_only"
DIFFERENT_DEVICE = "different_device"
CHAIN_UNCONFIRMED = "chain_unconfirmed"
UNRESOLVED = "unresolved"

CATEGORY_LABELS = {
    SUBJECT_MATCH: "can_be_attributed_to_subject",
    PATH_SIMILAR_ONLY: "path_similarity_only",
    DIFFERENT_DEVICE: "explicitly_different_device",
    CHAIN_UNCONFIRMED: "collection_chain_unconfirmed",
    UNRESOLVED: "unresolved",
}

_GENERIC_PATH_SEGMENTS = {
    "desktop",
    "documents",
    "downloads",
    "pictures",
    "screenshots",
    "videos",
    "music",
    "new folder",
    "temp",
    "tmp",
}


@dataclass(frozen=True)
class ChainLink:
    """Caller-confirmed provenance for one hive or other piece of evidence."""

    machine_id: str
    source_path: Optional[str] = None
    profile_sid: Optional[str] = None
    chain_id: Optional[str] = None
    confirmed_by: Optional[str] = None
    collected_at: Optional[str] = None


@dataclass
class CollectionChain:
    """Authoritative artifact-to-machine mapping supplied by the caller."""

    links: dict[str, ChainLink] = field(default_factory=dict)

    def confirm(
        self,
        artifact_id: str,
        machine_id: str,
        *,
        source_path: Optional[str] = None,
        profile_sid: Optional[str] = None,
        chain_id: Optional[str] = None,
        confirmed_by: Optional[str] = None,
        collected_at: Optional[str] = None,
    ) -> "CollectionChain":
        self.links[str(artifact_id)] = ChainLink(
            machine_id=str(machine_id),
            source_path=source_path,
            profile_sid=profile_sid,
            chain_id=chain_id,
            confirmed_by=confirmed_by,
            collected_at=collected_at,
        )
        return self

    def get(self, artifact_id: Optional[str]) -> Optional[ChainLink]:
        if artifact_id is None:
            return None
        return self.links.get(str(artifact_id))

    def machine_for(self, artifact_id: Optional[str]) -> Optional[str]:
        link = self.get(artifact_id)
        return link.machine_id if link else None


@dataclass
class HiveView:
    """Minimal hive input: plugin output or a pure synthetic dictionary view."""

    hive_id: str
    hive_type: Optional[str] = None
    machine_id: Optional[str] = None
    source_path: Optional[str] = None
    profile_sid: Optional[str] = None
    network_drives: Sequence[Mapping[str, Any]] = field(default_factory=list)
    profiles: Sequence[Mapping[str, Any]] = field(default_factory=list)

    @classmethod
    def from_plugin_outputs(
        cls,
        hive_id: str,
        *,
        hive_type: Optional[str] = None,
        machine_id: Optional[str] = None,
        source_path: Optional[str] = None,
        profile_sid: Optional[str] = None,
        network_drives: Any = None,
        profiles: Any = None,
    ) -> "HiveView":
        return cls(
            hive_id=hive_id,
            hive_type=hive_type,
            machine_id=machine_id,
            source_path=source_path,
            profile_sid=profile_sid,
            network_drives=_plugin_entries(network_drives),
            profiles=_plugin_entries(profiles),
        )


@dataclass
class Finding:
    finding_id: str
    category: str
    record_type: str
    endorsed: bool = False
    machine_id: Optional[str] = None
    candidate_machine_id: Optional[str] = None
    sid: Optional[str] = None
    candidate_sid: Optional[str] = None
    subject_id: Optional[str] = None
    path: Optional[str] = None
    candidate_path: Optional[str] = None
    drive_letter: Optional[str] = None
    network_path: Optional[str] = None
    resolved_path: Optional[str] = None
    relation: Optional[str] = None
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS[self.category]

    def to_dict(self) -> dict[str, Any]:
        data = {
            "finding_id": self.finding_id,
            "category": self.category,
            "category_label": self.category_label,
            "record_type": self.record_type,
            "endorsed": self.endorsed,
            "machine_id": self.machine_id,
            "candidate_machine_id": self.candidate_machine_id,
            "sid": self.sid,
            "candidate_sid": self.candidate_sid,
            "subject_id": self.subject_id,
            "path": self.path,
            "candidate_path": self.candidate_path,
            "drive_letter": self.drive_letter,
            "network_path": self.network_path,
            "resolved_path": self.resolved_path,
            "relation": self.relation,
            "reasons": list(self.reasons),
            "details": _json_safe(self.details),
        }
        return data


@dataclass
class ClaimAssessment:
    claim_id: str
    path: str
    category: str
    endorsed: bool
    machine_id: Optional[str]
    subject_id: Optional[str] = None
    finding_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "path": self.path,
            "category": self.category,
            "category_label": CATEGORY_LABELS[self.category],
            "endorsed": self.endorsed,
            "machine_id": self.machine_id,
            "subject_id": self.subject_id,
            "finding_ids": list(self.finding_ids),
            "reasons": list(self.reasons),
        }


@dataclass
class CrossHiveReport:
    findings: list[Finding] = field(default_factory=list)
    claims: list[ClaimAssessment] = field(default_factory=list)

    def by_category(self, category: str) -> list[Finding]:
        return [finding for finding in self.findings if finding.category == category]

    @property
    def subject_matches(self) -> list[Finding]:
        return self.by_category(SUBJECT_MATCH)

    @property
    def path_similar_only(self) -> list[Finding]:
        return self.by_category(PATH_SIMILAR_ONLY)

    @property
    def different_devices(self) -> list[Finding]:
        return self.by_category(DIFFERENT_DEVICE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "categories": dict(CATEGORY_LABELS),
            "findings": [finding.to_dict() for finding in self.findings],
            "claims": [claim.to_dict() for claim in self.claims],
        }

    def markdown(self) -> str:
        lines = [
            "| ID | 分类 | 设备 | SID/主体 | 记录 | 关系 | 背书 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for finding in self.findings:
            subject = finding.subject_id or finding.sid or "-"
            record = finding.network_path or finding.path or finding.candidate_path or "-"
            lines.append(
                "| {id} | {category} | {machine} | {subject} | `{record}` | {relation} | {endorsed} |".format(
                    id=finding.finding_id,
                    category=CATEGORY_LABELS[finding.category],
                    machine=finding.machine_id or "unknown",
                    subject=subject,
                    record=str(record).replace("|", "\\|")[:160],
                    relation=finding.relation or "-",
                    endorsed="yes" if finding.endorsed else "no",
                )
            )
        return "\n".join(lines)


@dataclass
class _Profile:
    hive_id: str
    machine_id: Optional[str]
    chain_confirmed: bool
    sid: str
    path: str
    username: str
    machine_sid_prefix: Optional[str]
    raw: Mapping[str, Any]


@dataclass
class _Mapping:
    hive_id: str
    machine_id: Optional[str]
    chain_confirmed: bool
    drive_letter: Optional[str]
    network_path: Optional[str]
    source_path: Optional[str]
    requested_sid: Optional[str]
    raw: Mapping[str, Any]
    bound_profile: Optional[_Profile] = None


def correlate_hives(
    hive_views: Union[HiveView, Mapping[str, Any], Sequence[Any], None] = None,
    *,
    collection_chain: Union[CollectionChain, Mapping[str, Any], Sequence[Any], None] = None,
    screenshots: Any = None,
    claims: Any = None,
    views: Any = None,
    chain: Any = None,
) -> CrossHiveReport:
    """Correlate network-drive plugin output with ProfileList SIDs.

    ``collection_chain`` is the caller-confirmed artifact-to-machine mapping.
    A ``machine_id`` supplied directly by the caller on a synthetic view is
    treated as confirmed provenance. Path-only inputs without a device id can
    never be promoted to a subject match.
    """
    resolved_views = _coerce_views(hive_views if hive_views is not None else views)
    active_chain = _coerce_chain(collection_chain if collection_chain is not None else chain)
    claim_inputs = screenshots if screenshots is not None else claims

    profiles: list[_Profile] = []
    mappings: list[_Mapping] = []

    for view in resolved_views:
        link = active_chain.get(view.hive_id)
        machine_id = link.machine_id if link else view.machine_id
        source_path = link.source_path if link and link.source_path else view.source_path
        default_sid = link.profile_sid if link and link.profile_sid else view.profile_sid
        chain_confirmed = link is not None or bool(view.machine_id)

        for raw_profile in view.profiles:
            sid = str(_pick(raw_profile, "sid", "SID", default="") or "")
            path = str(_pick(raw_profile, "path", "ProfileImagePath", "profile_path", default="") or "")
            profiles.append(
                _Profile(
                    hive_id=view.hive_id,
                    machine_id=machine_id,
                    chain_confirmed=chain_confirmed,
                    sid=sid,
                    path=path,
                    username=username_from_profile_path(path),
                    machine_sid_prefix=machine_sid_prefix(sid),
                    raw=raw_profile,
                )
            )

        for raw_mapping in view.network_drives:
            entry_sid = _pick(raw_mapping, "sid", "user_sid", "profile_sid") or default_sid
            mappings.append(
                _Mapping(
                    hive_id=view.hive_id,
                    machine_id=machine_id,
                    chain_confirmed=chain_confirmed,
                    drive_letter=_drive_letter(_pick(raw_mapping, "drive_letter", "DriveLetter", "letter")),
                    network_path=_pick(raw_mapping, "network_path", "RemotePath", "remote_path", "remotePath"),
                    source_path=source_path,
                    requested_sid=str(entry_sid) if entry_sid else None,
                    raw=raw_mapping,
                )
            )

    report = CrossHiveReport()
    for index, mapping in enumerate(mappings, start=1):
        report.findings.extend(_correlate_mapping(f"drive-{index}", mapping, profiles))

    for index, claim_data in enumerate(_coerce_claims(claim_inputs), start=1):
        claim = _build_claim(claim_data, f"claim-{index}", active_chain)
        assessment, findings = _evaluate_claim(claim, mappings, profiles)
        report.claims.append(assessment)
        report.findings.extend(findings)

    return report


# Readable aliases for callers/tests using the task's vocabulary.
cross_check = correlate_hives
reconcile_hives = correlate_hives
correlate_hive_views = correlate_hives


def correlate_plugin_outputs(
    network_drives: Any = None,
    profiles: Any = None,
    *,
    drive_hive_id: str = "network-drives",
    profile_hive_id: str = "profiles",
    drive_source_path: Optional[str] = None,
    machine_id: Optional[str] = None,
    collection_chain: Union[CollectionChain, Mapping[str, Any], Sequence[Any], None] = None,
    screenshots: Any = None,
    claims: Any = None,
) -> CrossHiveReport:
    """Correlate NetworkDrivesPlugin and ProfileListPlugin output."""
    views: list[HiveView] = []
    if network_drives is not None:
        views.append(
            HiveView.from_plugin_outputs(
                drive_hive_id,
                hive_type="ntuser",
                machine_id=machine_id,
                source_path=drive_source_path,
                network_drives=network_drives,
            )
        )
    if profiles is not None:
        views.append(
            HiveView.from_plugin_outputs(
                profile_hive_id,
                hive_type="software",
                machine_id=machine_id,
                profiles=profiles,
            )
        )
    return correlate_hives(
        views,
        collection_chain=collection_chain,
        screenshots=screenshots,
        claims=claims,
    )


correlate_records = correlate_plugin_outputs


def username_from_profile_path(path: Optional[str]) -> str:
    normalized = normalize_windows_path(path or "")
    if not normalized:
        return ""
    segments = [segment for segment in normalized.split("\\") if segment]
    if not segments:
        return ""
    leaf = segments[-1]
    if leaf.lower() == "ntuser.dat" and len(segments) >= 2:
        leaf = segments[-2]
    return leaf


def machine_sid_prefix(sid: Optional[str]) -> Optional[str]:
    if not sid:
        return None
    parts = str(sid).split("-")
    if len(parts) >= 7 and parts[0] == "S" and parts[1] == "1" and parts[2] == "5" and parts[3] == "21":
        return "-".join(parts[:7])
    return None


def normalize_windows_path(path: Any) -> str:
    if path is None:
        return ""
    text = str(path).strip().replace("/", "\\")
    text = re.sub(r"\\{2,}", lambda _match: "\\\\", text)
    if re.match(r"^%SystemRoot%", text, flags=re.IGNORECASE):
        text = r"C:\Windows" + text[len("%SystemRoot%") :]
    if re.match(r"^%windir%", text, flags=re.IGNORECASE):
        text = r"C:\Windows" + text[len("%windir%") :]
    if len(text) > 3 and text.endswith("\\"):
        text = text.rstrip("\\")
    return text


def paths_equal(left: Any, right: Any) -> bool:
    a = normalize_windows_path(left).casefold()
    b = normalize_windows_path(right).casefold()
    return bool(a and b and a == b)


def path_relation(left: Any, right: Any) -> Optional[str]:
    """Return a conservative textual/path relation, or ``None``.

    Textual relations are leads only.  They never establish identity by
    themselves; callers must additionally check SID and device provenance.
    """
    a = normalize_windows_path(left)
    b = normalize_windows_path(right)
    if not a or not b:
        return None
    if a.casefold() == b.casefold():
        return "equal_path"

    a_parts = _path_segments(a)
    b_parts = _path_segments(b)
    if _parts_contain(a_parts, b_parts) or _parts_contain(b_parts, a_parts):
        return "path_prefix"

    common_suffix = 0
    for a_part, b_part in zip(reversed(a_parts), reversed(b_parts)):
        if a_part.casefold() != b_part.casefold():
            break
        common_suffix += 1
    if common_suffix >= 2:
        return f"common_suffix_{common_suffix}"

    a_leaf = a_parts[-1] if a_parts else ""
    b_leaf = b_parts[-1] if b_parts else ""
    if a_leaf and a_leaf.casefold() == b_leaf.casefold() and a_leaf.casefold() not in _GENERIC_PATH_SEGMENTS:
        return "same_leaf"
    if _similar_name(a_leaf, b_leaf):
        return "similar_leaf"
    return None


def resolve_drive_path(path: str, drive_letter: Optional[str], network_path: Optional[str]) -> Optional[str]:
    """Resolve ``Z:\\...`` using a ``Z: -> \\server\\share`` mapping."""
    if not path or not drive_letter or not network_path:
        return None
    normalized = normalize_windows_path(path)
    match = re.match(r"^([A-Za-z]):\\?(.*)$", normalized)
    if not match or match.group(1).casefold() != str(drive_letter).casefold():
        return None
    suffix = match.group(2)
    root = normalize_windows_path(network_path)
    return f"{root}\\{suffix}" if suffix else root


def _correlate_mapping(finding_id: str, mapping: _Mapping, profiles: Sequence[_Profile]) -> list[Finding]:
    findings: list[Finding] = []
    bound_profile, bind_relation, bind_reason = _bind_profile(mapping, profiles)
    mapping.bound_profile = bound_profile

    if bound_profile is not None and bind_relation == "confirmed":
        findings.append(
            Finding(
                finding_id=f"{finding_id}-subject",
                category=SUBJECT_MATCH,
                record_type="drive_mapping",
                endorsed=True,
                machine_id=mapping.machine_id,
                sid=bound_profile.sid,
                subject_id=_subject_id(mapping.machine_id, bound_profile.sid),
                path=bound_profile.path,
                drive_letter=mapping.drive_letter,
                network_path=mapping.network_path,
                relation="sid_and_confirmed_chain",
                reasons=[
                    "collection chain confirms the NTUSER and ProfileList hives belong to one machine",
                    f"ProfileList maps SID {bound_profile.sid} to {bound_profile.path}",
                    bind_reason or "NTUSER hive is bound to that profile",
                ],
                details={"hive_id": mapping.hive_id, "profile_hive_id": bound_profile.hive_id},
            )
        )
    else:
        conflict = _device_conflict_with_best_profile(mapping, profiles)
        if conflict is not None:
            profile = conflict
            findings.append(_different_device_mapping(f"{finding_id}-device", mapping, profile, bind_reason))
        elif not mapping.chain_confirmed:
            findings.append(
                Finding(
                    finding_id=f"{finding_id}-chain",
                    category=CHAIN_UNCONFIRMED,
                    record_type="drive_mapping",
                    machine_id=mapping.machine_id,
                    sid=mapping.requested_sid,
                    drive_letter=mapping.drive_letter,
                    network_path=mapping.network_path,
                    relation=bind_relation,
                    reasons=["no caller-confirmed collection-chain link exists for this hive"],
                )
            )
        else:
            findings.append(
                Finding(
                    finding_id=f"{finding_id}-unresolved",
                    category=UNRESOLVED,
                    record_type="drive_mapping",
                    machine_id=mapping.machine_id,
                    sid=mapping.requested_sid,
                    drive_letter=mapping.drive_letter,
                    network_path=mapping.network_path,
                    relation=bind_relation,
                    reasons=[bind_reason or "no SID or exact profile-path binding was found"],
                )
            )

    for index, profile in enumerate(profiles, start=1):
        if bound_profile is not None and profile is bound_profile and bind_relation == "confirmed":
            continue
        relation = _mapping_profile_relation(mapping, profile)
        same_identity_hint = _same_account_hint(mapping, profile)
        if relation is None and not same_identity_hint:
            continue

        if mapping.machine_id and profile.machine_id and mapping.machine_id != profile.machine_id:
            if not any(
                existing.candidate_sid == profile.sid and existing.category == DIFFERENT_DEVICE for existing in findings
            ):
                findings.append(_different_device_mapping(f"{finding_id}-compare-{index}", mapping, profile, None))
            continue

        category = PATH_SIMILAR_ONLY
        if not mapping.chain_confirmed or not profile.chain_confirmed:
            reason = "path similarity exists, but the machine collection chain is not confirmed"
        else:
            reason = "path/user-name similarity alone does not bind the mapping to this SID"
        findings.append(
            Finding(
                finding_id=f"{finding_id}-compare-{index}",
                category=category,
                record_type="profile_candidate",
                machine_id=mapping.machine_id,
                candidate_machine_id=profile.machine_id,
                sid=mapping.requested_sid,
                candidate_sid=profile.sid,
                subject_id=_subject_id(mapping.machine_id, mapping.requested_sid),
                path=mapping.source_path,
                candidate_path=profile.path,
                drive_letter=mapping.drive_letter,
                network_path=mapping.network_path,
                relation=relation or "same_account_hint",
                reasons=[reason],
                details={"profile_username": profile.username},
            )
        )

    return findings


def _evaluate_claim(
    claim: "_Claim", mappings: Sequence[_Mapping], profiles: Sequence[_Profile]
) -> tuple[ClaimAssessment, list[Finding]]:
    findings: list[Finding] = []
    verified: list[str] = []
    finding_ids: list[str] = []

    for index, profile in enumerate(profiles, start=1):
        relation = path_relation(claim.path, profile.path)
        if relation is None:
            continue
        finding_id = f"{claim.claim_id}-profile-{index}"
        device_diff = bool(claim.machine_id and profile.machine_id and claim.machine_id != profile.machine_id)
        if device_diff:
            category = DIFFERENT_DEVICE
            endorsed = False
            reasons = [
                f"caller-confirmed machine for claim is {claim.machine_id}, profile machine is {profile.machine_id}",
                "identical user name or profile path on another device is not attribution",
            ]
        elif claim.chain_confirmed and relation in {"equal_path", "path_prefix"} and claim.machine_id == profile.machine_id:
            category = SUBJECT_MATCH
            endorsed = True
            verified.append(finding_id)
            reasons = [
                "claim and ProfileList SID are bound to the same caller-confirmed machine",
                f"claim path is {relation.replace('_', ' ')} profile path {profile.path}",
            ]
        else:
            category = PATH_SIMILAR_ONLY
            endorsed = False
            reasons = ["path similarity is present, but confirmed device/SID containment is absent"]
        finding_ids.append(finding_id)
        findings.append(
            Finding(
                finding_id=finding_id,
                category=category,
                record_type="screenshot_path",
                endorsed=endorsed,
                machine_id=claim.machine_id,
                candidate_machine_id=profile.machine_id,
                sid=profile.sid if category == SUBJECT_MATCH else None,
                candidate_sid=profile.sid,
                subject_id=_subject_id(claim.machine_id, profile.sid) if category == SUBJECT_MATCH else None,
                path=claim.path,
                candidate_path=profile.path,
                relation=relation,
                reasons=reasons,
                details={"claim_chain_confirmed": claim.chain_confirmed},
            )
        )

    for index, mapping in enumerate(mappings, start=1):
        same_drive = bool(mapping.drive_letter and _drive_letter(claim.path) == mapping.drive_letter)
        unc_relation = path_relation(claim.path, mapping.network_path)
        resolved = resolve_drive_path(claim.path, mapping.drive_letter, mapping.network_path)
        resolved_relation = path_relation(resolved, mapping.network_path) if resolved else None
        relation = resolved_relation or unc_relation
        device_diff = bool(claim.machine_id and mapping.machine_id and claim.machine_id != mapping.machine_id)
        if not same_drive and relation is None and not device_diff:
            continue
        if device_diff and not same_drive and relation is None:
            continue

        finding_id = f"{claim.claim_id}-drive-{index}"
        bound = mapping.bound_profile
        if bound is None:
            bound, _, _ = _bind_profile(mapping, profiles)
            mapping.bound_profile = bound
        device_diff = device_diff or bool(
            bound and claim.machine_id and bound.machine_id and claim.machine_id != bound.machine_id
        )

        if device_diff:
            profile_machine = bound.machine_id if bound else None
            category = DIFFERENT_DEVICE
            endorsed = False
            reasons = [
                f"claim machine {claim.machine_id or 'unknown'} differs from drive hive machine "
                f"{mapping.machine_id or 'unknown'} and ProfileList SID machine {profile_machine or 'unknown'}",
                "old mapped-drive path cannot endorse evidence collected from another device",
            ]
        elif (
            claim.chain_confirmed
            and relation in {"equal_path", "path_prefix"}
            and bound is not None
            and mapping.machine_id == claim.machine_id
            and bound.machine_id == claim.machine_id
        ):
            category = SUBJECT_MATCH
            endorsed = True
            verified.append(finding_id)
            reasons = [
                f"{mapping.drive_letter}: maps to {mapping.network_path}",
                f"resolved claim path to {resolved or claim.path}",
                f"mapping is bound to SID {bound.sid} and the confirmed machine chain matches",
            ]
        else:
            category = PATH_SIMILAR_ONLY
            endorsed = False
            reasons = ["drive/path similarity exists, but the SID and confirmed machine binding is incomplete"]

        finding_ids.append(finding_id)
        findings.append(
            Finding(
                finding_id=finding_id,
                category=category,
                record_type="mapped_path_claim",
                endorsed=endorsed,
                machine_id=claim.machine_id,
                candidate_machine_id=mapping.machine_id,
                sid=bound.sid if category == SUBJECT_MATCH and bound else None,
                candidate_sid=bound.sid if bound else mapping.requested_sid,
                subject_id=_subject_id(claim.machine_id, bound.sid) if category == SUBJECT_MATCH and bound else None,
                path=claim.path,
                candidate_path=mapping.source_path or bound.path if bound else mapping.source_path,
                drive_letter=mapping.drive_letter,
                network_path=mapping.network_path,
                resolved_path=resolved,
                relation=relation or ("same_drive_letter" if same_drive else None),
                reasons=reasons,
            )
        )

    if verified:
        category = SUBJECT_MATCH
        endorsed = True
        reasons = ["at least one SID-bound, machine-confirmed path anchor matches"]
        subject_id = next((f.subject_id for f in findings if f.finding_id in verified and f.subject_id), None)
    elif any(f.category == PATH_SIMILAR_ONLY for f in findings):
        category = PATH_SIMILAR_ONLY
        endorsed = False
        subject_id = None
        reasons = ["only path/drive similarity was established"]
    elif any(f.category == DIFFERENT_DEVICE for f in findings):
        category = DIFFERENT_DEVICE
        endorsed = False
        subject_id = None
        reasons = ["all available anchors are explicitly on another device"]
    else:
        category = UNRESOLVED
        endorsed = False
        subject_id = None
        reasons = ["no usable profile or mapped-drive anchor was found"]

    assessment = ClaimAssessment(
        claim_id=claim.claim_id,
        path=claim.path,
        category=category,
        endorsed=endorsed,
        machine_id=claim.machine_id,
        subject_id=subject_id,
        finding_ids=finding_ids,
        reasons=reasons,
    )
    return assessment, findings


@dataclass
class _Claim:
    claim_id: str
    path: str
    machine_id: Optional[str]
    chain_confirmed: bool


def _build_claim(data: Any, index_id: str, chain: CollectionChain) -> _Claim:
    if isinstance(data, str):
        claim_id = index_id
        path = data
        explicit_machine = None
        hive_id = None
    else:
        claim_id = str(_pick(data, "claim_id", "artifact_id", "id", default=index_id))
        path = str(_pick(data, "path", "screenshot_path", "file_path", default=""))
        explicit_machine = _pick(data, "machine_id", "device_id")
        hive_id = _pick(data, "hive_id", "artifact_id", "evidence_id")
    link = chain.get(claim_id) or chain.get(hive_id)
    machine_id = link.machine_id if link else explicit_machine
    confirmed = link is not None or bool(explicit_machine) or bool(_pick(data, "chain_confirmed", default=False))
    return _Claim(
        claim_id=claim_id,
        path=path,
        machine_id=str(machine_id) if machine_id else None,
        chain_confirmed=confirmed,
    )


def _bind_profile(mapping: _Mapping, profiles: Sequence[_Profile]) -> tuple[Optional[_Profile], str, Optional[str]]:
    if mapping.requested_sid:
        sid_matches = [profile for profile in profiles if profile.sid == mapping.requested_sid]
        confirmed = [
            profile
            for profile in sid_matches
            if mapping.machine_id
            and profile.machine_id == mapping.machine_id
            and mapping.chain_confirmed
            and profile.chain_confirmed
        ]
        if len(confirmed) == 1:
            return confirmed[0], "confirmed", f"caller/entry SID {mapping.requested_sid} matches ProfileList"
        if sid_matches:
            return sid_matches[0], "sid_cross_device", "SID candidate exists but confirmed machine ids do not match"

    if mapping.source_path:
        exact = [profile for profile in profiles if paths_equal(mapping.source_path, f"{profile.path}\\NTUSER.DAT")]
        confirmed = [
            profile
            for profile in exact
            if mapping.machine_id
            and profile.machine_id == mapping.machine_id
            and mapping.chain_confirmed
            and profile.chain_confirmed
        ]
        if len(confirmed) == 1:
            return confirmed[0], "confirmed", "confirmed NTUSER source path equals ProfileImagePath\\NTUSER.DAT"
        if exact:
            return (
                exact[0],
                "path_exact",
                "NTUSER source path exactly matches a profile path, but chain/SID device binding is incomplete",
            )
    return None, "unbound", "no confirmed SID or exact profile-path binding"


def _device_conflict_with_best_profile(mapping: _Mapping, profiles: Sequence[_Profile]) -> Optional[_Profile]:
    _, relation, _ = _bind_profile(mapping, profiles)
    if relation != "sid_cross_device":
        exact = [
            profile for profile in profiles if _mapping_profile_relation(mapping, profile) in {"equal_path", "path_prefix"}
        ]
        for profile in exact:
            if mapping.machine_id and profile.machine_id and mapping.machine_id != profile.machine_id:
                return profile
        return None
    bound, _, _ = _bind_profile(mapping, profiles)
    if bound and mapping.machine_id and bound.machine_id and mapping.machine_id != bound.machine_id:
        return bound
    return None


def _different_device_mapping(finding_id: str, mapping: _Mapping, profile: _Profile, reason: Optional[str]) -> Finding:
    return Finding(
        finding_id=finding_id,
        category=DIFFERENT_DEVICE,
        record_type="drive_mapping",
        machine_id=mapping.machine_id,
        candidate_machine_id=profile.machine_id,
        sid=mapping.requested_sid,
        candidate_sid=profile.sid,
        subject_id=_subject_id(mapping.machine_id, mapping.requested_sid),
        path=mapping.source_path,
        candidate_path=profile.path,
        drive_letter=mapping.drive_letter,
        network_path=mapping.network_path,
        relation="collection_chain_machine_mismatch",
        reasons=[
            f"drive hive is confirmed to {mapping.machine_id or 'unknown'}; profile/SID is confirmed to {profile.machine_id or 'unknown'}",
            "same local user name, RID, or profile path does not override the device chain",
        ]
        + ([reason] if reason else []),
        details={"profile_username": profile.username},
    )


def _mapping_profile_relation(mapping: _Mapping, profile: _Profile) -> Optional[str]:
    source_profile = mapping.source_path
    normalized_source = normalize_windows_path(source_profile)
    source_leaf = normalized_source.rsplit("\\", 1)[-1].casefold() if normalized_source else ""
    if source_leaf == "ntuser.dat":
        source_profile = normalize_windows_path(source_profile)
        source_profile = source_profile.rsplit("\\", 1)[0]
    relation = path_relation(source_profile, profile.path)
    if relation:
        return relation
    if _same_account_hint(mapping, profile):
        return "same_account_name_or_rid"
    return None


def _same_account_hint(mapping: _Mapping, profile: _Profile) -> bool:
    if mapping.requested_sid and profile.sid and mapping.requested_sid.rsplit("-", 1)[-1] == profile.sid.rsplit("-", 1)[-1]:
        return True
    source_user = username_from_profile_path(mapping.source_path)
    return bool(source_user and source_user.casefold() == profile.username.casefold())


def _subject_id(machine_id: Optional[str], sid: Optional[str]) -> Optional[str]:
    if machine_id and sid:
        return f"{machine_id}/{sid}"
    return sid or machine_id


def _drive_letter(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if len(text) == 1:
        return text.upper()
    match = re.match(r"^([A-Za-z]):?", text)
    return match.group(1).upper() if match else None


def _path_segments(normalized_path: str) -> list[str]:
    return [part for part in normalized_path.split("\\") if part]


def _parts_contain(outer: Sequence[str], inner: Sequence[str]) -> bool:
    if len(inner) >= len(outer):
        return False
    return [part.casefold() for part in outer[: len(inner)]] == [part.casefold() for part in inner]


def _similar_name(left: str, right: str) -> bool:
    if not left or not right:
        return False
    a = left.casefold()
    b = right.casefold()
    if a == b:
        return True
    shorter, longer = sorted((a, b), key=len)
    if len(shorter) >= 5 and longer.startswith(shorter):
        return True
    left_tokens = [token for token in re.split(r"[^0-9a-z\u4e00-\u9fff]+", a) if token]
    right_tokens = [token for token in re.split(r"[^0-9a-z\u4e00-\u9fff]+", b) if token]
    return bool(left_tokens and right_tokens and left_tokens[0] == right_tokens[0] and len(left_tokens[0]) >= 5)


def _coerce_views(value: Any) -> list[HiveView]:
    if value is None:
        return []
    if isinstance(value, HiveView):
        return [value]
    if isinstance(value, Mapping):
        views = []
        for hive_id, spec in value.items():
            if isinstance(spec, HiveView):
                views.append(spec)
            elif isinstance(spec, Mapping):
                data = dict(spec)
                data.setdefault("hive_id", hive_id)
                views.append(_view_from_mapping(data))
            else:
                raise TypeError(f"unsupported hive view for {hive_id}: {type(spec)!r}")
        return views
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        views: list[HiveView] = []
        for item in value:
            if isinstance(item, HiveView):
                views.append(item)
            elif isinstance(item, Mapping):
                views.append(_view_from_mapping(dict(item)))
            else:
                raise TypeError(f"unsupported hive view type: {type(item)!r}")
        return views
    raise TypeError(f"unsupported hive views type: {type(value)!r}")


def _view_from_mapping(data: Mapping[str, Any]) -> HiveView:
    allowed = {field.name for field in HiveView.__dataclass_fields__.values()}
    aliases = {
        "device_id": "machine_id",
        "machine": "machine_id",
        "machine_number": "machine_id",
    }
    normalized = {aliases.get(str(key), key): value for key, value in data.items()}
    filtered = {key: value for key, value in normalized.items() if key in allowed}
    for key in ("network_drives", "profiles"):
        if key in filtered:
            filtered[key] = _plugin_entries(filtered[key])
    return HiveView(**filtered)


def _coerce_chain(value: Any) -> CollectionChain:
    if value is None:
        return CollectionChain()
    if isinstance(value, CollectionChain):
        return value
    chain = CollectionChain()
    if isinstance(value, Mapping):
        items = value.items()
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        items = ((_pick(item, "artifact_id", "hive_id", "id"), item) for item in value)
    else:
        raise TypeError(f"unsupported collection chain type: {type(value)!r}")

    for artifact_id, spec in items:
        if isinstance(spec, str):
            chain.confirm(str(artifact_id), spec)
        elif isinstance(spec, ChainLink):
            chain.links[str(artifact_id)] = spec
        elif isinstance(spec, Mapping):
            machine_id = _pick(spec, "machine_id", "device_id", "machine", "machine_number")
            if machine_id is None:
                raise ValueError("collection-chain entry requires machine_id")
            chain.confirm(
                str(artifact_id or _pick(spec, "artifact_id", "hive_id", "id")),
                str(machine_id),
                source_path=_pick(spec, "source_path", "original_path"),
                profile_sid=_pick(spec, "profile_sid", "sid"),
                chain_id=_pick(spec, "chain_id"),
                confirmed_by=_pick(spec, "confirmed_by", "caller"),
                collected_at=_pick(spec, "collected_at"),
            )
        else:
            raise TypeError(f"unsupported chain entry: {type(spec)!r}")
    return chain


def _coerce_claims(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, Mapping)):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    return [value]


def _plugin_entries(value: Any) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    entries = getattr(value, "entries", value)
    if entries is None:
        return []
    if isinstance(entries, list):
        return entries
    if isinstance(entries, Mapping):
        return [entries]
    return list(entries)


def _pick(obj: Any, *names: str, default: Any = None) -> Any:
    if obj is None:
        return default
    for name in names:
        if isinstance(obj, Mapping):
            if name in obj and obj[name] is not None:
                return obj[name]
        else:
            value = getattr(obj, name, None)
            if value is not None:
                return value
    return default


def _json_safe(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return value
