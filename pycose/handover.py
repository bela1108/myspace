from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Mapping, Optional, Sequence, Tuple, Union

from pycose.headers import KID
from pycose.messages.encmessage import EncMessage


HANDOVER_GROUP = "HANDOVER_GROUP"
OLD_GROUP_HOLDER = "OLD_GROUP_HOLDER"

ELIGIBLE = "eligible"
INELIGIBLE = "ineligible"
INFORMATION_INCOMPLETE = "information_incomplete"


@dataclass(frozen=True)
class RosterEntry:
    eligible: bool


@dataclass(frozen=True)
class ConcurrentRecipientPath:
    holder_group: bytes
    recipient_kid: bytes
    recipient_path: Tuple[bytes, ...]
    expires_at: datetime


@dataclass(frozen=True)
class RecipientAssessment:
    kid: Optional[bytes]
    recipient_path: Tuple[Optional[bytes], ...]
    status: str
    group: Optional[bytes]
    is_nested: bool
    parent_path: Tuple[Optional[bytes], ...]
    reason: str


@dataclass(frozen=True)
class HandoverAssessment:
    status: str
    recipients: Tuple[RecipientAssessment, ...]
    active_concurrent_paths: Tuple[ConcurrentRecipientPath, ...]
    nested_recipient_handling: str


class HandoverMaterial:
    def __init__(self,
                 new_archive_group: bytes,
                 concurrent_recipient_paths: Sequence[Mapping[str, Any]],
                 now: Optional[datetime] = None):
        self._new_archive_group = _as_group(new_archive_group)
        self._concurrent_recipient_paths = tuple(
            _materialize_concurrent_path(path) for path in concurrent_recipient_paths
        )
        self._now = now if now is not None else datetime.now(timezone.utc)

    @property
    def new_archive_group(self) -> bytes:
        return self._new_archive_group

    @property
    def now(self) -> datetime:
        return self._now

    @property
    def concurrent_recipient_paths(self) -> Tuple[ConcurrentRecipientPath, ...]:
        return self._concurrent_recipient_paths

    @property
    def active_concurrent_paths(self) -> Tuple[ConcurrentRecipientPath, ...]:
        return tuple(path for path in self._concurrent_recipient_paths if self._is_active(path))

    def active_path_for(self, recipient_path: Sequence[Optional[bytes]]) -> Optional[ConcurrentRecipientPath]:
        path_tuple = tuple(recipient_path)
        for active_path in self.active_concurrent_paths:
            if active_path.recipient_path == path_tuple:
                return active_path
        return None

    def _is_active(self, path: ConcurrentRecipientPath) -> bool:
        return _as_utc(path.expires_at) > _as_utc(self._now)


def assess_handover(message: Union[EncMessage, bytes],
                    offline_roster: Mapping[bytes, Union[bool, Mapping[str, Any], RosterEntry]],
                    handover_material: HandoverMaterial) -> HandoverAssessment:
    cose_message = _message_from(message)
    assessments = tuple(
        assessment
        for recipient in cose_message.recipients
        for assessment in _collect_assessments(recipient, (), handover_material, offline_roster)
    )

    if not assessments:
        overall_status = INFORMATION_INCOMPLETE
    elif any(assessment.status == INFORMATION_INCOMPLETE for assessment in assessments):
        overall_status = INFORMATION_INCOMPLETE
    elif all(assessment.status == ELIGIBLE for assessment in assessments):
        overall_status = ELIGIBLE
    else:
        overall_status = INELIGIBLE

    return HandoverAssessment(
        status=overall_status,
        recipients=assessments,
        active_concurrent_paths=handover_material.active_concurrent_paths,
        nested_recipient_handling=(
            "A nested recipient is evaluated in the context of its nearest marked recipient. "
            "New-archive recipients remain eligible through their subtree, while an old-group concurrent "
            "path remains eligible only while its local expiry is in the future. A nested recipient that "
            "explicitly carries the new archive group is treated as replaced and does not require the old "
            "concurrent path; otherwise, expiry of the enclosing old-group path makes the nested subtree ineligible."
        )
    )


def _assess_recipient(recipient: Any,
                      ancestor_path: Tuple[Optional[bytes], ...],
                      handover_material: HandoverMaterial,
                      offline_roster: Mapping[bytes, Union[bool, Mapping[str, Any], RosterEntry]],
                      inherited_group: Optional[bytes] = None,
                      active_concurrent_path: Optional[ConcurrentRecipientPath] = None) -> RecipientAssessment:
    kid = _get_header(recipient, KID)
    recipient_path = ancestor_path + (kid,)
    parent_path = ancestor_path
    marked_group = _marked_group(recipient)
    holder_group = _holder_group(recipient)
    group = marked_group if marked_group is not None else holder_group or inherited_group

    active_path = active_concurrent_path
    effective_group = marked_group if marked_group is not None else holder_group
    if effective_group is not None and effective_group != handover_material.new_archive_group:
        own_active_path = handover_material.active_path_for(recipient_path)
        if own_active_path is not None:
            active_path = own_active_path

    status, reason = _eligibility_reason(
        kid, group, recipient_path, active_path, handover_material, offline_roster
    )

    return RecipientAssessment(
        kid=kid,
        recipient_path=recipient_path,
        status=status,
        group=group,
        is_nested=bool(ancestor_path),
        parent_path=parent_path,
        reason=reason
    )


def _collect_assessments(recipient: Any,
                         ancestor_path: Tuple[Optional[bytes], ...],
                         handover_material: HandoverMaterial,
                         offline_roster: Mapping[bytes, Union[bool, Mapping[str, Any], RosterEntry]],
                         inherited_group: Optional[bytes] = None,
                         active_concurrent_path: Optional[ConcurrentRecipientPath] = None) -> List[RecipientAssessment]:
    assessment = _assess_recipient(
        recipient,
        ancestor_path,
        handover_material,
        offline_roster,
        inherited_group,
        active_concurrent_path
    )
    assessments = [assessment]
    for child in recipient.recipients:
        assessments.extend(
            _collect_assessments(
                child,
                assessment.recipient_path,
                handover_material,
                offline_roster,
                assessment.group,
                _child_active_path(recipient, assessment, handover_material, active_concurrent_path)
            )
        )
    return assessments


def _child_active_path(parent: Any,
                       parent_assessment: RecipientAssessment,
                       handover_material: HandoverMaterial,
                       inherited_active_path: Optional[ConcurrentRecipientPath] = None
                       ) -> Optional[ConcurrentRecipientPath]:
    marked_group = _marked_group(parent)
    holder_group = _holder_group(parent)
    effective_group = marked_group if marked_group is not None else holder_group
    if parent_assessment.group == handover_material.new_archive_group:
        return None
    if effective_group is not None and effective_group != handover_material.new_archive_group:
        return handover_material.active_path_for(parent_assessment.recipient_path) or inherited_active_path
    return handover_material.active_path_for(parent_assessment.recipient_path) or inherited_active_path


def _eligibility_reason(kid: Optional[bytes],
                        group: Optional[bytes],
                        recipient_path: Tuple[Optional[bytes], ...],
                        active_path: Optional[ConcurrentRecipientPath],
                        handover_material: HandoverMaterial,
                        offline_roster: Mapping[bytes, Union[bool, Mapping[str, Any], RosterEntry]]
                        ) -> Tuple[str, str]:
    if kid is None:
        return INFORMATION_INCOMPLETE, "Recipient has no KID and cannot be matched to the offline roster."
    if kid not in offline_roster:
        return INFORMATION_INCOMPLETE, "Recipient KID is absent from the caller's offline roster."
    if not _roster_eligible(offline_roster[kid]):
        return INELIGIBLE, "Recipient is marked as not eligible in the caller's offline roster."
    if group is None:
        return (
            INFORMATION_INCOMPLETE,
            "Recipient has no handover group and cannot be assigned to the new archive group or an old group."
        )
    if group == handover_material.new_archive_group:
        return ELIGIBLE, "Recipient belongs to the approved new archive group and is present in the offline roster."
    if active_path is None:
        return INELIGIBLE, "Old-group recipient has no active concurrent path in the local handover material."
    if active_path.holder_group != group:
        return INELIGIBLE, "Concurrent path holder does not match the recipient's old group."
    return (
        ELIGIBLE,
        "Recipient uses an old-group concurrent path held by "
        f"{active_path.holder_group!r} and valid until {active_path.expires_at.isoformat()}."
    )


def _roster_eligible(value: Union[bool, Mapping[str, Any], RosterEntry]) -> bool:
    if isinstance(value, RosterEntry):
        return value.eligible
    if isinstance(value, Mapping):
        return bool(value["eligible"])
    return bool(value)


def _materialize_concurrent_path(path: Mapping[str, Any]) -> ConcurrentRecipientPath:
    holder_group = _as_group(path["holder_group"])
    recipient_kid = _as_group(path["recipient_kid"])
    raw_recipient_path = path.get("recipient_path", (recipient_kid,))
    recipient_path = tuple(_as_group(part) for part in raw_recipient_path)
    if not recipient_path:
        raise ValueError("recipient_path must contain at least one recipient KID")
    if recipient_path[-1] != recipient_kid:
        raise ValueError("recipient_path must end with recipient_kid")
    return ConcurrentRecipientPath(
        holder_group=holder_group,
        recipient_kid=recipient_kid,
        recipient_path=recipient_path,
        expires_at=_as_datetime(path["expires_at"])
    )


def _message_from(message: Union[EncMessage, bytes]) -> EncMessage:
    if isinstance(message, EncMessage):
        return message
    if isinstance(message, bytes):
        decoded = EncMessage.decode(message)
        if not isinstance(decoded, EncMessage):
            raise TypeError("Handover assessment requires a COSE_Encrypt message")
        return decoded
    raise TypeError("message must be an EncMessage or encoded COSE_Encrypt bytes")


def _get_header(obj: Any, attribute: Any) -> Optional[bytes]:
    value = obj.get_attr(attribute, None)
    if value is not None:
        return value
    for header in (obj.phdr, obj.uhdr):
        for key, header_value in header.items():
            if key == attribute or _header_name(key) == _header_name(attribute):
                return header_value
    return None


def _marked_group(obj: Any) -> Optional[bytes]:
    for header in (obj.phdr, obj.uhdr):
        for key, value in header.items():
            if _header_name(key) == HANDOVER_GROUP:
                return _as_group(value)
    return None


def _holder_group(obj: Any) -> Optional[bytes]:
    for header in (obj.phdr, obj.uhdr):
        for key, value in header.items():
            if _header_name(key) == OLD_GROUP_HOLDER:
                return _as_group(value)
    return None


def _header_name(key: Any) -> str:
    name = getattr(key, "fullname", key)
    return str(name).upper()


def _as_group(value: Union[bytes, str]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("group and recipient identifiers must be bytes or strings")


def _as_datetime(value: Union[datetime, str]) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        return datetime.fromisoformat(normalized)
    raise TypeError("expires_at must be a datetime or ISO 8601 string")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
