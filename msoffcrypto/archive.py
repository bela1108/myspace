from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable, Optional, Protocol

import olefile

from msoffcrypto import OfficeFile
from msoffcrypto.exceptions import (
    PolicyError,
    ReadPermissionDeniedError,
    TransferRejectedError,
)

__all__ = [
    "ArchiveMaterial",
    "ArchivePolicyGate",
    "ArchiveService",
    "CurrentPolicyTransferReviewer",
    "DEFAULT_POLICY_CUTOFF_DATE",
    "FIXED_POLICY_REFERENCE_DATE",
    "FormatProfile",
    "LegacyReadPermission",
    "PolicyError",
    "ReadPermission",
    "ReadPermissionChecker",
    "ReadPermissionDeniedError",
    "ReadRequest",
    "TransferRejectedError",
    "TransferRequest",
    "TransferResultReviewer",
    "TransferReview",
    "identify_format",
]


DEFAULT_POLICY_CUTOFF_DATE = date(2026, 1, 1)
FIXED_POLICY_REFERENCE_DATE = date(2026, 6, 30)
CURRENT_ENCRYPTION_TYPES = frozenset({"agile"})
LEGACY_ENCRYPTION_TYPES = frozenset({"rc4", "rc4_cryptoapi", "standard", "xor"})


@dataclass(frozen=True)
class ArchiveMaterial:
    material_id: str
    stream: Any
    source_date: Optional[date] = None
    source_date_trusted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReadRequest:
    material: ArchiveMaterial
    purpose: str
    effective_date: date


@dataclass(frozen=True)
class ReadPermission:
    allowed: bool
    reason: str = ""
    policy_version: str = ""


@dataclass(frozen=True)
class TransferRequest:
    material: ArchiveMaterial
    destination: str
    effective_date: date


@dataclass(frozen=True)
class FormatProfile:
    format: str
    encryption_type: Optional[str]
    encrypted: bool
    key_types: tuple[str, ...]
    office_file: Any

    @property
    def uses_legacy_encryption(self) -> bool:
        return self.encryption_type in LEGACY_ENCRYPTION_TYPES


@dataclass(frozen=True)
class TransferReview:
    accepted: bool
    reason: str = ""
    policy_version: str = ""

    @property
    def is_complete(self) -> bool:
        return self.accepted


class ReadPermissionChecker(Protocol):
    def authorize_read(self, request: ReadRequest, profile: FormatProfile) -> ReadPermission:
        ...


class TransferResultReviewer(Protocol):
    def review_transfer(
        self,
        request: TransferRequest,
        source: FormatProfile,
        result: FormatProfile,
    ) -> TransferReview:
        ...


def identify_format(stream: Any) -> FormatProfile:
    """Identify an Office file without loading a key or changing policy state."""
    position = stream.tell()
    try:
        office_file = OfficeFile(stream)
        encrypted = office_file.is_encrypted()
        encryption_type = getattr(office_file, "type", None)
        if encryption_type == "plain":
            encryption_type = None
        if encryption_type is None and encrypted:
            encryption_type = _detect_encryption_type(stream, encryption_type)
        return FormatProfile(
            format=office_file.format,
            encryption_type=encryption_type,
            encrypted=encrypted,
            key_types=tuple(getattr(office_file, "keyTypes", ())),
            office_file=office_file,
        )
    finally:
        stream.seek(position)


def _detect_encryption_type(
    stream: Any, encryption_type: Optional[str]
) -> Optional[str]:
    if encryption_type is not None:
        return encryption_type

    stream.seek(0)
    if not olefile.isOleFile(stream):
        return None

    with olefile.OleFileIO(stream) as ole:
        if ole.exists("wordDocument"):
            return "rc4_cryptoapi"
        if ole.exists("Workbook"):
            return "rc4_cryptoapi"
        if ole.exists("PowerPoint Document"):
            return "rc4_cryptoapi"
    return None


class LegacyReadPermission:
    """Default read decision for legacy encrypted historical materials."""

    def __init__(
        self,
        approved_material_ids: frozenset[str] | set[str] | tuple[str, ...] = (),
        cutoff_date: date = DEFAULT_POLICY_CUTOFF_DATE,
        policy_version: str = "current-read-policy",
    ):
        self.approved_material_ids = frozenset(approved_material_ids)
        self.cutoff_date = cutoff_date
        self.policy_version = policy_version

    def authorize_read(
        self, request: ReadRequest, profile: FormatProfile
    ) -> ReadPermission:
        if not profile.uses_legacy_encryption:
            return ReadPermission(True, "Legacy algorithm is not used", self.policy_version)

        if request.material.material_id not in self.approved_material_ids:
            return ReadPermission(
                False, "Historical material is not approved", self.policy_version
            )

        if not request.material.source_date_trusted:
            return ReadPermission(
                False,
                "Source date cannot establish historical status",
                self.policy_version,
            )

        if request.material.source_date is None:
            return ReadPermission(
                False, "Trusted source date is missing", self.policy_version
            )

        if request.material.source_date >= self.cutoff_date:
            return ReadPermission(
                False,
                "Material is not eligible under the legacy cutoff",
                self.policy_version,
            )

        if request.effective_date < request.material.source_date:
            return ReadPermission(
                False,
                "Effective date precedes the trusted source date",
                self.policy_version,
            )

        return ReadPermission(True, "Approved historical investigation read", self.policy_version)


class CurrentPolicyTransferReviewer:
    """Default result decision for material transferred under the current policy."""

    def __init__(self, policy_version: str = "current-transfer-policy"):
        self.policy_version = policy_version

    def review_transfer(
        self,
        request: TransferRequest,
        source: FormatProfile,
        result: FormatProfile,
    ) -> TransferReview:
        if not result.encrypted:
            return TransferReview(
                False, "New archive must use current encryption", self.policy_version
            )

        if result.uses_legacy_encryption:
            return TransferReview(
                False,
                "Transfer result still uses a legacy algorithm",
                self.policy_version,
            )

        if result.encryption_type not in CURRENT_ENCRYPTION_TYPES:
            return TransferReview(
                False,
                "Transfer result does not use a current encryption type",
                self.policy_version,
            )

        return TransferReview(True, "Transfer result satisfies the current policy", self.policy_version)


class ArchivePolicyGate:
    def __init__(
        self,
        read_permission_checker: ReadPermissionChecker,
        transfer_reviewer: TransferResultReviewer,
    ):
        self.read_permission_checker = read_permission_checker
        self.transfer_reviewer = transfer_reviewer

    def authorize_read(
        self, request: ReadRequest, profile: FormatProfile
    ) -> ReadPermission:
        decision = self.read_permission_checker.authorize_read(request, profile)
        if not decision.allowed:
            raise ReadPermissionDeniedError(decision.reason or "Read permission denied")
        return decision

    def review_transfer(
        self,
        request: TransferRequest,
        source: FormatProfile,
        result: FormatProfile,
    ) -> TransferReview:
        review = self.transfer_reviewer.review_transfer(request, source, result)
        if not review.accepted:
            raise TransferRejectedError(review.reason or "Transfer rejected")
        return review


KeyLoader = Callable[[Any], None]


class ArchiveService:
    """Orchestrate format identification, policy checks, and the existing read API."""

    def __init__(self, gate: ArchivePolicyGate):
        self.gate = gate

    def read_for_investigation(
        self,
        material: ArchiveMaterial,
        purpose: str,
        effective_date: date,
        key_loader: KeyLoader,
    ) -> tuple[FormatProfile, ReadPermission, Any]:
        profile = identify_format(material.stream)
        permission = self.gate.authorize_read(
            ReadRequest(material, purpose, effective_date), profile
        )
        key_loader(profile.office_file)
        output = io.BytesIO()
        profile.office_file.decrypt(output)
        output.seek(0)
        return profile, permission, output

    def transfer(
        self,
        material: ArchiveMaterial,
        destination: str,
        effective_date: date,
        key_loader: KeyLoader,
    ) -> tuple[TransferReview, FormatProfile, FormatProfile, Any]:
        source_profile, _, decrypted = self.read_for_investigation(
            material,
            "policy-controlled transfer",
            effective_date,
            key_loader,
        )
        result_profile = identify_format(decrypted)
        review = self.gate.transfer_reviewer.review_transfer(
            TransferRequest(material, destination, effective_date),
            source_profile,
            result_profile,
        )
        return review, source_profile, result_profile, decrypted

    def copy_for_new_archive(
        self,
        material: ArchiveMaterial,
        destination: str,
        effective_date: date,
    ) -> TransferReview:
        material.stream.seek(0)
        source_profile = identify_format(material.stream)
        if hasattr(material.stream, "getvalue"):
            source_data = material.stream.getvalue()
        else:
            source_data = material.stream.read()
        copied = io.BytesIO(source_data)
        result_profile = identify_format(copied)
        return self.gate.transfer_reviewer.review_transfer(
            TransferRequest(material, destination, effective_date),
            source_profile,
            result_profile,
        )
