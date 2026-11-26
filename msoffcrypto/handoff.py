from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from struct import unpack
from typing import BinaryIO

import olefile

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.doc97 import _parseFib
from msoffcrypto.format.ooxml import _parseinfo
from msoffcrypto.format.ppt97 import (
    _parseCurrentUser,
    _parseCryptSession10Container,
    _parseUserEditAtom,
    construct_persistobjectdirectory,
)
from msoffcrypto.format.xls97 import _BIFFStream, recordNameNum


class HandoffStage(str, Enum):
    VERIFY_PROTECTION = "verify_protection"
    CONVERT = "convert"


class HandoffQueue(str, Enum):
    TRANSFERABLE = "transferable"
    VERIFIABLE = "verifiable"
    SIGNATURE_REQUIRED = "signature_required"


class ProtectionIdentificationError(exceptions.FileFormatError):
    pass


@dataclass(frozen=True)
class ProtectionProfile:
    format: str
    protection_type: str
    encrypted: bool
    key_types: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class Recipient:
    department_id: str
    department_name: str
    protection_types: frozenset[str]
    stages: frozenset[HandoffStage]

    def can_convert(self, protection_type: str) -> bool:
        return (
            protection_type in self.protection_types
            and HandoffStage.CONVERT in self.stages
        )


@dataclass(frozen=True)
class ExhibitAuthorization:
    exhibit_id: str
    protection_type: str
    stages: frozenset[HandoffStage]


@dataclass(frozen=True)
class HandoffPlan:
    recipient: Recipient
    stage: HandoffStage
    action: str


@dataclass(frozen=True)
class MissingCondition:
    code: str
    description: str
    required_stage: HandoffStage | None = None
    protection_type: str | None = None


@dataclass(frozen=True)
class HandoffDecision:
    exhibit_id: str
    path: str
    profile: ProtectionProfile
    queue: HandoffQueue
    plans: tuple[HandoffPlan, ...] = field(default_factory=tuple)
    missing_conditions: tuple[MissingCondition, ...] = field(default_factory=tuple)


class _PptData:
    def __init__(self, currentuser, powerpointdocument):
        self.currentuser = currentuser
        self.powerpointdocument = powerpointdocument


MISSING_CONDITION_TEXT = {
    "CASE_PROTECTION_MISMATCH": "授权表声明的保护类型与实际识别结果不一致，须重新核对并补签",
    "CASE_VERIFY_AUTH": "缺少证物级保护核验授权，备份组不能接管核验",
    "CASE_CONVERT_AUTH": "缺少证物级转换授权，任何部门都不能执行转换",
    "DEPARTMENT_CAPABILITY": "缺少具备该保护类型转换能力且获授权的部门",
    "UNRECOGNIZED_FORMAT": "格式或加密容器无法识别，须先补签专门鉴定授权",
}


def _missing(
    code: str,
    protection_type: str | None = None,
    stage: HandoffStage | None = None,
) -> MissingCondition:
    return MissingCondition(
        code=code,
        description=MISSING_CONDITION_TEXT[code],
        required_stage=stage,
        protection_type=protection_type,
    )


def _legacy_doc_type(ole: olefile.OleFileIO) -> str:
    with ole.openstream("wordDocument") as stream:
        fib = _parseFib(stream)

    if fib.base.fEncrypted != 1:
        return "plain"
    if fib.base.fObfuscation == 1:
        return "xor_obfuscation"

    table_name = "1Table" if fib.base.fWhichTblStm == 1 else "0Table"
    with ole.openstream(table_name) as table:
        version_major, version_minor = unpack("<HH", table.read(4))

    if version_major == 0x0001 and version_minor == 0x0001:
        return "rc4"
    if version_major in (0x0002, 0x0003, 0x0004) and version_minor == 0x0002:
        return "rc4_cryptoapi"
    return "unknown_legacy_encryption"


def _legacy_xls_type(ole: olefile.OleFileIO) -> str:
    with ole.openstream("Workbook") as raw_workbook:
        workbook = _BIFFStream(raw_workbook)
        record_id, size = unpack("<HH", workbook.data.read(4))
        if record_id != 2057:
            raise ProtectionIdentificationError(
                "Workbook stream does not start with a BOF record"
            )
        workbook.data.read(size)
        if not workbook.has_record(recordNameNum["FilePass"]):
            return "plain"

        workbook.skip_to(recordNameNum["FilePass"])
        (encryption_type,) = unpack("<H", workbook.data.read(2))
        if encryption_type == 0x0000:
            return "xor_obfuscation"
        if encryption_type != 0x0001:
            return "unknown_legacy_encryption"
        version_major, version_minor = unpack("<HH", workbook.data.read(4))

    if version_major == 0x0001 and version_minor == 0x0001:
        return "rc4"
    if version_major in (0x0002, 0x0003, 0x0004) and version_minor == 0x0002:
        return "rc4_cryptoapi"
    return "unknown_legacy_encryption"


def _legacy_ppt_type(ole: olefile.OleFileIO) -> str:
    with ole.openstream("Current User") as current_user_stream, ole.openstream(
        "PowerPoint Document"
    ) as document_stream:
        current_user = _parseCurrentUser(current_user_stream)
        document_stream.seek(current_user.currentuseratom.offsetToCurrentEdit)
        user_edit_atom = _parseUserEditAtom(document_stream)
        if user_edit_atom.rh.recLen != 0x00000020:
            return "plain"

        current_user_stream.seek(0)
        document_stream.seek(0)
        persist_directory = construct_persistobjectdirectory(
            _PptData(current_user_stream, document_stream)
        )
        session_offset = persist_directory[user_edit_atom.encryptSessionPersistIdRef]
        document_stream.seek(session_offset)
        crypt_session = _parseCryptSession10Container(document_stream)
        version_major, version_minor = unpack("<HH", crypt_session.data[:4])

    if version_major in (0x0002, 0x0003, 0x0004) and version_minor == 0x0002:
        return "rc4_cryptoapi"
    return "unknown_legacy_encryption"


def inspect_protection(file: BinaryIO) -> ProtectionProfile:
    file.seek(0)
    if not olefile.isOleFile(file):
        try:
            office_file = OfficeFile(file)
        except exceptions.FileFormatError as exc:
            raise ProtectionIdentificationError(str(exc)) from exc
        if office_file.format != "ooxml" or office_file.type != "plain":
            raise ProtectionIdentificationError(
                "Unexpected non-OLE encrypted Office container"
            )
        return ProtectionProfile(
            format="ooxml",
            protection_type="plain",
            encrypted=False,
            key_types=tuple(office_file.keyTypes),
            detail="Unencrypted OOXML package",
        )

    ole = olefile.OleFileIO(file)
    try:
        if ole.exists("EncryptionInfo"):
            with ole.openstream("EncryptionInfo") as stream:
                encryption_type, _info = _parseinfo(stream)
            return ProtectionProfile(
                format="ooxml",
                protection_type=f"ecma376_{encryption_type}",
                encrypted=True,
                key_types=(
                    ("password", "secret_key")
                    if encryption_type == "standard"
                    else ("password", "private_key", "secret_key")
                ),
                detail=f"ECMA-376 {encryption_type} encryption",
            )

        if ole.exists("wordDocument"):
            office_format = "doc97"
            protection_type = _legacy_doc_type(ole)
        elif ole.exists("Workbook"):
            office_format = "xls97"
            protection_type = _legacy_xls_type(ole)
        elif ole.exists("PowerPoint Document"):
            office_format = "ppt97"
            protection_type = _legacy_ppt_type(ole)
        else:
            raise ProtectionIdentificationError("Unrecognized OLE Office container")
    finally:
        ole.close()

    return ProtectionProfile(
        format=office_format,
        protection_type=protection_type,
        encrypted=protection_type != "plain",
        key_types=("password",) if protection_type != "plain" else (),
        detail=(
            "Legacy binary Office protection"
            if protection_type != "plain"
            else "Unencrypted legacy Office file"
        ),
    )


def inspect_protection_file(path: str | Path) -> ProtectionProfile:
    with open(path, "rb") as file:
        return inspect_protection(file)


class HandoffPlanner:
    def __init__(
        self,
        recipients: list[Recipient],
        backup_team: Recipient,
        authorizations: list[ExhibitAuthorization],
    ):
        self.recipients = sorted(
            recipients, key=lambda recipient: recipient.department_id
        )
        self.backup_team = backup_team
        self.authorizations = {
            authorization.exhibit_id: authorization for authorization in authorizations
        }

    def plan(
        self,
        exhibit_id: str,
        path: str | Path,
        profile: ProtectionProfile | None = None,
    ) -> HandoffDecision:
        try:
            actual_profile = profile or inspect_protection_file(path)
        except ProtectionIdentificationError as exc:
            actual_profile = ProtectionProfile(
                format="unknown",
                protection_type="unrecognized",
                encrypted=False,
                key_types=(),
                detail=str(exc),
            )
        if actual_profile.protection_type in {
            "unrecognized",
            "unknown_legacy_encryption",
        }:
            return HandoffDecision(
                exhibit_id=exhibit_id,
                path=str(path),
                profile=actual_profile,
                queue=HandoffQueue.SIGNATURE_REQUIRED,
                missing_conditions=(
                    _missing("UNRECOGNIZED_FORMAT", actual_profile.protection_type),
                ),
            )

        authorization = self.authorizations.get(exhibit_id)
        missing: list[MissingCondition] = []
        if authorization is None:
            missing.append(
                _missing(
                    "CASE_CONVERT_AUTH",
                    actual_profile.protection_type,
                    HandoffStage.CONVERT,
                )
            )
            if actual_profile.encrypted:
                missing.append(
                    _missing(
                        "CASE_VERIFY_AUTH",
                        actual_profile.protection_type,
                        HandoffStage.VERIFY_PROTECTION,
                    )
                )
            return self._decision_without_case_authorization(
                exhibit_id, path, actual_profile, missing
            )

        type_matches = authorization.protection_type == actual_profile.protection_type
        if not type_matches:
            missing.append(
                _missing("CASE_PROTECTION_MISMATCH", actual_profile.protection_type)
            )

        if not type_matches:
            can_verify = False
        elif actual_profile.encrypted:
            can_verify = (
                actual_profile.protection_type in self.backup_team.protection_types
                and HandoffStage.VERIFY_PROTECTION in self.backup_team.stages
                and HandoffStage.VERIFY_PROTECTION in authorization.stages
            )
        else:
            can_verify = True
        if actual_profile.encrypted and type_matches and not can_verify:
            missing.append(
                _missing(
                    "CASE_VERIFY_AUTH",
                    actual_profile.protection_type,
                    HandoffStage.VERIFY_PROTECTION,
                )
            )

        can_convert = type_matches and HandoffStage.CONVERT in authorization.stages
        if not can_convert:
            missing.append(
                _missing(
                    "CASE_CONVERT_AUTH",
                    actual_profile.protection_type,
                    HandoffStage.CONVERT,
                )
            )

        capable_recipients = [
            recipient
            for recipient in self.recipients
            if recipient.can_convert(actual_profile.protection_type)
        ]
        if can_convert and not capable_recipients:
            missing.append(
                _missing(
                    "DEPARTMENT_CAPABILITY",
                    actual_profile.protection_type,
                    HandoffStage.CONVERT,
                )
            )

        if not can_verify:
            queue = HandoffQueue.SIGNATURE_REQUIRED
            plans: tuple[HandoffPlan, ...] = ()
        elif not (can_convert and capable_recipients):
            queue = HandoffQueue.VERIFIABLE
            plans = (
                HandoffPlan(
                    recipient=self.backup_team,
                    stage=HandoffStage.VERIFY_PROTECTION,
                    action="核验保护类型、固定元数据并等待转换补签",
                ),
            )
        else:
            queue = HandoffQueue.TRANSFERABLE
            plans = tuple(
                HandoffPlan(
                    recipient=recipient,
                    stage=HandoffStage.CONVERT,
                    action="连同保护核验记录转交转换",
                )
                for recipient in capable_recipients
            )

        return HandoffDecision(
            exhibit_id=exhibit_id,
            path=str(path),
            profile=actual_profile,
            queue=queue,
            plans=plans,
            missing_conditions=tuple(self._deduplicate_missing(missing)),
        )

    def _decision_without_case_authorization(
        self,
        exhibit_id: str,
        path: str | Path,
        profile: ProtectionProfile,
        missing: list[MissingCondition],
    ) -> HandoffDecision:
        return HandoffDecision(
            exhibit_id=exhibit_id,
            path=str(path),
            profile=profile,
            queue=HandoffQueue.SIGNATURE_REQUIRED,
            missing_conditions=tuple(self._deduplicate_missing(missing)),
        )

    @staticmethod
    def _deduplicate_missing(
        conditions: list[MissingCondition],
    ) -> list[MissingCondition]:
        seen: set[tuple[str, str | None, HandoffStage | None]] = set()
        result: list[MissingCondition] = []
        for condition in conditions:
            key = (
                condition.code,
                condition.protection_type,
                condition.required_stage,
            )
            if key not in seen:
                seen.add(key)
                result.append(condition)
        return result
