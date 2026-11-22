from typing import Dict, Iterable, List, Tuple

import cbor2

from pycose import headers
from pycose.exceptions import CoseException
from pycose.keys.cosekey import CoseKey
from pycose.messages.sign1message import Sign1Message

from receipt_ingestion.models import (
    DeviceDeclaration,
    IngestionResult,
    ReceiptStatus,
    Settlement,
)

REQUIRED_PAYLOAD_FIELDS = ("receipt_id", "device_id", "batch_id", "task_id", "commitment")

DEFAULT_REQUIRED_MATERIALS = ("delivery_note", "acceptance_form")


class ReceiptIngestionService:
    """离线设备签收回执入库服务。

    在 pycose 现有 COSE 签名校验之上，再核对已确认设备清单、
    任务范围与回执承诺，全部通过后才核销对应任务。
    """

    def __init__(self, required_materials: Tuple[str, ...] = DEFAULT_REQUIRED_MATERIALS):
        self.required_materials = tuple(required_materials)
        self._keys: Dict[bytes, CoseKey] = {}
        self._devices: Dict[str, DeviceDeclaration] = {}
        self._revoked_tasks: Dict[str, set] = {}
        self._awaiting: Dict[str, dict] = {}
        self._settlements: Dict[str, Settlement] = {}

    @property
    def settlements(self) -> Dict[str, Settlement]:
        return dict(self._settlements)

    @property
    def awaiting(self) -> Dict[str, dict]:
        return dict(self._awaiting)

    def register_key(self, kid: bytes, public_key: CoseKey) -> None:
        """登记验签公钥。不同批次可以共用同一个 KID/公钥。"""
        self._keys[bytes(kid)] = public_key

    def confirm_device(self, declaration: DeviceDeclaration) -> List[IngestionResult]:
        """登记或更新已确认设备（换批、用途变更均走此入口）。

        已有核销记录保持不变；更新后重审所有未决回执，
        让先到的未配对回执在材料齐备后得到确认。
        """
        self._devices[declaration.device_id] = declaration
        return self._reprocess_awaiting()

    def revoke_task(self, batch_id: str, task_id: str) -> None:
        """撤销某批次的任务资格，只影响该批次后续的核销，不回溯已有核销。"""
        self._revoked_tasks.setdefault(batch_id, set()).add(task_id)

    def ingest_batch(self, receipts: Iterable[bytes]) -> List[IngestionResult]:
        return [self.ingest(r) for r in receipts]

    def ingest(self, cose_bytes: bytes) -> IngestionResult:
        try:
            msg = Sign1Message.decode(cose_bytes)
        except Exception:
            return IngestionResult(ReceiptStatus.REJECTED, "无法解析的 COSE 回执")

        kid = msg.uhdr.get(headers.KID, msg.phdr.get(headers.KID))
        key = self._keys.get(kid)
        if key is None:
            return IngestionResult(ReceiptStatus.REJECTED, "未知的签名密钥标识")
        msg.key = key
        try:
            if not msg.verify_signature():
                return IngestionResult(ReceiptStatus.REJECTED, "COSE 签名校验失败")
        except CoseException:
            return IngestionResult(ReceiptStatus.REJECTED, "COSE 签名校验失败")

        try:
            payload = cbor2.loads(msg.payload)
        except Exception:
            return IngestionResult(ReceiptStatus.REJECTED, "回执内容无法解析")
        if not isinstance(payload, dict):
            return IngestionResult(ReceiptStatus.REJECTED, "回执内容格式不符")
        missing = [f for f in REQUIRED_PAYLOAD_FIELDS if f not in payload]
        if missing:
            return IngestionResult(ReceiptStatus.REJECTED, "回执缺少字段: %s" % ", ".join(missing))

        return self._evaluate(payload)

    def _evaluate(self, payload: dict) -> IngestionResult:
        receipt_id = payload["receipt_id"]

        existing = self._settlements.get(receipt_id)
        if existing is not None:
            return IngestionResult(ReceiptStatus.SETTLED, "回执已核销，幂等返回",
                                   receipt_id=receipt_id, settlement=existing)

        declaration = self._devices.get(payload["device_id"])
        if declaration is None:
            self._awaiting[receipt_id] = payload
            return IngestionResult(ReceiptStatus.PENDING, "设备不在已确认清单，等待材料齐备后确认",
                                   receipt_id=receipt_id)

        if payload["batch_id"] != declaration.batch_id or payload["commitment"] != declaration.commitment:
            self._awaiting.pop(receipt_id, None)
            return IngestionResult(ReceiptStatus.REJECTED, "回执承诺与已确认声明不符",
                                   receipt_id=receipt_id, declaration=declaration)

        revoked = self._revoked_tasks.get(declaration.batch_id, set())
        if payload["task_id"] not in declaration.task_scope or payload["task_id"] in revoked:
            self._awaiting.pop(receipt_id, None)
            return IngestionResult(ReceiptStatus.REJECTED, "任务超出设备任务范围或资格已撤销",
                                   receipt_id=receipt_id, declaration=declaration)

        missing_materials = declaration.missing_materials(self.required_materials)
        if missing_materials:
            self._awaiting[receipt_id] = payload
            return IngestionResult(ReceiptStatus.REFERRED,
                                   "缺少签收材料（%s），指回原声明" % "、".join(missing_materials),
                                   receipt_id=receipt_id, declaration=declaration)

        settlement = Settlement(receipt_id=receipt_id,
                                device_id=declaration.device_id,
                                batch_id=declaration.batch_id,
                                task_id=payload["task_id"],
                                commitment=payload["commitment"])
        self._settlements[receipt_id] = settlement
        self._awaiting.pop(receipt_id, None)
        return IngestionResult(ReceiptStatus.SETTLED, "核销完成",
                               receipt_id=receipt_id, settlement=settlement, declaration=declaration)

    def _reprocess_awaiting(self) -> List[IngestionResult]:
        results = []
        for payload in list(self._awaiting.values()):
            results.append(self._evaluate(payload))
        return results
