import cbor2
import pytest

from pycose.keys import EC2Key
from pycose.messages.sign1message import Sign1Message

from receipt_ingestion import (
    DeviceDeclaration,
    ReceiptIngestionService,
    ReceiptStatus,
)

KID = b"shared-test-key"
ALL_MATERIALS = ("delivery_note", "acceptance_form")


def make_key():
    return EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})


def sign_receipt(key, kid=KID, **overrides):
    payload = {
        "receipt_id": "r-1",
        "device_id": "dev-1",
        "batch_id": "batch-a",
        "task_id": "task-1",
        "commitment": b"commit-1",
    }
    payload.update(overrides)
    msg = Sign1Message(phdr={"ALG": "ES256"}, uhdr={"KID": kid},
                       payload=cbor2.dumps(payload))
    msg.key = key
    return msg.encode()


def declaration(device_id="dev-1", batch_id="batch-a", purpose="delivery",
                tasks=("task-1",), commitment=b"commit-1",
                materials=ALL_MATERIALS):
    return DeviceDeclaration(device_id=device_id, batch_id=batch_id,
                             purpose=purpose, task_scope=frozenset(tasks),
                             commitment=commitment, materials=tuple(materials))


@pytest.fixture
def key():
    return make_key()


@pytest.fixture
def service(key):
    svc = ReceiptIngestionService()
    svc.register_key(KID, key)
    return svc


def test_valid_receipt_is_settled(service, key):
    service.confirm_device(declaration())
    result = service.ingest(sign_receipt(key))
    assert result.status is ReceiptStatus.SETTLED
    assert result.settlement.task_id == "task-1"
    assert service.settlements["r-1"].device_id == "dev-1"


def test_batch_ingest(service, key):
    service.confirm_device(declaration())
    receipts = [sign_receipt(key, receipt_id="r-%d" % i) for i in range(3)]
    results = service.ingest_batch(receipts)
    assert [r.status for r in results] == [ReceiptStatus.SETTLED] * 3
    assert len(service.settlements) == 3


def test_valid_signature_but_out_of_scope_task_is_rejected(service, key):
    # 过去只查签名时这条回执会入库；现在任务不在范围内必须拒绝
    service.confirm_device(declaration(tasks=("task-1",)))
    result = service.ingest(sign_receipt(key, task_id="task-99"))
    assert result.status is ReceiptStatus.REJECTED
    assert service.settlements == {}


def test_commitment_mismatch_is_rejected(service, key):
    service.confirm_device(declaration(commitment=b"commit-1"))
    result = service.ingest(sign_receipt(key, commitment=b"commit-other"))
    assert result.status is ReceiptStatus.REJECTED
    assert service.settlements == {}


def test_invalid_signature_is_rejected(service):
    service.confirm_device(declaration())
    other_key = make_key()
    result = service.ingest(sign_receipt(other_key))
    assert result.status is ReceiptStatus.REJECTED
    assert service.settlements == {}


def test_unknown_kid_is_rejected(service, key):
    service.confirm_device(declaration())
    result = service.ingest(sign_receipt(key, kid=b"unknown-kid"))
    assert result.status is ReceiptStatus.REJECTED


def test_unmatched_receipt_pending_then_confirmed(service, key):
    # 回执先到，设备尚未确认 -> 未配对挂起
    result = service.ingest(sign_receipt(key))
    assert result.status is ReceiptStatus.PENDING
    assert service.settlements == {}

    # 材料齐备、设备确认后，先到的回执被核销
    followups = service.confirm_device(declaration())
    assert [r.status for r in followups] == [ReceiptStatus.SETTLED]
    assert service.settlements["r-1"].task_id == "task-1"
    assert service.awaiting == {}


def test_device_batch_or_purpose_change_preserves_settlements(service, key):
    service.confirm_device(declaration())
    assert service.ingest(sign_receipt(key)).status is ReceiptStatus.SETTLED

    # 设备换批并变更用途
    service.confirm_device(declaration(batch_id="batch-b", purpose="maintenance",
                                       tasks=("task-2",), commitment=b"commit-2"))
    # 已有核销保留
    assert service.settlements["r-1"].batch_id == "batch-a"
    # 旧承诺的回执不再核销
    stale = service.ingest(sign_receipt(key, receipt_id="r-2"))
    assert stale.status is ReceiptStatus.REJECTED
    # 新批次新承诺的回执正常核销
    fresh = service.ingest(sign_receipt(key, receipt_id="r-3", batch_id="batch-b",
                                        task_id="task-2", commitment=b"commit-2"))
    assert fresh.status is ReceiptStatus.SETTLED
    assert len(service.settlements) == 2


def test_revocation_does_not_cross_batches_sharing_key(service, key):
    # 两批设备共用同一测试公钥（同一 KID）
    service.confirm_device(declaration(device_id="dev-a", batch_id="batch-a",
                                       commitment=b"commit-a"))
    service.confirm_device(declaration(device_id="dev-b", batch_id="batch-b",
                                       commitment=b"commit-b"))

    assert service.ingest(sign_receipt(key, receipt_id="r-a", device_id="dev-a",
                                       commitment=b"commit-a")).status is ReceiptStatus.SETTLED
    assert service.ingest(sign_receipt(key, receipt_id="r-b", device_id="dev-b",
                                       batch_id="batch-b",
                                       commitment=b"commit-b")).status is ReceiptStatus.SETTLED

    # 撤销 batch-a 的 task-1 资格
    service.revoke_task("batch-a", "task-1")

    # 两批已有核销都不受影响
    assert set(service.settlements) == {"r-a", "r-b"}
    # batch-a 后续同任务回执被拒绝
    revoked = service.ingest(sign_receipt(key, receipt_id="r-a2", device_id="dev-a",
                                          commitment=b"commit-a"))
    assert revoked.status is ReceiptStatus.REJECTED
    # batch-b 同任务回执照常核销
    unaffected = service.ingest(sign_receipt(key, receipt_id="r-b2", device_id="dev-b",
                                             batch_id="batch-b", commitment=b"commit-b"))
    assert unaffected.status is ReceiptStatus.SETTLED
    assert set(service.settlements) == {"r-a", "r-b", "r-b2"}


def test_missing_materials_referred_to_declaration(service, key):
    # 设备已确认但签收材料不齐
    service.confirm_device(declaration(materials=("delivery_note",)))
    result = service.ingest(sign_receipt(key))
    assert result.status is ReceiptStatus.REFERRED
    # 指回原声明
    assert result.declaration is not None
    assert result.declaration.device_id == "dev-1"
    assert "acceptance_form" in result.reason
    assert service.settlements == {}

    # 材料补齐后重审，回执得以核销
    followups = service.confirm_device(declaration(materials=ALL_MATERIALS))
    assert [r.status for r in followups] == [ReceiptStatus.SETTLED]
    assert "r-1" in service.settlements
