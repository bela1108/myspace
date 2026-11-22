import enum
from dataclasses import dataclass
from typing import Optional, Tuple


class ReceiptStatus(enum.Enum):
    """回执入库结果状态。"""

    SETTLED = "settled"    # 核销完成
    PENDING = "pending"    # 未配对（设备不在已确认清单），等待材料齐备后确认
    REFERRED = "referred"  # 缺签收材料，指回原声明
    REJECTED = "rejected"  # 签名、承诺或任务范围不符，拒绝入库


@dataclass(frozen=True)
class DeviceDeclaration:
    """经过确认的设备清单条目（即原声明）。"""

    device_id: str
    batch_id: str
    purpose: str
    task_scope: frozenset
    commitment: bytes
    materials: Tuple[str, ...] = ()

    def missing_materials(self, required: Tuple[str, ...]) -> Tuple[str, ...]:
        return tuple(m for m in required if m not in self.materials)


@dataclass(frozen=True)
class Settlement:
    """核销记录。一旦生成即不可变，换批、用途变更或资格撤销都不影响。"""

    receipt_id: str
    device_id: str
    batch_id: str
    task_id: str
    commitment: bytes


@dataclass(frozen=True)
class IngestionResult:
    status: ReceiptStatus
    reason: str
    receipt_id: Optional[str] = None
    settlement: Optional[Settlement] = None
    declaration: Optional[DeviceDeclaration] = None
