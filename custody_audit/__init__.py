"""
custody_audit
=============

离线的 EVTX 证物保管核对工具。

本包完全运行在本地，不访问网络。它把调用方提供的三类材料与源证物
(Windows EVTX 事件日志) 交叉核对，回答三个问题：

1. 源证物的哪些记录范围已经被长期保管人实际签收，可继续复查原文；
2. 哪些范围只移交了脱敏摘要，原始记录不再随外部清单流转；
3. 哪些范围尚未被任何有相应权限的保管人承接。

注意：上一任保管人仍持有同一份副本并不构成移交，只有落在记录范围上、
签收人具备相应权限且签收时间有效的回执才会被认可。
"""

from custody_audit.audit import (
    AuditConfig,
    AuditResult,
    FileReconciliation,
    HandoverReceipt,
    Custodian,
    ExternalManifest,
    ManifestEntry,
    reconcile,
)
from custody_audit.evtx_records import (
    RecordRange,
    RecordSummary,
    summarize_evtx,
)

__all__ = [
    "AuditConfig",
    "AuditResult",
    "FileReconciliation",
    "HandoverReceipt",
    "Custodian",
    "ExternalManifest",
    "ManifestEntry",
    "reconcile",
    "RecordRange",
    "RecordSummary",
    "summarize_evtx",
]
