"""Machine-readable status identifiers for ABI verdicts."""

STABLE = "STABLE"
RENAMED_ORDINAL_KEPT = "RENAMED_ORDINAL_KEPT"
ORDINAL_STABLE = "ORDINAL_STABLE"
ALIAS_AMBIGUOUS = "ALIAS_AMBIGUOUS"
FORWARDED_CONFIRMED = "FORWARDED_CONFIRMED"
FORWARDED_UNCONFIRMED = "FORWARDED_UNCONFIRMED"
REMOVED = "REMOVED"
UNRESOLVED = "UNRESOLVED"

ALL_STATUSES = (
    STABLE,
    RENAMED_ORDINAL_KEPT,
    ORDINAL_STABLE,
    ALIAS_AMBIGUOUS,
    FORWARDED_CONFIRMED,
    FORWARDED_UNCONFIRMED,
    REMOVED,
    UNRESOLVED,
)


# Human-readable Chinese explanations for each status identifier.
STATUS_TEXT = {
    STABLE: "新旧版本同名同序号，身份稳定，旧系统可继续按名或按序号使用",
    RENAMED_ORDINAL_KEPT: "旧名称在新版本被改名，但同一序号槽位保留：按名调用失效，按序号调用在旧系统仍可用",
    ORDINAL_STABLE: "序号槽位在两版本均存在，按序号调用在旧系统仍可用",
    ALIAS_AMBIGUOUS: "同一名称对应多个序号（重名别名），按名解析存在歧义，需改用序号确认身份",
    FORWARDED_CONFIRMED: "显式前转，且前转目标模块在本次离线模块集合内，可继续追踪",
    FORWARDED_UNCONFIRMED: "显式前转，但前转目标模块不在离线集合，目标引用无法确认",
    REMOVED: "新版本已删除该导出声明，旧系统调用将失败",
    UNRESOLVED: "调用方引用的名称或序号在对应版本中不存在，无法解析",
}
