"""Offline ABI cross-check for Windows extension DLL exports using pefile.

Callers are split into two explicitly enumerated populations:
* by-name callers bind through the export name table;
* by-ordinal callers bind through the ordinal/function table only.

For every synthetic caller reference the checker compares the export
declarations of the old and new DLL, records duplicate-name aliases,
explicit forwarders and references whose target cannot be confirmed
offline, and emits a verdict independent for the two binding styles.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pefile

from .statuses import STATUS_TEXT, STABLE, RENAMED_ORDINAL_KEPT, ORDINAL_STABLE
from .statuses import ALIAS_AMBIGUOUS, FORWARDED_CONFIRMED, FORWARDED_UNCONFIRMED
from .statuses import REMOVED, UNRESOLVED

@dataclass(frozen=True)
class ExportEntry:
    """One export slot as parsed from a DLL export directory."""

    ordinal: int
    name: str | None
    forwarder: str | None
    rva: int

    @property
    def is_forwarder(self) -> bool:
        return self.forwarder is not None

    @property
    def is_named(self) -> bool:
        return self.name is not None


@dataclass
class VersionExports:
    """Parsed export declarations of one DLL version."""

    module: str
    path: Path
    dll_name: str
    ordinal_base: int
    by_ordinal: dict[int, ExportEntry]
    by_name: dict[str, list[ExportEntry]]
    warnings: list[str] = field(default_factory=list)

    def names(self) -> list[str]:
        return sorted(self.by_name)


def _decode(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    return raw.decode("ascii", errors="replace")


def load_exports(path: str | Path, module: str | None = None) -> VersionExports:
    """Load and index the export directory of one DLL version."""

    path = Path(path)
    pe = pefile.PE(str(path))
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        pe.close()
        raise ValueError(f"{path} has no export directory")

    directory = pe.DIRECTORY_ENTRY_EXPORT
    dll_name = _decode(directory.name) or path.name
    base = directory.struct.Base
    by_ordinal: dict[int, ExportEntry] = {}
    by_name: dict[str, list[ExportEntry]] = {}

    for symbol in directory.symbols:
        entry = ExportEntry(
            ordinal=symbol.ordinal,
            name=_decode(symbol.name),
            forwarder=_decode(symbol.forwarder),
            rva=symbol.address,
        )
        by_ordinal.setdefault(entry.ordinal, entry)
        if entry.name is not None:
            by_name.setdefault(entry.name, []).append(entry)

    warnings = list(pe.get_warnings())
    pe.close()
    return VersionExports(
        module=module or path.stem,
        path=path,
        dll_name=dll_name,
        ordinal_base=base,
        by_ordinal=by_ordinal,
        by_name=by_name,
        warnings=warnings,
    )


@dataclass(frozen=True)
class CallerReference:
    """One synthetic caller entry from an explicit manifest."""

    caller: str
    binding: str  # "name" or "ordinal"
    target: str  # export name for by-name, ordinal string for by-ordinal
    note: str = ""

    @property
    def ordinal_value(self) -> int | None:
        if self.binding != "ordinal":
            return None
        return int(self.target.lstrip("#"))


def load_manifest(path: str | Path) -> list[CallerReference]:
    """Load an explicitly enumerated synthetic-caller manifest (JSON)."""

    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    references: list[CallerReference] = []
    for item in payload:
        binding = item["binding"]
        if binding not in ("name", "ordinal"):
            raise ValueError(f"unsupported binding: {binding}")
        references.append(
            CallerReference(
                caller=item["caller"],
                binding=binding,
                target=str(item["target"]),
                note=item.get("note", ""),
            )
        )
    return references


def split_forwarder(forwarder: str) -> tuple[str, str | None]:
    """Split ``MODULE.Symbol`` or ``MODULE.#17`` into (module, symbol)."""

    module, separator, symbol = forwarder.partition(".")
    if not separator:
        return module.strip().lower(), None
    return module.strip().lower(), symbol.strip()


def _forwarder_status(
    entry: ExportEntry, available_modules: set[str]
) -> str:
    target_module, _ = split_forwarder(entry.forwarder or "")
    if target_module in available_modules:
        return FORWARDED_CONFIRMED
    return FORWARDED_UNCONFIRMED


@dataclass
class ReferenceVerdict:
    """Verdict for one synthetic caller reference."""

    caller: str
    binding: str
    target: str
    status: str
    usable_on_old: bool
    old_resolved: bool
    new_resolved: bool
    old_ordinals: list[int]
    new_ordinals: list[int]
    forwarder: str | None
    detail: str

    def to_dict(self) -> dict:
        return {
            "caller": self.caller,
            "binding": self.binding,
            "target": self.target,
            "status": self.status,
            "status_text": STATUS_TEXT[self.status],
            "usable_on_old": self.usable_on_old,
            "old_resolved": self.old_resolved,
            "new_resolved": self.new_resolved,
            "old_ordinals": self.old_ordinals,
            "new_ordinals": self.new_ordinals,
            "forwarder": self.forwarder,
            "detail": self.detail,
        }


def _entry_forwarder(entry: ExportEntry | None) -> str | None:
    if entry is None:
        return None
    return entry.forwarder


def evaluate_name_reference(
    reference: CallerReference,
    old: VersionExports,
    new: VersionExports,
    available_modules: set[str],
) -> ReferenceVerdict:
    """Evaluate a caller that binds strictly by export name."""

    name = reference.target
    old_entries = old.by_name.get(name, [])
    new_entries = new.by_name.get(name, [])
    old_ordinals = sorted(entry.ordinal for entry in old_entries)
    new_ordinals = sorted(entry.ordinal for entry in new_entries)

    if not old_entries:
        status = UNRESOLVED
        detail = "该名称在旧版本导出表中不存在，按名调用无法解析"
        return ReferenceVerdict(reference.caller, "name", name, status, False,
                                False, bool(new_entries), old_ordinals,
                                new_ordinals, None, detail)

    if not new_entries:
        # Name gone in the new version. Check whether the same ordinal kept a
        # (renamed) slot: that is the "ordinal kept, name changed" case.
        kept = _find_renamed_slot(old_entries, new)
        if kept is not None:
            old_entry, new_entry = kept
            detail = (
                f"旧名 {name} 在新版本改名为 {new_entry.name}，"
                f"序号 {old_entry.ordinal} 槽位保留"
            )
            return ReferenceVerdict(reference.caller, "name", name,
                                    RENAMED_ORDINAL_KEPT, False, True, False,
                                    old_ordinals, [new_entry.ordinal],
                                    new_entry.forwarder, detail)
        detail = f"名称 {name} 在新版本被删除且无同序号槽位"
        return ReferenceVerdict(reference.caller, "name", name, REMOVED, False,
                                True, False, old_ordinals, [], None, detail)

    if len(old_entries) > 1 or len(new_entries) > 1:
        detail = "名称映射到多个序号，按名加载的具体身份存在歧义"
        forwarder = _entry_forwarder(new_entries[0])
        return ReferenceVerdict(reference.caller, "name", name,
                                ALIAS_AMBIGUOUS, False, True, True,
                                old_ordinals, new_ordinals, forwarder, detail)

    old_entry = old_entries[0]
    new_entry = new_entries[0]
    if old_entry.forwarder is not None or new_entry.forwarder is not None:
        forwarder = new_entry.forwarder or old_entry.forwarder
        status = _forwarder_status(new_entry, available_modules)
        detail = f"名称 {name} 为显式前转：{forwarder}"
        return ReferenceVerdict(reference.caller, "name", name, status,
                                status == FORWARDED_CONFIRMED, True, True,
                                old_ordinals, new_ordinals, forwarder, detail)

    detail = f"名称 {name} 在新旧版本均存在（序号 {old_entry.ordinal}）"
    return ReferenceVerdict(reference.caller, "name", name, STABLE, True,
                            True, True, old_ordinals, new_ordinals, None,
                            detail)


def _find_renamed_slot(
    old_entries: list[ExportEntry], new: VersionExports
) -> tuple[ExportEntry, ExportEntry] | None:
    """Return an old/new pair sharing an ordinal whose name changed."""

    for old_entry in old_entries:
        new_entry = new.by_ordinal.get(old_entry.ordinal)
        if new_entry is None:
            continue
        if new_entry.name != old_entry.name:
            return old_entry, new_entry
    return None


def evaluate_ordinal_reference(
    reference: CallerReference,
    old: VersionExports,
    new: VersionExports,
    available_modules: set[str],
) -> ReferenceVerdict:
    """Evaluate a caller that binds strictly by export ordinal."""

    ordinal = reference.ordinal_value
    assert ordinal is not None
    old_entry = old.by_ordinal.get(ordinal)
    new_entry = new.by_ordinal.get(ordinal)
    target = reference.target

    if old_entry is None:
        detail = f"序号 {ordinal} 在旧版本导出地址表中不存在"
        return ReferenceVerdict(reference.caller, "ordinal", target,
                                UNRESOLVED, False, False, new_entry is not None,
                                [], [ordinal] if new_entry else [],
                                _entry_forwarder(new_entry), detail)

    if new_entry is None:
        detail = f"序号 {ordinal} 在新版本被删除，旧系统按序号调用将失败"
        return ReferenceVerdict(reference.caller, "ordinal", target, REMOVED,
                                False, True, False, [ordinal], [],
                                old_entry.forwarder, detail)

    name_changed = old_entry.name != new_entry.name
    if new_entry.forwarder is not None or old_entry.forwarder is not None:
        forwarder = new_entry.forwarder or old_entry.forwarder
        status = _forwarder_status(new_entry, available_modules)
        detail = f"序号 {ordinal} 为显式前转：{forwarder}"
        return ReferenceVerdict(reference.caller, "ordinal", target, status,
                                status == FORWARDED_CONFIRMED, True, True,
                                [ordinal], [ordinal], forwarder, detail)

    if name_changed:
        detail = (
            f"序号 {ordinal} 保留，但名称由 {old_entry.name} 改为 "
            f"{new_entry.name}；按序号调用在旧系统仍可用"
        )
        return ReferenceVerdict(reference.caller, "ordinal", target,
                                ORDINAL_STABLE, True, True, True, [ordinal],
                                [ordinal], None, detail)

    detail = f"序号 {ordinal} 在新旧版本均存在，名称未变（{old_entry.name}）"
    return ReferenceVerdict(reference.caller, "ordinal", target, STABLE, True,
                            True, True, [ordinal], [ordinal], None, detail)


@dataclass
class ReconcileReport:
    """Full result of an old-vs-new export reconciliation."""

    module: str
    old_dll: str
    new_dll: str
    verdicts: list[ReferenceVerdict]
    declaration_diff: dict[str, list[dict]]
    forwarders: list[dict]
    available_modules: list[str]

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "old_dll": self.old_dll,
            "new_dll": self.new_dll,
            "available_modules": self.available_modules,
            "verdicts": [verdict.to_dict() for verdict in self.verdicts],
            "declaration_diff": self.declaration_diff,
            "forwarders": self.forwarders,
        }


def _declaration_diff(old: VersionExports, new: VersionExports) -> dict[str, list[dict]]:
    added: list[dict] = []
    removed: list[dict] = []
    renamed_ordinal_kept: list[dict] = []
    stable: list[dict] = []

    for ordinal, old_entry in sorted(old.by_ordinal.items()):
        new_entry = new.by_ordinal.get(ordinal)
        payload = {
            "ordinal": ordinal,
            "old_name": old_entry.name,
            "new_name": new_entry.name if new_entry else None,
            "old_forwarder": old_entry.forwarder,
            "new_forwarder": new_entry.forwarder if new_entry else None,
        }
        if new_entry is None:
            removed.append(payload)
        elif old_entry.name != new_entry.name:
            renamed_ordinal_kept.append(payload)
        else:
            stable.append(payload)

    for ordinal, new_entry in sorted(new.by_ordinal.items()):
        if ordinal not in old.by_ordinal:
            added.append({
                "ordinal": ordinal,
                "new_name": new_entry.name,
                "new_forwarder": new_entry.forwarder,
            })

    return {
        "added": added,
        "removed": removed,
        "renamed_ordinal_kept": renamed_ordinal_kept,
        "stable": stable,
    }


def _collect_forwarders(
    versions: list[VersionExports], available_modules: set[str]
) -> list[dict]:
    rows: list[dict] = []
    for version in versions:
        for ordinal, entry in sorted(version.by_ordinal.items()):
            if entry.forwarder is None:
                continue
            target_module, symbol = split_forwarder(entry.forwarder)
            rows.append({
                "version": version.module,
                "ordinal": ordinal,
                "name": entry.name,
                "forwarder": entry.forwarder,
                "target_module": target_module,
                "target_symbol": symbol,
                "confirmed": target_module in available_modules,
            })
    return rows


def reconcile(
    old_path: str | Path,
    new_path: str | Path,
    manifest_path: str | Path,
    extra_module_paths: list[str | Path] | None = None,
) -> ReconcileReport:
    """Run the full offline ABI reconciliation for one extension module."""

    old = load_exports(old_path, module="old")
    new = load_exports(new_path, module="new")
    references = load_manifest(manifest_path)

    extra_paths = extra_module_paths or []
    extra_versions = [load_exports(path) for path in extra_paths]
    all_versions = [old, new, *extra_versions]
    available_modules = {
        version.dll_name.split(".")[0].lower() for version in all_versions
    }

    verdicts: list[ReferenceVerdict] = []
    for reference in references:
        if reference.binding == "name":
            verdict = evaluate_name_reference(
                reference, old, new, available_modules
            )
        else:
            verdict = evaluate_ordinal_reference(
                reference, old, new, available_modules
            )
        verdicts.append(verdict)

    return ReconcileReport(
        module=old.dll_name,
        old_dll=str(old.path),
        new_dll=str(new.path),
        verdicts=verdicts,
        declaration_diff=_declaration_diff(old, new),
        forwarders=_collect_forwarders(all_versions, available_modules),
        available_modules=sorted(available_modules),
    )


def render_report(report: ReconcileReport) -> str:
    """Render a human-readable Chinese report from a reconciliation result."""

    lines: list[str] = []
    lines.append(f"离线 ABI 核对报告：{report.module}")
    lines.append(f"旧版本：{report.old_dll}")
    lines.append(f"新版本：{report.new_dll}")
    lines.append(
        "离线模块集合：" + ", ".join(report.available_modules)
    )
    lines.append("")

    lines.append("== 导出声明差异 ==")
    diff = report.declaration_diff
    lines.append(f"稳定声明：{len(diff['stable'])} 项")
    lines.append(
        f"序号保留但改名：{len(diff['renamed_ordinal_kept'])} 项"
    )
    for row in diff["renamed_ordinal_kept"]:
        lines.append(
            f"  - 序号 {row['ordinal']}：{row['old_name']} -> {row['new_name']}"
        )
    lines.append(f"新版本删除：{len(diff['removed'])} 项")
    for row in diff["removed"]:
        lines.append(f"  - 序号 {row['ordinal']}：{row['old_name']}")
    lines.append(f"新版本新增：{len(diff['added'])} 项")
    for row in diff["added"]:
        lines.append(f"  - 序号 {row['ordinal']}：{row['new_name']}")
    lines.append("")

    lines.append("== 显式前转与目标确认 ==")
    if not report.forwarders:
        lines.append("（无显式前转）")
    for row in report.forwarders:
        confirmed = "已确认" if row["confirmed"] else "目标未确认"
        lines.append(
            f"  - [{row['version']}] 序号 {row['ordinal']} "
            f"{row['name']} -> {row['forwarder']}（{confirmed}）"
        )
    lines.append("")

    lines.append("== 合成调用者核对结论 ==")
    for verdict in report.verdicts:
        binding = "按名" if verdict.binding == "name" else "按序号"
        old_flag = "可解析" if verdict.old_resolved else "不可解析"
        new_flag = "可解析" if verdict.new_resolved else "不可解析"
        usable = "旧系统仍可用" if verdict.usable_on_old else "旧系统不可用"
        lines.append(
            f"  - {verdict.caller} [{binding} {verdict.target}] "
            f"{verdict.status}：{verdict.detail}"
        )
        lines.append(
            f"      旧版={old_flag} 新版={new_flag} 结论={usable}"
        )
    return "\n".join(lines)
