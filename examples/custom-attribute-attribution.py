#!/usr/bin/env python3
"""Read-only custom-attribute attribution report for .NET metadata."""

import argparse
import json
from collections import OrderedDict

import dnfile

from dnfile.customattributes import analyze_custom_attributes


SECTIONS = (
    ("assembly", "1. 标记挂在程序集上"),
    ("member_only", "2. 只挂在成员上"),
    ("insufficient", "3. 一条引用不足以证明归属"),
)


def _token(value):
    return "?" if value is None else "0x{:08x}".format(value)


def _offset(value):
    return "?" if value is None else "0x{:x}".format(value)


def _identity(record):
    owner = record.constructor.owner
    if owner is None:
        return record.constructor.name, "constructor unresolved"
    if owner.assembly is not None:
        return owner.display_name, owner.assembly.canonical
    return owner.display_name, "{}:{}:{}#{}".format(
        owner.scope_kind, owner.scope_name, owner.table, owner.row_index)


def _arg_line(arg):
    label = arg.kind
    if arg.name:
        label += " " + arg.name
    value = repr(arg.value) if arg.decoded else "<unparsed>"
    return (
        "- `{}` `{}` = `{}`; blob `[0x{:x},0x{:x})`; file `[{}, {})`"
        .format(
            label, arg.type_name, value, arg.blob_offset, arg.end_blob_offset,
        _offset(arg.file_offset), _offset(arg.end_file_offset),
        )
    )


def _record_lines(record):
    lines = []
    parent = record.parent
    lines.append("### `{}`".format(record.type_display_name))
    lines.append("")
    lines.append("- 属性行: `CustomAttribute[{}]` token `{}` file `{}`".format(
        record.row_index, _token(record.token), _offset(record.row_file_offset)))
    lines.append("- 作用对象: `{}[{}]` token `{}` file `{}` {}".format(
        parent.table or "?", parent.row_index or "?", _token(parent.token),
        _offset(parent.file_offset), parent.name))
    verdict = {
        "assembly": "Parent 解析到 Assembly，标记作用于整个程序集。",
        "member_only": "Parent 不是 Assembly，只覆盖当前成员。",
        "insufficient": "引用链不足以确定构造器所属程序集，不能证明归属。",
    }.get(record.comparison, "未分类。")
    lines.append("- 结论: " + verdict)
    if parent.owner is not None:
        lines.append("- 成员所有者: `{}` ({})".format(
            parent.owner.display_name, parent.owner.scope_name))
    lines.append("- 构造器: `{}[{}]` token `{}` file `{}` signature file `{}`".format(
        record.constructor.table or "?", record.constructor.row_index or "?",
        _token(record.constructor.token), _offset(record.constructor.file_offset),
        _offset(record.constructor.signature_file_offset)))
    if record.constructor.owner is not None:
        lines.append("- 类型身份: `{}` scope `{}`".format(
            record.constructor.owner.display_name, record.constructor.owner.scope_name))
        lines.append("- 引用链: {}".format(" -> ".join(
            "`{}`".format(hop) for hop in record.constructor.owner.resolution_chain)))
    if record.notes:
        lines.append("- 备注: {}".format("; ".join(record.notes)))
    if record.blob.arguments:
        lines.append("- 可解释参数:")
        lines.extend("  " + _arg_line(arg) for arg in record.blob.arguments)
    else:
        lines.append("- 可解释参数: 无")
    if not record.blob.complete:
        lines.append("- 未解部分: `{}` 起始 blob offset `0x{:x}` file `{}`".format(
            record.blob.error or "incomplete",
            record.blob.error_offset or 0,
            _offset(record.blob.error_file_offset)))
        if record.blob.remaining_hex:
            lines.append("- 原始剩余: `{}`".format(record.blob.remaining_hex))
    return lines


def render_markdown(records, source):
    lines = ["# .NET 自定义特性归属核对", ""]
    lines.append("- 样本: `{}`".format(source))
    lines.append("- 方式: dnfile 只读解析; 未执行样本代码")
    lines.append("- 偏移: `blob` 为相对 CA 值负载起点, `file` 为原始文件绝对偏移")
    for key, title in SECTIONS:
        selected = [r for r in records if r.comparison == key]
        lines.extend(["", "## " + title, ""])
        if not selected:
            lines.append("无。")
            continue
        groups = OrderedDict()
        for record in selected:
            groups.setdefault(_identity(record), []).append(record)
        for (display, scope), group in groups.items():
            lines.append("### `{}`".format(display))
            lines.append("")
            lines.append("- 程序集/作用域: `{}`".format(scope))
            lines.append("")
            for record in group:
                lines.extend(_record_lines(record)[2:])
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", help="path to a .NET PE file (read-only)")
    parser.add_argument("--name", help="only attributes whose display name contains this text")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    args = parser.parse_args()
    pe = dnfile.dnPE(args.sample)
    if not pe.net or not pe.net.mdtables:
        raise SystemExit("not a .NET assembly or metadata could not be parsed")
    records = analyze_custom_attributes(pe)
    if args.name:
        records = [r for r in records if args.name in r.type_display_name]
    if args.json:
        print(json.dumps([r.to_dict() for r in records], indent=2, ensure_ascii=False))
    else:
        print(render_markdown(records, args.sample))


if __name__ == "__main__":
    main()
