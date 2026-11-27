"""YARA 规则 condition 离线保守比较工具。

基于 plyara 解析出的 condition_terms，仅支持普通布尔组合
（and / or / not / 括号 / true / false）与固定字符串引用（$a 这类），
对两版规则的检测适用范围做保守定级：

- 等价     : 两版 condition 布尔等价，无需升档
- 扩围     : 新版命中文集严格变大，需要升档复审
- 缩围     : 新版命中文集严格变小，无需升档
- 不可比   : 互有增删，两个方向都不蕴含，需人工复核
- 未知     : 含库函数调用、动态计数等不支持构造，留待人工

判定方法：把每个字符串引用按"字符串定义"（类型+值+修饰符）抽象成
独立布尔原子，在两版原子的并集上做真值表比较。原子数较少时这是
精确判定；对蕴含方向（扩围/缩围/等价）的结论是保守安全的——
全集赋值上成立的蕴含，在原子取值存在任何相关性时仍然成立。
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys

import plyara

VERDICT_EQUIVALENT = "等价"
VERDICT_EXPANDED = "扩围"
VERDICT_SHRUNK = "缩围"
VERDICT_INCOMPARABLE = "不可比"
VERDICT_UNKNOWN = "未知"

# 真值表规模上限：2^16 = 65536 种赋值，离线比较足够快。
MAX_ATOMS = 16

_STRING_REF = re.compile(r"^\$[A-Za-z0-9_]+$")


class UnsupportedCondition(Exception):
    """condition 中出现不支持离线比较的构造。"""


# AST 节点：
#   ("const", bool)
#   ("atom", key)            key 为字符串定义的规范化元组
#   ("not", node)
#   ("and", left, right)
#   ("or",  left, right)


def _string_key(string_def: dict) -> tuple:
    """把一条字符串定义规范化为可哈希的原子标识。

    按定义而非名字标识原子：两版规则中名字不同但定义相同的
    字符串视为同一原子；名字相同但定义被改动的视为不同原子。
    """
    value = " ".join(str(string_def.get("value", "")).split())
    modifiers = tuple(sorted(string_def.get("modifiers", [])))
    return (string_def.get("type", "text"), value, modifiers)


class _ConditionParser:
    """对 plyara 的 condition_terms 做递归下降解析（仅支持布尔子集）。"""

    def __init__(self, tokens, strings_by_name):
        self.tokens = tokens
        self.strings_by_name = strings_by_name
        self.pos = 0

    def parse(self):
        if not self.tokens:
            raise UnsupportedCondition("condition 为空")
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise UnsupportedCondition(f"无法解析的剩余记号: {self.tokens[self.pos]!r}")
        return node

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _parse_or(self):
        node = self._parse_and()
        while self._peek() == "or":
            self.pos += 1
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self._peek() == "and":
            self.pos += 1
            node = ("and", node, self._parse_not())
        return node

    def _parse_not(self):
        if self._peek() == "not":
            self.pos += 1
            return ("not", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self):
        tok = self._peek()
        if tok == "(":
            self.pos += 1
            node = self._parse_or()
            if self._peek() != ")":
                raise UnsupportedCondition("括号不匹配")
            self.pos += 1
            return node
        if tok in ("true", "false"):
            self.pos += 1
            return ("const", tok == "true")
        if tok is not None and _STRING_REF.match(tok):
            self.pos += 1
            if tok not in self.strings_by_name:
                raise UnsupportedCondition(f"引用了未定义的字符串 {tok}")
            return ("atom", _string_key(self.strings_by_name[tok]))
        raise UnsupportedCondition(f"不支持的记号: {tok!r}")


def _eval(node, env):
    kind = node[0]
    if kind == "const":
        return node[1]
    if kind == "atom":
        return env[node[1]]
    if kind == "not":
        return not _eval(node[1], env)
    if kind == "and":
        return _eval(node[1], env) and _eval(node[2], env)
    if kind == "or":
        return _eval(node[1], env) or _eval(node[2], env)
    raise AssertionError(f"未知节点: {kind}")


def _collect_atoms(node, acc):
    kind = node[0]
    if kind == "atom":
        acc.add(node[1])
    elif kind == "not":
        _collect_atoms(node[1], acc)
    elif kind in ("and", "or"):
        _collect_atoms(node[1], acc)
        _collect_atoms(node[2], acc)


def _parse_rule_condition(rule):
    """解析单条规则的 condition，返回 (ast, {atom_key: 显示名})。"""
    strings_by_name = {s["name"]: s for s in rule.get("strings", [])}
    ast = _ConditionParser(rule.get("condition_terms", []), strings_by_name).parse()
    names = {}
    for s in rule.get("strings", []):
        names.setdefault(_string_key(s), s["name"])
    return ast, names


def _format_env(env, names):
    parts = [
        f"{names.get(key, key)}={'1' if env[key] else '0'}"
        for key in env
    ]
    parts.sort()
    return ", ".join(parts)


def compare_conditions(old_rule, new_rule):
    """比较同一规则的新旧两版，返回 (verdict, reason)。"""
    try:
        old_ast, old_names = _parse_rule_condition(old_rule)
        new_ast, new_names = _parse_rule_condition(new_rule)
    except UnsupportedCondition as exc:
        return VERDICT_UNKNOWN, f"含不支持离线比较的构造（{exc}），留待人工复核"

    names = dict(new_names)
    names.update(old_names)  # 显示名优先用旧版，便于对照 diff

    atoms = set()
    _collect_atoms(old_ast, atoms)
    _collect_atoms(new_ast, atoms)
    atoms = sorted(atoms, key=str)
    if len(atoms) > MAX_ATOMS:
        return VERDICT_UNKNOWN, f"布尔原子过多（{len(atoms)} > {MAX_ATOMS}），留待人工复核"

    old_only_hit = None  # 旧真新假的赋值（存在则说明新版删掉了部分命中）
    new_only_hit = None  # 新真旧假的赋值（存在则说明新版扩出了部分命中）
    for bits in itertools.product((False, True), repeat=len(atoms)):
        env = dict(zip(atoms, bits))
        old_val = _eval(old_ast, env)
        new_val = _eval(new_ast, env)
        if old_val and not new_val and old_only_hit is None:
            old_only_hit = env
        if new_val and not old_val and new_only_hit is None:
            new_only_hit = env
        if old_only_hit is not None and new_only_hit is not None:
            break

    n = len(atoms)
    if old_only_hit is None and new_only_hit is None:
        return VERDICT_EQUIVALENT, (
            f"布尔结构等价：在 {n} 个字符串原子的全部赋值上两版 condition 真值表一致，无需升档"
        )
    if old_only_hit is None:
        return VERDICT_EXPANDED, (
            f"旧版命中文集是新版真子集（旧=>新恒成立），"
            f"新增命中例如：{_format_env(new_only_hit, names)}；检测范围扩大，需要升档复审"
        )
    if new_only_hit is None:
        return VERDICT_SHRUNK, (
            f"新版命中文集是旧版真子集（新=>旧恒成立），"
            f"被移除的命中例如：{_format_env(old_only_hit, names)}；范围收窄，无需升档"
        )
    return VERDICT_INCOMPARABLE, (
        f"互有增删，两个方向都不蕴含：仅旧版命中 {_format_env(old_only_hit, names)}；"
        f"仅新版命中 {_format_env(new_only_hit, names)}；需人工复核"
    )


def load_rules(path):
    parser = plyara.Plyara()
    with open(path, "r", encoding="utf-8") as fh:
        return parser.parse_string(fh.read())


def compare_files(old_path, new_path):
    """按规则名配对两个规则文件，返回结构化比较结果。"""
    old_rules = {r["rule_name"]: r for r in load_rules(old_path)}
    new_rules = {r["rule_name"]: r for r in load_rules(new_path)}

    results = []
    for name in sorted(set(old_rules) | set(new_rules)):
        if name not in old_rules:
            results.append({"rule": name, "verdict": "新增规则",
                            "reason": "旧文件中不存在，整体属于新增检测能力"})
        elif name not in new_rules:
            results.append({"rule": name, "verdict": "删除规则",
                            "reason": "新文件中已移除"})
        else:
            verdict, reason = compare_conditions(old_rules[name], new_rules[name])
            results.append({"rule": name, "verdict": verdict, "reason": reason})
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="YARA 规则 condition 离线保守比较（等价/扩围/缩围/不可比/未知）")
    ap.add_argument("old_file", help="旧版规则文件")
    ap.add_argument("new_file", help="新版规则文件")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args(argv)

    results = compare_files(args.old_file, args.new_file)
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for item in results:
            print(f"[{item['verdict']}] {item['rule']}")
            print(f"    依据: {item['reason']}")
    # 需要升档或人工时退出码为 1，便于接入复审流水线。
    needs_attention = any(i["verdict"] in (VERDICT_EXPANDED, VERDICT_INCOMPARABLE,
                                           VERDICT_UNKNOWN, "新增规则")
                          for i in results)
    return 1 if needs_attention else 0


if __name__ == "__main__":
    sys.exit(main())
