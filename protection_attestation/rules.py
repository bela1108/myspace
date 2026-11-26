"""Explicit, auditable normalization rules for protection claims.

The rule catalog is intentionally declarative: every normalized claim carries
the rule that accepted its recorded representation.  Rule packs allow a new
canonical notation while retaining adapters for historical approval values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


RULE_PACKS: dict[str, dict[str, str]] = {
    "archivist-rules-2024.1": {
        "hash_canonical": "hyphen",
        "label": "档案参数规则 v2024.1（历史连字符算法记法）",
    },
    "archivist-rules-2026.2": {
        "hash_canonical": "office_token",
        "label": "档案参数规则 v2026.2（Office/msoffcrypto 规范令牌）",
        "successor_to": "archivist-rules-2024.1",
    },
}


@dataclass
class NormalizedClaim:
    field: str
    accepted: bool
    ruleset_id: str
    rule_id: str | None = None
    rule_version: str | None = None
    rule_title: str | None = None
    canonical_value: Any = None
    notation_transform: bool = False
    historical_compatibility: bool = False
    accepted_forms: tuple[str, ...] = ()
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "ruleset_id": self.ruleset_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "rule_title": self.rule_title,
            "canonical_value": self.canonical_value,
            "notation_transform": self.notation_transform,
            "historical_compatibility": self.historical_compatibility,
            "accepted_forms": list(self.accepted_forms),
            "note": self.note,
        }


def _rule(
    ruleset_id: str,
    rule_id: str,
    version: str,
    title: str,
    canonical: Any,
    *,
    notation_transform: bool = False,
    historical: bool = False,
    accepted_forms: tuple[str, ...] = (),
    note: str | None = None,
) -> NormalizedClaim:
    return NormalizedClaim(
        field="",
        accepted=True,
        ruleset_id=ruleset_id,
        rule_id=rule_id,
        rule_version=version,
        rule_title=title,
        canonical_value=canonical,
        notation_transform=notation_transform,
        historical_compatibility=historical,
        accepted_forms=accepted_forms,
        note=note,
    )


def _reject(ruleset_id: str, field: str, value: Any, reason: str) -> NormalizedClaim:
    result = NormalizedClaim(
        field=field,
        accepted=False,
        ruleset_id=ruleset_id,
        rule_id="rule.rejected.v1",
        rule_version="1.0",
        rule_title="No explicitly accepted normalization rule matched",
        canonical_value=None,
        note=reason,
        accepted_forms=(),
    )
    return result


def _envelope(value: Any) -> tuple[Any, str | None]:
    if isinstance(value, dict) and "value" in value:
        return value["value"], value.get("unit")
    return value, None


def _parse_number_with_unit(value: Any) -> tuple[Any, str | None]:
    value, unit = _envelope(value)
    if unit is not None:
        return value, str(unit)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value, None
    if not isinstance(value, str):
        return value, None
    match = re.fullmatch(r"\s*([0-9]+)\s*([A-Za-z\u4e00-\u9fff_ ]*?)\s*", value)
    if not match:
        return value, None
    number = int(match.group(1))
    unit_text = match.group(2).strip() or None
    return number, unit_text


_BIT_UNITS = {"bit", "bits", "位", "比特"}
_BYTE_UNITS = {"byte", "bytes", "B", "字节"}


def _normalize_length(field: str, value: Any, ruleset_id: str, *, target: str) -> NormalizedClaim:
    number, unit = _parse_number_with_unit(value)
    if not isinstance(number, int) or isinstance(number, bool):
        return _reject(ruleset_id, field, value, "长度值必须是整数或带明确单位的整数字符串")

    unit_key = None if unit is None else unit.strip()
    if unit_key is None:
        source_unit = target
    elif unit_key in _BIT_UNITS:
        source_unit = "bits"
    elif unit_key in _BYTE_UNITS:
        source_unit = "bytes"
    else:
        return _reject(ruleset_id, field, value, f"不接受的长度单位: {unit_key}")

    if target == "bits":
        if source_unit == "bits":
            result = _rule(
                ruleset_id,
                "length.bits_identity",
                "1.0",
                "密钥长度的位值直接作为规范位长度",
                number,
                accepted_forms=("integer bits", "N bit(s)", "N 位/比特"),
            )
        else:
            result = _rule(
                ruleset_id,
                "length.bytes_to_bits",
                "1.0",
                "按 1 byte = 8 bits 转换密钥长度；这是单位记法换算",
                number * 8,
                notation_transform=True,
                accepted_forms=("N byte(s)", "N 字节"),
                note=f"{number} 字节 × 8 = {number * 8} 位",
            )
    else:
        if source_unit == "bytes":
            result = _rule(
                ruleset_id,
                "length.bytes_identity",
                "1.0",
                "字节长度直接作为规范字节数",
                number,
                accepted_forms=("integer bytes", "N byte(s)", "N 字节"),
            )
        elif number % 8 == 0:
            result = _rule(
                ruleset_id,
                "length.bits_to_bytes",
                "1.0",
                "按 8 bits = 1 byte 转换二进制长度",
                number // 8,
                notation_transform=True,
                accepted_forms=("N bit(s)", "N 位/比特"),
                note=f"{number} 位 ÷ 8 = {number // 8} 字节",
            )
        else:
            return _reject(ruleset_id, field, value, "位长度不能被 8 整除，无法规范化为字节")
    result.field = field
    return result


def _normalize_count(field: str, value: Any, ruleset_id: str) -> NormalizedClaim:
    if isinstance(value, int) and not isinstance(value, bool):
        result = _rule(
            ruleset_id,
            "count.integer_identity",
            "1.0",
            "迭代/轮次计数直接使用整数",
            value,
            accepted_forms=("integer"),
        )
        result.field = field
        return result
    if isinstance(value, str):
        match = re.search(r"[0-9]+", value)
        number = int(match.group(0)) if match else None
    else:
        number = None
    if isinstance(number, int):
        result = _rule(
            ruleset_id,
            "count.decorated_integer",
            "1.0",
            "从带单位或说明的文本中转写第一个十进制计数",
            number,
            notation_transform=True,
            accepted_forms=("N 轮", "N iterations", "N PBKDF2 rounds"),
            note="仅去除计数周围的说明文字，不改变计数值",
        )
        result.field = field
        return result
    return _reject(ruleset_id, field, value, "无法把计数记法规范化为整数")


_HASH_BASE = {
    "sha1": "SHA1",
    "sha": "SHA1",
    "securehashalgorithm1": "SHA1",
    "sha256": "SHA256",
    "sha2": "SHA256",
    "securehashalgorithm256": "SHA256",
    "sha512": "SHA512",
    "securehashalgorithm512": "SHA512",
}


def _normalize_hash(field: str, value: Any, ruleset_id: str, *, historical: bool) -> NormalizedClaim:
    if not isinstance(value, str):
        return _reject(ruleset_id, field, value, "哈希算法描述必须是字符串")
    original = value.strip()
    lowered = original.lower()
    compact = lowered
    for phrase in (
        "secure hash algorithm",
        "摘要算法",
        "哈希算法",
        "散列算法",
        "digest algorithm",
        "hash algorithm",
        "digest",
        "algorithm",
        " ",
        "_",
        "-",
    ):
        compact = compact.replace(phrase, "")
    base = _HASH_BASE.get(compact)
    if base is None:
        return _reject(ruleset_id, field, value, f"没有已批准的哈希算法别名规则: {original}")

    uses_hyphen = bool(re.fullmatch(r"(?i:SHA)\s*-\s*(1|256|512)", original))
    is_description = any(token in original for token in ("算法", "algorithm", "digest", "摘要")) and not uses_hyphen
    pack = RULE_PACKS[ruleset_id]
    if pack["hash_canonical"] == "hyphen":
        canonical = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512"}[base]
        if uses_hyphen and not any(x in original for x in ("算法", "algorithm", "digest")):
            rule_id = "hash.archival_hyphen_identity"
            title = "历史档案连字符算法名原样接受"
            transform = False
        elif is_description or "算法" in original:
            rule_id = "hash.description_to_archival_hyphen"
            title = "把人类可读算法说明转写为历史连字符规范名"
            transform = True
        else:
            rule_id = "hash.office_to_archival_hyphen"
            title = "把 Office 无连字符令牌转写为历史连字符规范名"
            transform = True
        result = _rule(
            ruleset_id,
            rule_id,
            "1.0",
            title,
            canonical,
            notation_transform=transform,
            historical=historical,
            accepted_forms=("SHA1/SHA-1", "SHA256/SHA-256", "SHA512/SHA-512", "中英文算法说明"),
        )
    else:
        canonical = base
        if uses_hyphen and not any(x in original for x in ("算法", "algorithm", "digest")):
            result = _rule(
                ruleset_id,
                "hash.v1_canonical_compat",
                "2.0",
                "新规范使用 Office 令牌；明确兼容 v2024.1 批准单中的连字符历史值",
                canonical,
                notation_transform=True,
                historical=True,
                accepted_forms=("SHA-1", "SHA-256", "SHA-512"),
                note=f"历史规范值 {original} 兼容转写为 {canonical}",
            )
        elif is_description or "算法" in original or " " in original.strip():
            result = _rule(
                ruleset_id,
                "hash.description_to_office_token",
                "2.0",
                "把人类可读算法说明转写为 Office 规范令牌",
                canonical,
                notation_transform=True,
                accepted_forms=("SHA-1 摘要算法", "SHA-1 digest algorithm"),
            )
        else:
            result = _rule(
                ruleset_id,
                "hash.office_token_identity",
                "2.0",
                "Office/msoffcrypto 算法令牌原样接受",
                canonical,
                accepted_forms=("SHA1", "SHA256", "SHA512"),
            )
        if historical and not result.historical_compatibility:
            result = NormalizedClaim(
                **{**result.__dict__, "historical_compatibility": True},
            )
    result.field = field
    return result


def _normalize_suite(field: str, value: Any, ruleset_id: str) -> NormalizedClaim:
    if isinstance(value, dict):
        cipher = str(value.get("cipher_algorithm", "")).strip().upper()
        bits = value.get("key_length_bits")
        chaining = str(value.get("cipher_chaining", "CBC")).removeprefix("ChainingMode").upper()
        if cipher != "AES" or not isinstance(bits, int):
            return _reject(ruleset_id, field, value, "结构化加密套件必须包含 AES 与整数 key_length_bits")
        canonical = f"AES-{bits}-{chaining}"
        result = _rule(
            ruleset_id,
            "suite.compose_office_attributes",
            "1.0",
            "由独立的密码算法、位数和链接模式属性组成规范套件名",
            canonical,
            accepted_forms=("cipherAlgorithm + keyBits + cipherChaining"),
        )
        result.field = field
        return result

    if not isinstance(value, str):
        return _reject(ruleset_id, field, value, "加密套件描述必须是字符串或结构化属性")
    description = value.replace("ChainingMode", "")
    match = re.search(r"AES[^0-9]*(128|192|256)", description, flags=re.IGNORECASE)
    if not match:
        return _reject(ruleset_id, field, value, f"无法识别 AES 套件描述: {value}")
    bits = int(match.group(1))
    chain_match = re.search(r"(CBC|ECB|GCM)", description, flags=re.IGNORECASE)
    chaining = chain_match.group(1).upper() if chain_match else "CBC"
    canonical = f"AES-{bits}-{chaining}"
    result = _rule(
        ruleset_id,
        "suite.aes_description",
        "1.0",
        "从 AES 位数和链接模式描述转写为 AES-位数-模式",
        canonical,
        notation_transform=canonical != value.strip(),
        accepted_forms=("AES-128-CBC", "AES128-CBC", "AES-128-CBC 分组加密"),
        note=None if canonical == value.strip() else "仅规范分隔符/后缀说明，密码属性不变",
    )
    result.field = field
    return result


def normalize_claim(
    field: str,
    value: Any,
    ruleset_id: str,
    *,
    historical: bool = False,
) -> NormalizedClaim:
    if ruleset_id not in RULE_PACKS:
        return _reject(ruleset_id, field, value, f"未知规则版本: {ruleset_id}")

    if field == "key_length_bits":
        return _normalize_length(field, value, ruleset_id, target="bits")
    if field in {"salt_length_bytes", "block_size_bytes", "hash_size_bytes"}:
        return _normalize_length(field, value, ruleset_id, target="bytes")
    if field == "spin_count":
        return _normalize_count(field, value, ruleset_id)
    if field == "hash_algorithm":
        return _normalize_hash(field, value, ruleset_id, historical=historical)
    if field == "encryption_suite":
        return _normalize_suite(field, value, ruleset_id)

    if field == "protection_kind":
        text = str(value).strip().lower()
        if "agile" in text:
            canonical = "agile"
        elif "standard" in text:
            canonical = "standard"
        else:
            return _reject(ruleset_id, field, value, "未知保护类型")
        result = _rule(
            ruleset_id,
            "enum.protection_kind_alias",
            "1.0",
            "把中英文保护类型说明规范化为 msoffcrypto 类型令牌",
            canonical,
            notation_transform=str(value) != canonical,
            accepted_forms=("agile", "Agile Encryption", "Agile 密码加密"),
        )
        result.field = field
        return result

    if field == "cipher_algorithm":
        text = re.sub(r"[\s_-]+", "", str(value)).upper()
        if text != "AES":
            return _reject(ruleset_id, field, value, "本批样例仅接受 AES 密码算法令牌")
        result = _rule(
            ruleset_id,
            "enum.cipher_algorithm",
            "1.0",
            "密码算法名称去除分隔符并大写",
            "AES",
            notation_transform=str(value) != "AES",
            accepted_forms=("AES", "aes", "A E S"),
        )
        result.field = field
        return result

    if field == "cipher_chaining":
        canonical = str(value).removeprefix("ChainingMode").replace("-", "").replace("_", "").upper()
        if canonical not in {"CBC", "ECB", "GCM"}:
            return _reject(ruleset_id, field, value, "未知或不接受的密码链接模式")
        result = _rule(
            ruleset_id,
            "enum.chaining_mode",
            "1.0",
            "移除 Office 的 ChainingMode 前缀并规范化大小写",
            canonical,
            notation_transform=str(value) != canonical,
            accepted_forms=("CBC", "ChainingModeCBC"),
        )
        result.field = field
        return result

    if isinstance(value, (str, int)):
        result = _rule(
            ruleset_id,
            "identity.scalar",
            "1.0",
            "未配置别名的标量按原值接受",
            value,
        )
        result.field = field
        return result
    return _reject(ruleset_id, field, value, "不支持的证词值类型")
