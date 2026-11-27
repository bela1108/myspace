"""Report assembly and export for symbol evidence."""

import csv
import datetime
import io
import json
import os

from .debug import file_sha256, load_pe_image
from .evaluate import evaluate_claims
from .model import (
    DEBUG_RECORD_MATCH,
    DIGEST_VERIFIED,
    NAME_ONLY,
    NO_EVIDENCE,
    Claim,
    EvidenceLevel,
    SignoffEntry,
)
from .signoff import claims_from_signoff, load_claims, load_signoff

SCHEMA_VERSION = "symbol-evidence/1"


def _now():
    return (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    )


def _prepare_signoff(signoff):
    if signoff is None:
        return []
    if isinstance(signoff, list) and all(
        isinstance(item, SignoffEntry) for item in signoff
    ):
        return signoff
    return load_signoff(signoff)


def _prepare_claims(claims):
    if isinstance(claims, list) and all(isinstance(item, Claim) for item in claims):
        return claims
    return load_claims(claims)


class EvidenceReport:
    """The complete evidence report, with JSON/Markdown/CSV renderers."""

    def __init__(
        self,
        image,
        evidence,
        signoff_entries=None,
        generated_at=None,
        warnings=None,
        symbol_file=None,
    ):
        self.image = image
        self.evidence = list(evidence)
        self.signoff_entries = list(signoff_entries or [])
        self.generated_at = generated_at or _now()
        self.warnings = list(warnings or [])
        self.symbol_file = symbol_file or {}

    @property
    def verified_count(self):
        return sum(1 for item in self.evidence if item.verified)

    def _duplicate_display_names(self):
        groups = {}
        for item in self.evidence:
            key = item.claim.display_name.lower()
            groups.setdefault(key, []).append(item)
        duplicates = []
        for items in groups.values():
            if len(items) > 1:
                duplicates.append(
                    {
                        "display_name": items[0].claim.display_name,
                        "count": len(items),
                        "ids": [item.claim.export_id for item in items],
                        "verified_ids": [
                            item.claim.export_id for item in items if item.verified
                        ],
                        "note": "同名记录按记录 ID 独立保留，未合并",
                    }
                )
        return duplicates

    def summary(self):
        by_level = {
            NO_EVIDENCE: 0,
            NAME_ONLY: 0,
            DEBUG_RECORD_MATCH: 0,
            DIGEST_VERIFIED: 0,
        }
        for item in self.evidence:
            by_level[item.level] = by_level.get(item.level, 0) + 1
        duplicates = self._duplicate_display_names()
        return {
            "total": len(self.evidence),
            "verified": self.verified_count,
            "unverified": len(self.evidence) - self.verified_count,
            "complete_digest": sum(1 for item in self.evidence if item.digest_complete),
            "incomplete_digest": sum(
                1
                for item in self.evidence
                if item.claim.digest is not None and not item.digest_complete
            ),
            "missing_digest": sum(
                1 for item in self.evidence if item.claim.digest is None
            ),
            "by_level": by_level,
            "duplicate_display_names": duplicates,
            "statement": "只有签收材料提供完整且与声明一致的摘要时，记录才显示为已证实；"
            "仅有名称或仅调试身份吻合的记录不得写成已证实。",
        }

    def to_dict(self):
        records = [item.to_dict() for item in self.evidence]
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "image": self.image.to_dict(),
            "symbol_file": self.symbol_file,
            "evidence_levels": {
                "no_evidence": "无任何可关联证据",
                "name_only": "仅显示名/PDB 文件名匹配，不能证明构建身份",
                "debug_record_match": "PE 调试记录 GUID/Age（或 NB10/Age）与声明吻合",
                "digest_verified": "签收材料提供完整摘要且与声明一致",
            },
            "summary": self.summary(),
            "warnings": self.warnings,
            "signoff": [entry.to_dict() for entry in self.signoff_entries],
            "claims": records,
            "records": records,
        }

    def to_legacy_dict(self):
        """Return only the flat record view kept for older report consumers."""

        return {
            "records": [item.to_legacy_dict() for item in self.evidence],
            "verified": self.verified_count,
        }

    def to_json(self):
        return _json_dumps(self.to_dict())

    def to_markdown(self):
        summary = self.summary()
        lines = [
            "# 符号与发行镜像证据复核",
            "",
            "生成时间：%s" % self.generated_at,
            "",
            "## 镜像与调试记录",
            "",
        ]
        if self.image.path:
            lines.append("- PE：`%s`" % self.image.path)
        if self.image.sha256:
            lines.append("- PE SHA-256：`%s`" % self.image.sha256)
        lines.append("- CodeView 调试记录：%d 条" % len(self.image.identities))
        for identity in self.image.identities:
            lines.append(
                "  - %s：`%s`，身份 `%s`"
                % (
                    identity.kind.upper() if identity.kind else "?",
                    identity.pdb_name or identity.pdb_path or "?",
                    identity.identity_key or "不完整",
                )
            )
        lines.extend(["", "## 证据等级定义", ""])
        lines.append("- `name_only`：仅有名称，不能证明符号库与镜像来自同一构建。")
        lines.append(
            "- `debug_record_match`：PE 调试记录身份与声明吻合，但仍无完整文件摘要。"
        )
        lines.append(
            "- `digest_verified`：签收材料提供完整摘要且与声明一致，才允许显示已证实。"
        )
        if self.signoff_entries:
            lines.extend(["", "## 签收材料", ""])
            for entry in self.signoff_entries:
                if entry.digest is not None:
                    digest_state = "完整" if entry.digest.is_complete else "不完整"
                    digest_text = "符号文件摘要%s" % digest_state
                elif entry.pe_digest is not None:
                    digest_state = "完整" if entry.pe_digest.is_complete else "不完整"
                    digest_text = "PE 摘要%s" % digest_state
                else:
                    digest_text = "无摘要"
                lines.append(
                    "- 第 %s 行：`%s`，身份 `%s`，%s%s%s"
                    % (
                        entry.row or "?",
                        entry.name or entry.pdb_name or "?",
                        entry.identity_key or "未提供",
                        digest_text,
                        "，签收人 %s" % entry.signer if entry.signer else "",
                        "，单号 %s" % entry.reference if entry.reference else "",
                    )
                )
        lines.extend(["", "## 逐条结论", ""])
        lines.append(
            "| # | 记录 ID | 显示名 | 源定位 | 证据等级 | 摘要完整 | 已证实 | 依据 |"
        )
        lines.append("|---:|---|---|---|---|---|---|---|")
        for index, item in enumerate(self.evidence, start=1):
            claim = item.claim
            location = claim.source_file or "-"
            if claim.line is not None:
                location = "%s:%s" % (location, claim.line)
            digest_state = "是" if item.digest_complete else "否"
            verified = "是" if item.verified else "否"
            lines.append(
                "| %d | `%s` | %s | %s | `%s`（%s） | %s | %s | %s |"
                % (
                    index,
                    claim.export_id,
                    _md_cell(claim.display_name),
                    _md_cell(location),
                    item.level,
                    EvidenceLevel.label(item.level),
                    digest_state,
                    verified,
                    _md_cell(item.basis),
                )
            )
        lines.extend(["", "## 复核结论", ""])
        lines.append(summary["statement"])
        lines.append(
            "共 %d 条声明：已证实 %d 条，未证实 %d 条。"
            % (summary["total"], summary["verified"], summary["unverified"])
        )
        if summary["duplicate_display_names"]:
            lines.append("")
            lines.append("### 同名记录")
            lines.append("")
            for duplicate in summary["duplicate_display_names"]:
                lines.append(
                    "- `%s` 出现 %d 次（%s）；未按显示名合并，已证实记录：%s。"
                    % (
                        duplicate["display_name"],
                        duplicate["count"],
                        "、".join("`%s`" % item for item in duplicate["ids"]),
                        "、".join("`%s`" % item for item in duplicate["verified_ids"])
                        or "无",
                    )
                )
        if self.warnings:
            lines.extend(["", "### 注意", ""])
            for warning in self.warnings:
                lines.append("- %s" % warning)
        lines.extend(
            [
                "",
                "> 仅有名称或仅有调试身份吻合，都不能替代签收材料中的完整摘要；"
                "导出中的 `verified` 仅为 `digest_verified` 记录置为 true。",
                "",
            ]
        )
        return "\n".join(lines)

    def to_csv(self):
        fields = [
            "id",
            "display_name",
            "file",
            "source_file",
            "location",
            "line",
            "symbol",
            "pdb",
            "pdb_name",
            "guid",
            "age",
            "sha256",
            "hash",
            "digest_algorithm",
            "digest_complete",
            "evidence_level",
            "verified",
            "basis",
        ]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for item in self.evidence:
            record = item.to_dict()
            writer.writerow({key: record.get(key) for key in fields})
        return output.getvalue()

    def write(
        self, output_dir, formats=("json", "md", "csv"), basename="symbol_evidence"
    ):
        os.makedirs(output_dir, exist_ok=True)
        written = []
        if "json" in formats:
            path = os.path.join(output_dir, basename + ".json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.to_json())
            written.append(path)
        if "md" in formats:
            path = os.path.join(output_dir, basename + ".md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.to_markdown())
            written.append(path)
        if "csv" in formats:
            path = os.path.join(output_dir, basename + ".csv")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.to_csv())
            written.append(path)
        return written


def _md_cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def _json_dumps(value):
    return json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n"


def build_report(
    pe=None,
    pe_path=None,
    pe_data=None,
    pe_sha256=None,
    signoff=None,
    claims=None,
    pdb_path=None,
    generated_at=None,
):
    """Build a report from a PE, a sign-off sheet, and optional claims.

    ``pe`` may be a ``pefile.PE`` instance, a path, or omitted in favour of
    ``pe_path``/``pe_data``.  If ``claims`` is omitted, sign-off rows become
    the claims; this is useful when the sheet itself lists the symbol-library
    entries but the postmortem only contains the narrative claim.
    """

    if isinstance(pe, (str, os.PathLike)) and os.path.exists(pe):
        pe_path = pe
        pe = None
    image = load_pe_image(path=pe_path, pe=pe, data=pe_data, sha256=pe_sha256)
    signoff_entries = _prepare_signoff(signoff)

    if claims is None:
        claims = claims_from_signoff(signoff_entries)
    else:
        claims = _prepare_claims(claims)

    pdb_sha256 = None
    if pdb_path and os.path.exists(pdb_path):
        pdb_sha256 = file_sha256(pdb_path)

    evidence = evaluate_claims(
        claims,
        image.identities,
        signoff_entries=signoff_entries,
        pe_sha256=image.sha256,
        pdb_sha256=pdb_sha256,
    )

    warnings = list(image.warnings)
    if not signoff_entries:
        warnings.append("未提供符号库签收表，所有声明最多只能到名称或调试身份等级")
    if pdb_sha256 is None and signoff_entries:
        warnings.append(
            "未提供 PDB 实体文件，符号文件摘要仅按签收表记录比对，未对 PDB 内容重新计算"
        )
    duplicates = []
    groups = {}
    for item in evidence:
        groups.setdefault(item.claim.display_name.lower(), []).append(item)
    for items in groups.values():
        if len(items) > 1:
            duplicates.append(items[0].claim.display_name)
    for display_name in duplicates:
        warnings.append(
            "显示名 %s 出现在多条记录中；记录按 ID 独立保留，未合并" % display_name
        )

    symbol_file = {
        "path": pdb_path,
        "sha256": pdb_sha256,
        "content_rehashed": bool(pdb_sha256),
    }
    return EvidenceReport(
        image=image,
        evidence=evidence,
        signoff_entries=signoff_entries,
        generated_at=generated_at,
        warnings=warnings,
        symbol_file=symbol_file,
    )
