"""
Read previously produced `pip-audit` JSON results without contacting any service.

The remediation check is an offline analysis: it never installs a package,
performs resolution, or queries a vulnerability database. It only consumes the
JSON manifests produced by `pip-audit --format json` (or `-f json`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name


@dataclass(frozen=True)
class AuditVulnerability:
    """
    A single vulnerability recorded for an audited package.
    """

    id: str
    fix_versions: tuple[str, ...]
    aliases: frozenset[str]

    @property
    def id_aliases(self) -> frozenset[str]:
        """
        Every identifier that refers to this vulnerability.
        """
        return frozenset({self.id, *self.aliases})


@dataclass(frozen=True)
class AuditReport:
    """
    The vulnerability records of one already completed `pip-audit` run.

    Skipped packages (missing `version`/`vulns` entries) are retained so that
    the remediation check can flag them as incomplete evidence.
    """

    source: Path
    vulnerabilities: dict[str, list[AuditVulnerability]]
    skipped: dict[str, str]
    raw_dependencies: tuple[dict[str, Any], ...] = field(default_factory=tuple)


class AuditReportError(ValueError):
    """
    Raised when an audit result file cannot be parsed.
    """

    pass


def read_audit_report(path: Path) -> AuditReport:
    """
    Parse a `pip-audit` JSON manifest from `path`.

    Raises `AuditReportError` when the file is missing, unreadable, or does not
    look like a `pip-audit` JSON manifest.
    """
    try:
        with path.open(mode="r", encoding="utf-8") as io:
            manifest = json.load(io)
    except FileNotFoundError as e:
        raise AuditReportError(f"{path}: audit result file not found") from e
    except json.JSONDecodeError as e:
        raise AuditReportError(f"{path}: invalid JSON in audit result") from e

    if not isinstance(manifest, dict) or not isinstance(manifest.get("dependencies"), list):
        raise AuditReportError(
            f"{path}: not a pip-audit JSON manifest (missing a dependencies array)"
        )

    vulnerabilities: dict[str, list[AuditVulnerability]] = {}
    skipped: dict[str, str] = {}
    for entry in manifest["dependencies"]:
        if not isinstance(entry, dict) or "name" not in entry:
            raise AuditReportError(f"{path}: malformed dependency entry in audit result")
        name = canonicalize_name(str(entry["name"]))
        if "vulns" not in entry:
            skipped[name] = str(entry.get("skip_reason", "not audited"))
            continue
        if not isinstance(entry["vulns"], list):
            raise AuditReportError(f"{path}: malformed vulnerability list for {name}")
        vulnerabilities[name] = [_parse_vuln(path, name, raw) for raw in entry["vulns"]]

    return AuditReport(
        source=path,
        vulnerabilities=vulnerabilities,
        skipped=skipped,
        raw_dependencies=tuple(manifest["dependencies"]),
    )


def _parse_vuln(path: Path, package: str, raw: Any) -> AuditVulnerability:
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
        raise AuditReportError(f"{path}: malformed vulnerability entry for {package}")
    fix_versions = raw.get("fix_versions", [])
    if not isinstance(fix_versions, list):
        raise AuditReportError(f"{path}: malformed fix_versions for {package}")
    aliases = raw.get("aliases", [])
    if not isinstance(aliases, list):
        raise AuditReportError(f"{path}: malformed aliases for {package}")
    return AuditVulnerability(
        id=raw["id"],
        fix_versions=tuple(str(version) for version in fix_versions),
        aliases=frozenset(str(alias) for alias in aliases),
    )
