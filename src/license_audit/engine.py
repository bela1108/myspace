"""Offline license-conflict review engine.

The engine never reaches the network. It parses locally supplied YARA
publication books with :mod:`plyara`, reads the sample manifest, approval
scope and frozen rule version handed in by the caller, and decides which
duplicate approval receipts may safely be folded.

A folded receipt must point at the *same concrete authorization*: matching
receipt wording alone is not enough because two identical statements may
originate from distinct sample grants.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import plyara
from plyara.exceptions import ParseTypeError, ParseValueError
from plyara.utils import generate_hash

#: Metadata keys that carry the provenance identity of an approval receipt.
REQUIRED_META_KEYS = (
    'authorization_id',
    'sample_id',
    'receipt_text',
    'scope',
)

#: Verdict labels used in the report.
VERDICT_FOLD = 'foldable'
VERDICT_KEEP = 'keep_duplicate'
VERDICT_VIOLATION = 'violation'
VERDICT_SINGLE = 'single'


class LicenseAuditError(Exception):
    """Raised when the caller-supplied audit inputs cannot be processed."""


@dataclass(frozen=True)
class RuleReceipt:
    """One approval receipt extracted from a parsed YARA rule."""

    rule_name: str
    book: str
    source_path: str
    start_line: int
    stop_line: int
    logic_hash: str
    authorization_id: str
    sample_id: str
    receipt_text: str
    scope: str
    raw_rule: dict[str, Any] = field(repr=False)

    @property
    def location(self) -> str:
        """Human readable pointer back to the original rule text."""
        return f'{self.source_path}:{self.start_line}-{self.stop_line}'


@dataclass
class Dossier:
    """Findings for one group of rules sharing the same matching logic."""

    logic_hash: str
    receipt_text: str
    receipts: list[RuleReceipt]
    verdict: str
    reasons: list[str] = field(default_factory=list)
    keep_receipts: list[RuleReceipt] = field(default_factory=list)
    folded_receipts: list[RuleReceipt] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the dossier for JSON reports."""
        return {
            'logic_hash': self.logic_hash,
            'receipt_text': self.receipt_text,
            'verdict': self.verdict,
            'reasons': list(self.reasons),
            'receipts': [
                {
                    'rule_name': item.rule_name,
                    'book': item.book,
                    'authorization_id': item.authorization_id,
                    'sample_id': item.sample_id,
                    'scope': item.scope,
                    'location': item.location,
                }
                for item in self.receipts
            ],
            'keep_receipts': [item.location for item in self.keep_receipts],
            'folded_receipts': [item.location for item in self.folded_receipts],
            'trace': _trace_lines(self),
        }


@dataclass
class AuditReport:
    """Aggregate result of an offline review run."""

    frozen_version: str
    books: list[str]
    dossiers: list[Dossier]
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Count dossiers by verdict."""
        counts = {
            VERDICT_FOLD: 0,
            VERDICT_KEEP: 0,
            VERDICT_VIOLATION: 0,
            VERDICT_SINGLE: 0,
        }
        for dossier in self.dossiers:
            counts[dossier.verdict] += 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        """Serialize the full report for machine-readable output."""
        return {
            'frozen_version': self.frozen_version,
            'books': list(self.books),
            'summary': self.summary(),
            'errors': list(self.errors),
            'dossiers': [dossier.as_dict() for dossier in self.dossiers],
        }


def _metadata_dict(rule: dict[str, Any]) -> dict[str, Any]:
    """Flatten plyara's list-of-single-key-dicts metadata structure."""
    flattened: dict[str, Any] = {}
    for entry in rule.get('metadata', []):
        flattened.update(entry)
    return flattened


def load_json_input(path: str | Path, label: str) -> dict[str, Any]:
    """Load a caller-supplied JSON input file with a clear error."""
    source = Path(path)
    if not source.is_file():
        raise LicenseAuditError(f'{label} not found: {source}')
    try:
        data = json.loads(source.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        raise LicenseAuditError(f'{label} is not valid JSON: {exc}') from exc
    if not isinstance(data, dict):
        raise LicenseAuditError(f'{label} must contain a JSON object')
    return data


def parse_book(path: str | Path, book_name: str) -> list[RuleReceipt]:
    """Parse one publication book into typed approval receipts."""
    source = Path(path)
    if not source.is_file():
        raise LicenseAuditError(f'publication book not found: {source}')

    parser = plyara.Plyara()
    try:
        rules = parser.parse_string(source.read_text(encoding='utf-8'))
    except (ParseTypeError, ParseValueError) as exc:
        raise LicenseAuditError(f'failed to parse {source}: {exc}') from exc

    receipts: list[RuleReceipt] = []
    for rule in rules:
        metadata = _metadata_dict(rule)
        missing = [key for key in REQUIRED_META_KEYS if key not in metadata]
        if missing:
            raise LicenseAuditError(
                f'rule {rule.get("rule_name")} in {source} is missing '
                f'required metadata: {", ".join(sorted(missing))}'
            )
        receipts.append(
            RuleReceipt(
                rule_name=rule['rule_name'],
                book=book_name,
                source_path=str(source),
                start_line=int(rule['start_line']),
                stop_line=int(rule['stop_line']),
                logic_hash=generate_hash(rule),
                authorization_id=str(metadata['authorization_id']),
                sample_id=str(metadata['sample_id']),
                receipt_text=str(metadata['receipt_text']),
                scope=str(metadata['scope']),
                raw_rule=rule,
            )
        )
    return receipts


def _check_manifest(receipt: RuleReceipt, manifest: dict[str, Any]) -> str | None:
    samples = manifest.get('samples', {})
    if receipt.sample_id not in samples:
        return f'sample {receipt.sample_id} absent from local sample manifest'
    sample = samples[receipt.sample_id]
    registered = sample.get('authorization_id')
    if registered != receipt.authorization_id:
        return (
            f'sample {receipt.sample_id} is bound to authorization '
            f'{registered}, receipt claims {receipt.authorization_id}'
        )
    return None


def _check_scope(receipt: RuleReceipt, scope_table: dict[str, Any]) -> str | None:
    allowed = scope_table.get(receipt.authorization_id, {}).get('allowed_scopes')
    if allowed is None:
        return (
            f'authorization {receipt.authorization_id} has no entry in the '
            'approval scope table'
        )
    if receipt.scope not in allowed:
        return (
            f'scope {receipt.scope} outside approved scope {sorted(allowed)} '
            f'for authorization {receipt.authorization_id}'
        )
    return None


def _check_freeze(
    receipt: RuleReceipt, frozen_rules: dict[str, Any]
) -> str | None:
    expected = frozen_rules.get(receipt.rule_name)
    if expected is None:
        return (
            f'rule {receipt.rule_name} absent from frozen rule version '
            f'{receipt.logic_hash}'
        )
    if expected != receipt.logic_hash:
        return (
            f'rule {receipt.rule_name} drifted: frozen {expected} but parsed '
            f'{receipt.logic_hash}'
        )
    return None


def _trace_lines(dossier: Dossier) -> list[str]:
    """Build direct pointers back to the original information per case file."""
    lines = []
    for receipt in dossier.receipts:
        lines.append(
            f'[{receipt.book}] {receipt.rule_name} '
            f'auth={receipt.authorization_id} sample={receipt.sample_id} '
            f'scope={receipt.scope} -> {receipt.location}'
        )
    return lines


def _adjudicate_group(
    group: list[RuleReceipt],
    manifest: dict[str, Any],
    scope_table: dict[str, Any],
    frozen_rules: dict[str, Any],
) -> Dossier:
    first = group[0]
    dossier = Dossier(
        logic_hash=first.logic_hash,
        receipt_text=first.receipt_text,
        receipts=list(group),
        verdict=VERDICT_SINGLE,
    )

    for receipt in group:
        for check in (
            _check_manifest(receipt, manifest),
            _check_scope(receipt, scope_table),
            _check_freeze(receipt, frozen_rules),
        ):
            if check:
                dossier.reasons.append(check)

    if dossier.reasons:
        dossier.verdict = VERDICT_VIOLATION
        dossier.keep_receipts = list(group)
        return dossier

    if len(group) == 1:
        dossier.verdict = VERDICT_SINGLE
        dossier.keep_receipts = list(group)
        return dossier

    authorization_ids = {receipt.authorization_id for receipt in group}
    sample_ids = {receipt.sample_id for receipt in group}
    scopes = {receipt.scope for receipt in group}

    if len(authorization_ids) > 1:
        dossier.verdict = VERDICT_KEEP
        dossier.reasons.append(
            'identical receipt wording originates from distinct '
            f'authorizations {sorted(authorization_ids)}; folding would '
            'merge separate sample grants'
        )
        dossier.keep_receipts = list(group)
        return dossier

    if len(sample_ids) > 1 or len(scopes) > 1:
        dossier.verdict = VERDICT_KEEP
        differing = []
        if len(sample_ids) > 1:
            differing.append(f'samples {sorted(sample_ids)}')
        if len(scopes) > 1:
            differing.append(f'scopes {sorted(scopes)}')
        dossier.reasons.append(
            'shared authorization id but provenance still differs: '
            + '; '.join(differing)
        )
        dossier.keep_receipts = list(group)
        return dossier

    canonical = min(group, key=lambda item: (item.book, item.start_line))
    dossier.verdict = VERDICT_FOLD
    dossier.reasons.append(
        f'all {len(group)} receipts resolve to the same concrete '
        f'authorization {canonical.authorization_id} and identical '
        'sample, scope and frozen logic hash'
    )
    dossier.keep_receipts = [canonical]
    dossier.folded_receipts = [
        receipt for receipt in group if receipt is not canonical
    ]
    return dossier


def run_review(
    books: list[tuple[str, str]],
    manifest_path: str | Path,
    scope_path: str | Path,
    freeze_path: str | Path,
) -> AuditReport:
    """Run the full offline review and return the structured report.

    Args:
        books: Pairs of ``(book_name, book_path)`` for each publication book.
        manifest_path: Local sample manifest JSON.
        scope_path: Approval scope JSON keyed by authorization id.
        freeze_path: Frozen rule version JSON keyed by rule name.
    """
    manifest = load_json_input(manifest_path, 'sample manifest')
    scope_doc = load_json_input(scope_path, 'approval scope')
    freeze_doc = load_json_input(freeze_path, 'frozen rule version')

    scope_table = scope_doc.get('authorizations', {})
    frozen_version = str(freeze_doc.get('version', 'unknown'))
    frozen_rules = freeze_doc.get('rule_hashes', {})

    all_receipts: list[RuleReceipt] = []
    parsed_books: list[str] = []
    for book_name, book_path in books:
        all_receipts.extend(parse_book(book_path, book_name))
        parsed_books.append(book_name)

    groups: dict[str, list[RuleReceipt]] = {}
    for receipt in all_receipts:
        groups.setdefault(receipt.logic_hash, []).append(receipt)

    dossiers = [
        _adjudicate_group(
            sorted(group, key=lambda item: (item.book, item.start_line)),
            manifest,
            scope_table,
            frozen_rules,
        )
        for _, group in sorted(groups.items())
    ]

    return AuditReport(
        frozen_version=frozen_version,
        books=parsed_books,
        dossiers=dossiers,
    )
