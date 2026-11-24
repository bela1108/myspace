"""Command line entry point for the read-only TUF cross-check.

The tool is intentionally offline: it only opens files passed on the command
line and never constructs a network client. Each party is described by a
small JSON manifest so that the exact inputs (saved receipt bundle, the root
the party vouches for, and the declared observation scope) can be archived
next to the signed metadata they refer to.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from forensics.crosscheck import run_crosscheck
from forensics.models import PartyInput
from forensics.report import render_json, render_markdown


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open('rb') as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f'cannot read manifest {path}: {exc}') from exc
    required = {'party', 'root', 'metadata_dir', 'scope'}
    missing = required - set(data)
    if missing:
        raise SystemExit(
            f'manifest {path} is missing keys: {sorted(missing)}'
        )
    if not isinstance(data['scope'], list) or not all(
        isinstance(pattern, str) for pattern in data['scope']
    ):
        raise SystemExit(f'manifest {path}: scope must be a list of strings')
    return data


def _resolve(base: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return (base / candidate).resolve()


def _build_input(manifest_path: Path) -> PartyInput:
    data = _load_manifest(manifest_path)
    base = manifest_path.resolve().parent
    root = _resolve(base, data['root'])
    metadata_dir = _resolve(base, data['metadata_dir'])
    if not root.is_file():
        raise SystemExit(f'root metadata not found: {root}')
    if not metadata_dir.is_dir():
        raise SystemExit(f'metadata directory not found: {metadata_dir}')
    return PartyInput(
        party=str(data['party']),
        root=root,
        metadata_dir=metadata_dir,
        scope=tuple(data['scope']),
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser (exposed for testing)."""

    parser = argparse.ArgumentParser(
        prog='tuf-crosscheck',
        description=(
            'Read-only offline comparison of TUF release statements that two '
            'parties verified independently against their own roots.'
        ),
    )
    parser.add_argument(
        '--alpha',
        required=True,
        type=Path,
        help='manifest JSON for the first party',
    )
    parser.add_argument(
        '--beta',
        required=True,
        type=Path,
        help='manifest JSON for the second party',
    )
    parser.add_argument(
        '--format',
        choices=('json', 'markdown'),
        default='markdown',
        help='report format (default: markdown)',
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=None,
        help='write the report here instead of stdout',
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the cross-check and return a process exit code.

    Exit code 2 means at least one proven conflict was found; 0 means the
    run completed (undecided records alone do not count as failure).
    """

    args = build_parser().parse_args(argv)
    alpha = _build_input(args.alpha)
    beta = _build_input(args.beta)
    report = run_crosscheck((alpha, beta))
    rendered = (
        render_json(report)
        if args.format == 'json'
        else render_markdown(report)
    )
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered, encoding='utf-8')
    return 2 if report.conflicts else 0


if __name__ == '__main__':
    raise SystemExit(main())
