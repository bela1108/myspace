"""Generate the demo fixtures and run the offline cross-check.

Running python -m forensics.demo writes a self-contained demo tree under
the chosen directory (default ./demo_output) and prints both the
Markdown report and the path to the JSON evidence report.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from forensics.cli import main as crosscheck_main
from forensics.generate.demo import build_demo
from forensics.report import render_json
from forensics.crosscheck import run_crosscheck
from forensics.cli import _build_input


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='python -m forensics.demo',
        description=(
            'Generate signed demo bundles and cross-check offline.'
        ),
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('demo_output'),
        help='directory for generated fixtures and reports',
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = build_demo(args.output_dir)
    json_report = args.output_dir / 'crosscheck-report.json'
    alpha = _build_input(paths['alpha_manifest'])
    beta = _build_input(paths['beta_manifest'])
    report = run_crosscheck((alpha, beta))
    json_report.write_text(render_json(report), encoding='utf-8')

    exit_code = crosscheck_main([
        '--alpha', str(paths['alpha_manifest']),
        '--beta', str(paths['beta_manifest']),
        '--format', 'markdown',
    ])
    print(f'\nJSON evidence report written to {json_report}')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
