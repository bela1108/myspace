import argparse
from typing import cast

from .common import valid_path


def add_probe_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'probe',
        help='Holds each enabled plugin accountable against a verified sample manifest.',
        description=(
            'Runs a recovery probe: every plugin named by a sample must detect its '
            'own and shared positives, and leave its negatives alone. The release '
            'verdict is based only on this freshly verified run; an old baseline can '
            'be shown for reference but can never authorize a release.'
        ),
    )

    parser.add_argument(
        'manifest',
        type=valid_path,
        help='Path to the probe manifest describing the verified test samples.',
    )

    parser.add_argument(
        '--reference-baseline',
        dest='reference_baseline',
        type=valid_path,
        default=None,
        help=(
            'Optional old baseline to display for reference. It is never used to '
            'satisfy the release verdict, since it carries no verified sample '
            'identity.'
        ),
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Outputs results in a machine-readable format.',
    )

    return cast(argparse.ArgumentParser, parser)


def parse_args(args: argparse.Namespace) -> None:
    if args.action != 'probe':
        return
