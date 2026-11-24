import argparse
from typing import cast


def add_audit_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'audit',
        help='Manually assesses a baseline to determine validity of secrets found.',
        description=(
            'Auditing a baseline allows analysts to label results, and optimize plugins for '
            'the highest signal-to-noise ratio for their environment.'
        ),
    )

    parser.add_argument(
        'filename',
        nargs='*',
        help=(
            'Audit a given baseline file to distinguish the difference '
            'between false and true positives. Optional when --probe is used.'
        ),
    )

    _add_mode_parser(parser)
    _add_report_module(parser)
    _add_statistics_module(parser)
    _add_recovery_probe_module(parser)
    return cast(argparse.ArgumentParser, parser)


def _add_mode_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--diff',
        action='store_true',
        help=(
            'Allows the comparison of two baseline files, in order to '
            'effectively distinguish the difference between various '
            'plugin configurations.'
        ),
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help=(
            'Displays the results of an interactive auditing session '
            'which have been saved to a baseline file.'
        ),
    )

    parser.add_argument(
        '--report',
        action='store_true',
        help=(
            'Displays a report with the secrets detected'
        ),
    )



def _add_recovery_probe_module(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group(
        title='recovery probe',
        description=(
            'Holds each plugin accountable against a labelled set of test samples. '
            'Use --probe with a probe manifest; add --gate to enforce a release decision.'
        ),
    )

    group.add_argument(
        '--probe',
        metavar='PROBE_FILE',
        help=(
            'Path to a recovery probe manifest. Runs a fresh scan of the probe '
            'samples and reports per-plugin positive/negative accounting.'
        ),
    )

    group.add_argument(
        '--gate',
        action='store_true',
        help=(
            'Treat the recovery probe result as a release gate: exit non-zero if any '
            'plugin misses a positive sample or flags a negative one. Comparison-only '
            'runs never pass the gate.'
        ),
    )

    group.add_argument(
        '--compare-baseline',
        metavar='BASELINE_FILE',
        help=(
            'Reconcile an existing baseline against the probe samples without scanning. '
            'A baseline that predates the probe can only be displayed for comparison; it '
            'cannot satisfy the release gate (use a fresh --probe run for that).'
        ),
    )

def _add_report_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='reporting',
        description=(
            'Display a report with all the findings and the made decisions. '
            'To be used with the report mode (--report).'
        ),
    )

    report_parser = parser.add_mutually_exclusive_group()
    report_parser.add_argument(
        '--only-real',
        action='store_true',
        help=(
            'Only includes real secrets in the report'
        ),
    )

    report_parser.add_argument(
        '--only-false',
        action='store_true',
        help=(
            'Only includes false positives in the report'
        ),
    )


def _add_statistics_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='analytics',
        description=(
            'Quantify the success of your plugins based on the labelled results '
            'in your baseline. To be used with the statistics mode (--stats).'
        ),
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Outputs results in a machine-readable format.',
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.action != 'audit':
        return

    if args.diff and len(args.filename) != 2:
        raise argparse.ArgumentTypeError(
            '--diff mode requires two files to compare with each other.',
        )
    elif not args.diff and not args.probe and len(args.filename) != 1:
        raise argparse.ArgumentTypeError(
            'Can only specify one baseline at a time.',
        )

    if args.compare_baseline and not args.probe:
        raise argparse.ArgumentTypeError(
            '--compare-baseline requires a --probe manifest.',
        )

    if args.gate and not args.probe:
        raise argparse.ArgumentTypeError(
            '--gate requires a --probe manifest.',
        )
