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
        nargs='+',
        help=(
            'Audit a given baseline file to distinguish the difference '
            'between false and true positives.'
        ),
    )

    _add_mode_parser(parser)
    _add_report_module(parser)
    _add_statistics_module(parser)
    _add_aggregation_module(parser)
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

    parser.add_argument(
        '--aggregate',
        action='store_true',
        help=(
            'Builds an offline, privacy-reviewed summary from audited baselines. '
            'Only groups that are safe to disclose are written to the external report.'
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


def _add_aggregation_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='aggregation',
        description=(
            'Offline disclosure review for audited baselines. Use with --aggregate, or '
            'through the top-level `aggregate` command.'
        ),
    )
    _add_aggregation_options(parser)


def add_aggregate_action(
    parent: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'aggregate',
        help='Summarizes audited baselines while enforcing disclosure thresholds.',
        description=(
            'Reads audited baselines, existing team boundaries, and prior releases, then '
            'emits an external aggregate containing only approved groups and an internal '
            'receipt describing any restricted groups.'
        ),
    )
    parser.add_argument(
        'filename',
        nargs='+',
        help='Audited baseline files, audit bundles, or aggregate reports to summarize.',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Outputs results in a machine-readable format (the default for aggregation).',
    )
    _add_aggregation_options(parser)
    return cast(argparse.ArgumentParser, parser)


def _add_aggregation_options(parent: argparse.ArgumentParser) -> None:
    parent.add_argument(
        '--team-boundaries',
        '--boundaries',
        '--teams',
        '--team-config',
        '--boundary-file',
        dest='team_boundaries',
        help=(
            'JSON file describing teams (or people/files to teams). If omitted, team data '
            'embedded in the input bundle is used.'
        ),
    )
    parent.add_argument(
        '--minimum-group-size',
        '--min-group-size',
        '--minimum-count',
        '--threshold',
        '--k',
        dest='minimum_group_size',
        type=int,
        help='Minimum number of distinct people required in a releasable group.',
    )
    parent.add_argument(
        '--history',
        '--release-history',
        '--previous-report',
        '--historical-report',
        dest='history',
        action='append',
        default=[],
        help=(
            'Previously released report or historical checked-out baseline. May be '
            'specified more than once, or point at a directory of JSON reports.'
        ),
    )
    parent.add_argument(
        '--report-id',
        '--release-id',
        dest='aggregate_report_id',
        help='Identity to attach to this release request (also usable in release history).',
    )
    parent.add_argument(
        '--merge-group',
        '--merge-groups',
        '--group-merge',
        dest='merge_groups',
        action='append',
        default=[],
        help=(
            'Merge disclosure groups, e.g. `team-a,team-b=engineering` or '
            '`team-a,team-b` (which produces `team-a+team-b`).'
        ),
    )
    parent.add_argument(
        '--receipt',
        '--internal-receipt',
        dest='receipt_output',
        help='Write the internal receipt (restricted groups and history identities) here.',
    )
    parent.add_argument(
        '--output',
        '--external-output',
        '--public-output',
        '--external',
        dest='aggregate_output',
        help='Write the external report (approved groups only) here.',
    )
    parent.add_argument(
        '--external-only',
        action='store_true',
        help='Print only the external report to stdout.',
    )
    parent.add_argument(
        '--internal-only',
        action='store_true',
        help='Print only the internal receipt to stdout.',
    )
    parent.add_argument(
        '--include-unlabelled',
        action='store_true',
        help='Include findings without a manual decision (but still exclude false positives).',
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.action not in ('audit', 'aggregate'):
        return

    if getattr(args, 'aggregate', False) or args.action == 'aggregate':
        if not args.filename:
            raise argparse.ArgumentTypeError(
                'Aggregation requires at least one baseline or report.',
            )
        if args.external_only and args.internal_only:
            raise argparse.ArgumentTypeError(
                '--external-only and --internal-only cannot be used together.',
            )
        return

    if args.diff and len(args.filename) != 2:
        raise argparse.ArgumentTypeError(
            '--diff mode requires two files to compare with each other.',
        )
    elif not args.diff and len(args.filename) != 1:
        raise argparse.ArgumentTypeError(
            'Can only specify one baseline at a time.',
        )
