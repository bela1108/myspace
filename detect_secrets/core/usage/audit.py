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
            'between false and true positives.  In scheduling mode this is '
            'the plan file (JSON or YAML).'
        ),
    )

    _add_mode_parser(parser)
    _add_report_module(parser)
    _add_statistics_module(parser)
    _add_schedule_module(parser)
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
        '--schedule',
        '--plan',
        action='store_true',
        help=(
            'Builds a weekly manual-review worklist from a plan file.  '
            'The plan supplies local group hours, tags, permissions, and '
            'candidates.'
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


def _add_schedule_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='scheduling',
        description=(
            'Inputs and outputs for the scheduling mode (--schedule).  '
            'The exported schedule is anonymized: it only carries a random '
            'task id, the processing order, and the required capabilities.'
        ),
    )

    parser.add_argument(
        '--export',
        '--output',
        metavar='<file>',
        help=(
            'Write the anonymized schedule to <file>.  Use "-" to write it '
            'to stdout instead of the human-readable worklist.'
        ),
    )

    parser.add_argument(
        '--seed',
        help=(
            'Seed used to generate random task ids.  Supplying a seed makes '
            'the exported ids reproducible.'
        ),
    )

    parser.add_argument(
        '--work-hours',
        '--local-hours',
        dest='work_hours',
        metavar='<file>',
        help=(
            'JSON/YAML file with per-group local weekly hours.  It may be a '
            'mapping of group name to hours, or a list of group objects.'
        ),
    )

    parser.add_argument(
        '--tags',
        '--labels',
        metavar='<file>',
        help=(
            'JSON/YAML file mapping tags to required capabilities and '
            'optional priorities.'
        ),
    )

    parser.add_argument(
        '--permissions',
        '--reviewers',
        metavar='<file>',
        help=(
            'JSON/YAML file mapping project names to the groups that may '
            'review them.'
        ),
    )

    parser.add_argument(
        '--candidates',
        '--candidate-list',
        metavar='<file>',
        help=(
            'JSON/YAML file containing additional candidate objects.'
        ),
    )

    parser.add_argument(
        '--weeks',
        type=int,
        help=(
            'Number of weekly capacity windows to schedule.  Defaults to the '
            'value in the plan (or 1).'
        ),
    )

    parser.add_argument(
        '--max-nodes',
        dest='max_nodes',
        type=int,
        default=1000000,
        help=(
            'Branch-and-bound node limit.  Defaults to 1000000.  When reached, '
            'the best schedule found so far is returned and marked non-optimal.'
        ),
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.action != 'audit':
        return

    if args.schedule:
        if args.diff or args.stats or args.report:
            raise argparse.ArgumentTypeError(
                '--schedule cannot be combined with --diff, --stats, or --report.',
            )
        if len(args.filename) > 1:
            raise argparse.ArgumentTypeError(
                'Scheduling mode accepts at most one plan file.',
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
