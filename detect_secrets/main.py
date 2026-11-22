import argparse
import json
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from . import audit
from .core import baseline
from .core import plugins
from .core.log import log
from .core.scan import get_files_to_scan
from .core.scan import scan_for_allowlisted_secrets_in_file
from .core.scan import scan_line
from .core.secrets_collection import SecretsCollection
from .core.usage import ParserBuilder
from .exceptions import InvalidBaselineError
from .exceptions import InvalidFile
from .probe import compare_against_baseline
from .probe import ProbeManifest
from .probe import run_probe
from .settings import get_plugins
from .settings import get_settings


def main(argv: Optional[List[str]] = None) -> int:
    if not argv and len(sys.argv) == 1:     # pragma: no cover
        argv = ['--help']

    args = parse_args(argv)
    if args.verbose:    # pragma: no cover
        log.set_debug_level(args.verbose)

    if args.action == 'scan':
        handle_scan_action(args)
    elif args.action == 'audit':
        handle_audit_action(args)
    elif args.action == 'probe':
        return handle_probe_action(args)

    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    return ParserBuilder().add_console_use_arguments().parse_args(argv)


def handle_scan_action(args: argparse.Namespace) -> None:
    if args.list_all_plugins:
        # NOTE: If there was a baseline provided, it would already have been parsed and
        # settings populated by the time it reaches here.
        print('\n'.join(get_settings().plugins))
        return

    if args.string:
        line = args.string
        if isinstance(args.string, bool):
            # Support stdin usage, rather than specifying on CLI.
            line = sys.stdin.read().splitlines()[0]

        print(scan_adhoc_string(line))
        return

    if args.only_allowlisted:
        secrets = SecretsCollection(root=args.custom_root)
        for filename in get_files_to_scan(
            *args.path,
            should_scan_all_files=args.all_files,
            root=args.custom_root,
        ):
            for secret in scan_for_allowlisted_secrets_in_file(filename):
                secrets[secret.filename].add(secret)

        print(json.dumps(baseline.format_for_output(secrets), indent=2))
        return

    secrets = baseline.create(
        *args.path,
        should_scan_all_files=args.all_files,
        root=args.custom_root,
        num_processors=args.num_cores,
    )
    if args.baseline is not None:
        # The pre-commit hook's baseline upgrade is to trim the supplied baseline for non-existent
        # secrets, and to upgrade the format to the latest version. This is because the pre-commit
        # hook is not supposed to allow any new secrets to enter commit history.
        #
        # Unlike that, this scan's intention is to re-catalog the secrets in the repository. This
        # means that we should favor (and allow) the newly found secrets, and create a baseline
        # with them. It should also upgrade the format to the latest version, which is done by
        # default.
        secrets.merge(args.baseline)

        baseline.save_to_file(secrets, args.baseline_filename)
    else:
        print(json.dumps(baseline.format_for_output(secrets, is_slim_mode=args.slim), indent=2))


def scan_adhoc_string(line: str) -> str:
    registered_plugins = get_plugins()

    results = {
        plugin.secret_type: 'False'
        for plugin in registered_plugins
    }

    for secret in scan_line(line):
        results[secret.type] = (
            plugins.initialize.from_secret_type(secret.type)    # type: ignore
            .format_scan_result(secret)
        )

    # Pretty formatting
    longest_plugin_name_length = max([
        len(plugin.__class__.__name__)
        for plugin in registered_plugins
    ])
    return '\n'.join([
        ('{:%d}: {}' % longest_plugin_name_length).format(
            plugin.__class__.__name__,
            results[plugin.secret_type],
        )
        for plugin in sorted(registered_plugins, key=lambda x: str(x.__class__.__name__))
    ])


def handle_audit_action(args: argparse.Namespace) -> None:
    try:
        if args.stats:
            stats = audit.analytics.calculate_statistics_for_baseline(args.filename[0])
            if args.diff:
                # TODO
                raise NotImplementedError

            if args.json:
                print(json.dumps(stats.json(), indent=2))
            else:
                print(str(stats))
        elif args.report:
            class_to_print = None
            if args.only_real:
                class_to_print = audit.report.SecretClassToPrint.REAL_SECRET
            elif args.only_false:
                class_to_print = audit.report.SecretClassToPrint.FALSE_POSITIVE
            print(
                json.dumps(
                    audit.report.generate_report(args.filename[0], class_to_print),
                    indent=4,
                    sort_keys=True,
                ),
            )
        else:
            # Starts interactive session.
            if args.diff:
                # Show changes
                audit.compare_baselines(args.filename[0], args.filename[1])
            else:
                # Label secrets
                audit.audit_baseline(args.filename[0])
    except InvalidBaselineError:
        pass


def handle_probe_action(args: argparse.Namespace) -> int:
    try:
        manifest = ProbeManifest.load_from_file(args.manifest)
    except InvalidFile as exc:
        print(str(exc), file=sys.stderr)
        return 1

    report = run_probe(manifest.samples)

    baseline_comparison = None
    if args.reference_baseline:
        baseline_comparison = compare_against_baseline(
            manifest.samples,
            args.reference_baseline,
        )

    if args.json:
        payload = report.json()
        if baseline_comparison is not None:
            payload['baseline-reference'] = baseline_comparison
        print(json.dumps(payload, indent=2))
    else:
        print(str(report))
        if baseline_comparison is not None:
            print(_format_baseline_reference(baseline_comparison))

    return 0 if report.all_healthy else 1


def _format_baseline_reference(comparison: Dict[str, Any]) -> str:
    divider = '-' * 60
    lines = [
        divider,
        f'Reference only (not used for the release verdict): {comparison["baseline"]}',
    ]
    for sample in comparison['samples']:
        if sample['found-in-baseline']:
            observed = ', '.join(sample['baseline-plugins'])
            lines.append(f'  {sample["id"]}: baseline flagged {observed}')
        else:
            lines.append(
                f'  {sample["id"]}: no matching identity in old baseline',
            )
    return chr(10).join(lines)
