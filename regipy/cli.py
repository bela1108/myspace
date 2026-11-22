import csv
import json
import logging
import os
import time
from dataclasses import asdict
from typing import Optional

import click
from tabulate import tabulate

from regipy.cli_utils import _normalize_subkey_fields, get_filtered_subkeys
from regipy.exceptions import RegistryKeyNotFoundException
from regipy.plugins.plugin import PLUGINS
from regipy.plugins.utils import run_relevant_plugins
from regipy.recovery import apply_transaction_logs
from regipy.regdiff import compare_hives
from regipy.registry import RegistryHive
from regipy.snapshots import Snapshot, compare_snapshots
from regipy.utils import _setup_logging, calculate_xor32_checksum

logger = logging.getLogger(__name__)


@click.command()
@click.argument(
    "hive_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
)
@click.option("-v", "--verbose", is_flag=True, default=True, help="Verbosity")
def parse_header(hive_path, verbose):
    _setup_logging(verbose=verbose)
    registry_hive = RegistryHive(hive_path)

    click.secho(tabulate(registry_hive.header.items(), tablefmt="fancy_grid"))

    if registry_hive.header.primary_sequence_num != registry_hive.header.secondary_sequence_num:
        click.secho("Hive is not clean! You should apply transaction logs", fg="red")

    calculated_checksum = calculate_xor32_checksum(registry_hive._stream.read(508))
    if registry_hive.header.checksum != calculated_checksum:
        click.secho("Hive is not clean! Header checksum does not match", fg="red")


@click.command()
@click.argument(
    "hive_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
)
@click.option(
    "-o",
    "output_path",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    required=False,
)
@click.option("-p", "--registry-path", help="A registry path to start iterating from")
@click.option(
    "-t",
    "--timeline",
    is_flag=True,
    default=False,
    help="Create a CSV timeline instead",
)
@click.option(
    "-l",
    "--hive-type",
    type=click.STRING,
    required=False,
    help="Specify a hive type, if it could not be identified for some reason",
)
@click.option(
    "-r",
    "--partial_hive_path",
    type=click.STRING,
    required=False,
    help='The path from which the partial hive actually starts, for example: -t ntuser -r "/Software" '
    "would mean this is actually a HKCU hive, starting from HKCU/Software",
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbosity")
@click.option(
    "-d",
    "--do-not-fetch-values",
    is_flag=True,
    default=False,
    help="Not fetching the values for each subkey makes the iteration way faster. Values count will still be returned",
)
@click.option(
    "-s",
    "--start-date",
    type=click.STRING,
    required=False,
    help='If "-s" was specified, fetch only values for subkeys starting this timestamp in isoformat',
)
@click.option(
    "-e",
    "--end-date",
    type=click.STRING,
    required=False,
    help='If "-e" was specified, fetch only values for subkeys until this timestamp in isoformat',
)
def registry_dump(
    hive_path,
    output_path,
    registry_path,
    timeline,
    hive_type,
    partial_hive_path,
    verbose,
    do_not_fetch_values,
    start_date,
    end_date,
):
    _setup_logging(verbose=verbose)
    registry_hive = RegistryHive(hive_path, hive_type=hive_type, partial_hive_path=partial_hive_path)

    start_time = time.monotonic()

    if registry_path:
        try:
            name_key_entry = registry_hive.get_key(registry_path)
        except RegistryKeyNotFoundException as ex:
            logger.debug(f"Did not find the key: {ex}")
            return
    else:
        name_key_entry = registry_hive.root

    if timeline and not output_path:
        click.secho("You must provide an output path if choosing timeline output!", fg="red")
        return

    subkey_count = 0
    if output_path:
        try:
            with open(output_path, "w") as output_file:
                csvwriter: Optional[csv.DictWriter] = None
                if timeline:
                    csvwriter = csv.DictWriter(
                        output_file,
                        delimiter=",",
                        quotechar='"',
                        quoting=csv.QUOTE_MINIMAL,
                        fieldnames=["timestamp", "subkey_name", "values_count", "values"],
                    )
                    csvwriter.writeheader()

                for subkey_count, entry in enumerate(
                    get_filtered_subkeys(
                        registry_hive,
                        name_key_entry,
                        fetch_values=not do_not_fetch_values,
                        start_date=start_date,
                        end_date=end_date,
                    )
                ):
                    if timeline and csvwriter:
                        csvwriter.writerow(
                            {
                                "subkey_name": entry.path,
                                "timestamp": entry.timestamp,
                                "values_count": entry.values_count,
                                "values": entry.values,
                            }
                        )
                    else:
                        output_file.write(
                            json.dumps(
                                asdict(
                                    entry,
                                ),
                                separators=(
                                    ",",
                                    ":",
                                ),
                                default=_normalize_subkey_fields,
                            )
                        )
                        output_file.write("\n")
        except OSError as e:
            logger.error(f"Failed to write output file {output_path}: {e}")
            return
    else:
        for subkey_count, entry in enumerate(
            registry_hive.recurse_subkeys(name_key_entry, as_json=True, fetch_values=not do_not_fetch_values)
        ):
            click.secho(json.dumps(asdict(entry), indent=4))

    click.secho(f"Completed in {time.monotonic() - start_time}s ({subkey_count} subkeys enumerated)")


@click.command()
@click.argument(
    "hive_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
)
@click.option(
    "-o",
    "output_path",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    required=True,
    help="Output path for plugins result",
)
@click.option(
    "-p",
    "--plugins",
    type=click.STRING,
    required=False,
    help="A plugin or list of plugins to execute command separated",
)
@click.option(
    "-t",
    "--hive-type",
    type=click.STRING,
    required=False,
    help="Specify a hive type, if it could not be identified for some reason",
)
@click.option(
    "-r",
    "--partial_hive_path",
    type=click.STRING,
    required=False,
    help='The path from which the partial hive actually starts, for example: -t ntuser -r "/Software" '
    "would mean this is actually a HKCU hive, starting from HKCU/Software",
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbosity")
@click.option(
    "--include-unvalidated",
    is_flag=True,
    default=False,
    help="Include plugins that don't have validation test cases. "
    "These plugins may return incomplete or inaccurate data. Use at your own risk.",
)
@click.option(
    "--continue-on-error",
    is_flag=True,
    default=False,
    help="Continue running the remaining plugins when a plugin fails, "
    'recording the failure in the result as {"error": "<message>"} instead of aborting.',
)
def run_plugins(hive_path, output_path, plugins, hive_type, partial_hive_path, verbose, include_unvalidated, continue_on_error):
    _setup_logging(verbose=verbose)
    registry_hive = RegistryHive(hive_path, hive_type=hive_type, partial_hive_path=partial_hive_path)
    click.secho(f"Loaded {len(PLUGINS)} plugins", fg="white")

    if plugins:
        plugin_names = {x.NAME for x in PLUGINS}
        plugins = plugins.split(",")
        plugins = set(plugins)
        if not plugins.issubset(plugin_names):
            click.secho(
                "Invalid plugin names given: {}".format(",".join(set(plugins) - plugin_names)),
                fg="red",
            )
            click.secho(
                "Use --help or -h to get list of plugins and their descriptions",
                fg="red",
            )
            return

    if include_unvalidated:
        click.secho(
            "Warning: Including unvalidated plugins. These may return incomplete or inaccurate data.",
            fg="yellow",
        )

    # Run relevant plugins
    plugin_results = run_relevant_plugins(
        registry_hive,
        as_json=True,
        plugins=plugins,
        include_unvalidated=include_unvalidated,
        continue_on_error=continue_on_error,
    )

    # If output path was set, dump results to disk
    if output_path:
        try:
            with open(output_path, "w") as f:
                f.write(json.dumps(plugin_results, indent=4))
        except OSError as e:
            logger.error(f"Failed to write output file {output_path}: {e}")
            return
    else:
        print(json.dumps(plugin_results, indent=4))
    click.secho(
        f"Finished: {len(plugin_results)}/{len(PLUGINS)} plugins matched the hive type",
        fg="green",
    )


@click.command(name="snapshot-timeline")
@click.argument("snapshots", nargs=-1, required=True)
@click.option(
    "-p",
    "--plugins",
    type=click.STRING,
    required=False,
    help="Comma separated plugin names, or all. Defaults to recentdocs,typed_paths when no --key-path is given.",
)
@click.option("-r", "--key-path", "key_paths", multiple=True, help="Additional registry key path to compare.")
@click.option(
    "-o",
    "output_path",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    required=False,
    help="Output path for the snapshot evidence JSON.",
)
@click.option("--sort/--no-sort", default=True, help="Sort snapshots by their observation timestamp.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbosity")
def snapshot_timeline(snapshots, plugins, key_paths, output_path, sort, verbose):
    """Compare historical hive snapshots and emit per-value evidence timelines.

    Each SNAPSHOT is either a hive path or a hive path followed by @ and an
    ISO-8601 observation timestamp, for example:

        regipy-snapshot-timeline ntuser-2020.dat@2020-01-01T00:00:00Z ntuser-2021.dat@2021-01-01T00:00:00Z

    If no timestamp is supplied, the hive header timestamp is used and marked
    as such in the output.
    """
    _setup_logging(verbose=verbose)

    parsed_snapshots = []
    for spec in snapshots:
        if "@" in spec:
            hive_path, timestamp = spec.rsplit("@", 1)
        else:
            hive_path, timestamp = spec, None
        if not os.path.exists(hive_path):
            raise click.BadParameter(f"Snapshot hive does not exist: {hive_path}")
        parsed_snapshots.append(Snapshot.from_path(hive_path, timestamp=timestamp))

    plugin_classes = None
    if plugins:
        if plugins.strip().lower() == "all":
            plugin_classes = list(PLUGINS)
        else:
            requested = {name.strip() for name in plugins.split(",") if name.strip()}
            known = {plugin.NAME for plugin in PLUGINS}
            invalid = requested - known
            if invalid:
                click.secho("Invalid plugin names given: " + ", ".join(sorted(invalid)), fg="red")
                return
            plugin_classes = [plugin for plugin in PLUGINS if plugin.NAME in requested]
    elif key_paths:
        plugin_classes = []
    # else: let compare_snapshots use its recentdocs/typed_paths default.

    result = compare_snapshots(
        parsed_snapshots,
        plugins=plugin_classes,
        key_paths=list(key_paths) or None,
        as_json=True,
        sort=sort,
    )

    rendered = json.dumps(result, indent=4)
    if output_path:
        try:
            with open(output_path, "w") as output_file:
                output_file.write(rendered)
        except OSError as e:
            logger.error(f"Failed to write output file {output_path}: {e}")
            return
    else:
        click.secho(rendered)

    snapshot_count = len(result["snapshots"])
    value_count = len(result["value_timelines"])
    click.secho(
        f"Compared {snapshot_count} snapshots, produced {value_count} value timelines",
        fg="green",
    )


@click.command()
def list_plugins():
    click.secho(
        tabulate(
            [(x.NAME, x.COMPATIBLE_HIVE, x.DESCRIPTION) for x in PLUGINS],
            headers=["Plugin Name", "Compatible hive", "Description"],
        )
    )


@click.command()
@click.argument(
    "first_hive_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
)
@click.argument(
    "second_hive_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
)
@click.option(
    "-o",
    "output_path",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    required=False,
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbosity")
def reg_diff(first_hive_path, second_hive_path, output_path, verbose):
    _setup_logging(verbose=verbose)
    REGDIFF_HEADERS = ["difference", "first_hive", "second_hive", "description"]

    found_differences = compare_hives(first_hive_path, second_hive_path, verbose=verbose)
    click.secho(f"Comparing {os.path.basename(first_hive_path)} vs {os.path.basename(second_hive_path)}")

    if output_path:
        try:
            with open(output_path, "w") as csvfile:
                csvwriter = csv.writer(csvfile, delimiter="|", quoting=csv.QUOTE_MINIMAL)
                csvwriter.writerow(REGDIFF_HEADERS)
                for difference in found_differences:
                    csvwriter.writerow(difference)
        except OSError as e:
            logger.error(f"Failed to write output file {output_path}: {e}")
            return
    else:
        click.secho(tabulate(found_differences, headers=REGDIFF_HEADERS, tablefmt="fancy_grid"))
    click.secho(f"Detected {len(found_differences)} differences", fg="green")


@click.command()
@click.argument(
    "hive_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
)
@click.option(
    "-p",
    "primary_log_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
)
@click.option(
    "-s",
    "secondary_log_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=False,
)
@click.option(
    "-o",
    "output_path",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    required=False,
)
@click.option("-v", "--verbose", is_flag=True, default=True, help="Verbosity")
def parse_transaction_log(hive_path, primary_log_path, secondary_log_path, output_path, verbose):
    _setup_logging(verbose=verbose)
    logger.info(f"Processing hive {hive_path} with transaction log {primary_log_path}")
    if secondary_log_path:
        logger.info(f"Processing hive {hive_path} with secondary transaction log {secondary_log_path}")

    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(
        hive_path,
        primary_log_path,
        secondary_log_path=secondary_log_path,
        restored_hive_path=output_path,
        verbose=verbose,
    )
    if recovered_dirty_pages_count:
        click.secho(
            f"Recovered {recovered_dirty_pages_count} dirty pages. Restored hive is at {restored_hive_path}",
            fg="green",
        )
