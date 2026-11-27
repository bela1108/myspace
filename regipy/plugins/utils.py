import json
import logging
from typing import Any, Callable, Union

from regipy import NKRecord
from regipy.plugins.coverage import (
    REASON_UNVALIDATED_PLUGIN,
    PluginCoverage,
    assess_plugin_coverage,
    build_coverage_report,
)
from regipy.plugins.plugin import PLUGINS
from regipy.plugins.validation_status import (
    is_plugin_validated,
    warn_unvalidated_plugin,
)

logger = logging.getLogger(__name__)


# Type alias for value mapping specification
# Can be:
#   - str: simple rename (registry "Foo" -> entry "foo")
#   - tuple[str, Callable]: rename + transform function
ValueSpec = Union[str, tuple[str, Callable[[Any], Any]]]


def extract_values(
    registry_key,
    value_map: dict[str, ValueSpec],
    entry: dict[str, Any],
) -> None:
    """
    Extract registry values into an entry dict using a declarative mapping.

    Args:
        registry_key: Registry key to iterate values from
        value_map: Mapping of registry value names to output specifications
        entry: Dict to populate with extracted values

    Example value_map:
        {
            "ProfileName": "profile_name",  # Simple rename
            "Enabled": ("enabled", lambda v: v == 1),  # Convert with function
            "DateCreated": ("date_created", parse_date_func),  # Custom transform
        }
    """
    for value in registry_key.iter_values():
        name = value.name
        if name not in value_map:
            continue

        spec = value_map[name]
        if isinstance(spec, str):
            entry[spec] = value.value
        else:
            output_name, converter = spec
            entry[output_name] = converter(value.value)


def dump_hive_to_json(
    registry_hive,
    output_path,
    name_key_entry: NKRecord,
    verbose=False,
    fetch_values=True,
):
    """
    Write the hive subkeys to a JSON-lines file, one line per entry.
    :param registry_hive: a RegistryHive object
    :param output_path: Output path to save the JSON
    :param name_key_entry: The NKRecord to start iterating from
    :param verbose: verbosity
    :return: The result, as dict
    """
    subkey_count = 0
    with open(output_path, mode="w") as writer:
        for subkey_count, entry in enumerate(
            registry_hive.recurse_subkeys(name_key_entry, as_json=True, fetch_values=fetch_values)
        ):
            writer.write(
                json.dumps(
                    entry.to_dict(),
                    separators=(
                        ",",
                        ":",
                    ),
                )
            )
            writer.write("\n")
    return subkey_count


def run_relevant_plugins(
    registry_hive,
    as_json=False,
    plugins=None,
    include_unvalidated=False,
    continue_on_error=False,
    include_coverage=False,
):
    """
    Execute the relevant plugins on the hive

    :param registry_hive: a RegistryHive object
    :param as_json: Whether to return result as json
    :param plugins: List of plugin to execute (names according to the NAME field in each plugin)
    :param include_unvalidated: Whether to include plugins that don't have validation test cases.
                                If False (default), only validated plugins will be executed.
                                Unvalidated plugins may return incomplete or inaccurate data.
    :param continue_on_error: Whether to continue running the remaining plugins when a plugin
                              fails. If True, a failing plugin is recorded in the result as
                              {"error": "<message>"} and the run continues. If False (default),
                              the original behavior applies: ModuleNotFoundError is logged and
                              the plugin is skipped, and any other exception propagates.
    :param include_coverage: Whether to add a reserved ``_coverage`` key describing, per plugin,
                             whether it was checked, whether its result is conclusive, and the
                             acquisition scope. Defaults to False so the original result shape is
                             preserved exactly.
    :return: The result, as dict
    """
    plugin_results = {}
    plugin_coverage: dict[str, PluginCoverage] = {}
    for plugin_class in PLUGINS:
        plugin = plugin_class(registry_hive, as_json=as_json)
        plugin_name = plugin.NAME or plugin.__class__.__name__

        # If the list of plugins is defined, but the plugin is not in the list skip it.
        if plugins and plugin.NAME not in plugins:
            continue

        # Check validation status
        if not is_plugin_validated(plugin.NAME):
            if not include_unvalidated:
                logger.debug(f"Skipping unvalidated plugin: {plugin.NAME}")
                if include_coverage:
                    plugin.skip_reason = (
                        f"Plugin '{plugin.NAME}' has no validation test case and was skipped; "
                        "pass include_unvalidated=True to run it."
                    )
                    plugin.skip_reason_code = REASON_UNVALIDATED_PLUGIN
                    plugin_coverage[plugin_name] = assess_plugin_coverage(plugin, executed=False)
                continue
            # Always warn when running unvalidated plugins
            warn_unvalidated_plugin(plugin.NAME)

        if plugin.can_run():
            try:
                plugin.executed = True
                plugin.run()
                plugin_results[plugin.NAME] = plugin.entries
                if include_coverage:
                    plugin_coverage[plugin_name] = assess_plugin_coverage(plugin, executed=True)
            except ModuleNotFoundError as e:
                plugin.error = e
                logger.error(f"Plugin {plugin.NAME} has missing dependencies")
                if include_coverage:
                    plugin_coverage[plugin_name] = assess_plugin_coverage(plugin, executed=True, error=e)
                if continue_on_error:
                    plugin_results[plugin.NAME] = {"error": str(e)}
            except Exception as e:
                plugin.error = e
                # Always log the failure for visibility, regardless of continue_on_error setting
                logger.exception(f"Plugin {plugin.NAME} failed: {e}")
                if include_coverage:
                    plugin_coverage[plugin_name] = assess_plugin_coverage(plugin, executed=True, error=e)
                if not continue_on_error:
                    raise
                # A single failing plugin must not abort the whole run -
                # record the failure and continue to the next plugin.
                plugin_results[plugin.NAME] = {"error": str(e)}
        elif include_coverage:
            plugin_coverage[plugin_name] = assess_plugin_coverage(plugin, executed=False)

    if include_coverage:
        plugin_results["_coverage"] = build_coverage_report(registry_hive, plugin_coverage)
    return plugin_results
