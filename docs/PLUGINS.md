## regipy Plugins

* The plugin system is a robust and extensive feature that auto-detects the hive type and execute the relevant plugins.

To see a comprehensive list, please refer to the [Validation cases report](../validation/plugin_validation.md)

## Contributing new plugins
Adding a new plugin is very straight forward:
1. Copy the `regipy/plugins/plugin_template.py` file to the relevant folder (according to hive type)
2. Update the code:
   * Update the `NAME` parameter and the Class name accordingly (NAME in snake case, Class name in camel case)
   * Feel free to use/add any utility function to `regipy/utils.py` 
   * Import your class in `regipy/plugins/__init__.py`
3. Add a [validation case](../README.md#validation-cases). This is mandatory and replaces the old regipy tests.

## Evidence coverage

An empty plugin result is ambiguous by itself: the plugin may have run over a
complete hive and found nothing, it may never have run because the hive type was
not recognized, or the acquisition may only cover part of the hive. Pass
`include_coverage=True` to `run_relevant_plugins()` (or `--include-coverage` /
`--coverage` to `regipy-plugins-run`) to add a reserved `_coverage` section:

* `status: "no_results"` - the plugin ran over the full hive and found no records; absence is conclusive.
* `status: "partial_scope"` - the plugin ran, but only the recorded acquisition scope is covered; the result is not conclusive.
* `status: "not_checked"` - the plugin had no precondition to run (for example an unrecognized/incompatible hive type, or an unvalidated plugin was skipped).
* `status: "results"` - matching records were found.
* `status: "error"` - the plugin failed before a complete result could be assessed.

Each entry also carries `checked`, `conclusive`, `partial_hive_path`, and a
human-readable `reason`. Default output is unchanged when coverage is not
requested.
