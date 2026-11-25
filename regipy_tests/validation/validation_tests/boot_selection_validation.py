from regipy.plugins.bcd.boot_selection import BootSelectionPlugin
from regipy_tests.validation.validation import ValidationCase


class BootSelectionPluginValidationCase(ValidationCase):
    plugin = BootSelectionPlugin
    test_hive_file_name = "BCD.xz"

    def custom_test(self):
        output = self.plugin_output
        assert output is not None

        assert output["boot_manager"]["guid"] == "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
        assert output["boot_manager"]["role"] == "boot_manager"

        assert output["default_entry"]["guid"] == "{733b62e5-f608-11eb-825c-c112f60133ab}"
        assert output["default_entry"]["name"] == "Windows 10"
        assert output["default_entry"]["role"] == "boot_loader"
        assert output["default_entry"]["source_key"].endswith("\\Elements\\23000003\\Element")

        assert [entry["guid"] for entry in output["display_order"]] == ["{733b62e5-f608-11eb-825c-c112f60133ab}"]
        assert output["selected_entry"]["basis"] == "bcd_default"
        assert output["selected_entry"]["certainty"] == "configured_default"
        assert output["conclusion"]["actual_selection_known"] is False
        assert "does not prove" in output["conclusion"]["statement"]
        assert output["missing_objects"] == []

        self.expected_entries_count = len(output)
