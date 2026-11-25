"""Tests for BCD role and boot-selection analysis."""

from regipy.bcd import analyze_boot_selection, read_bcd_roles
from regipy.plugins.bcd.boot_selection import BootSelectionPlugin

BOOT_MANAGER = "{11111111-1111-1111-1111-111111111111}"
DEFAULT_OS = "{22222222-2222-2222-2222-222222222222}"
TEMPORARY_OS = "{33333333-3333-3333-3333-333333333333}"
MISSING_OS = "{44444444-4444-4444-4444-444444444444}"


def synthetic_bcd_model(with_temporary=True):
    """A purely synthetic BCD model; no binary hive is involved."""
    objects = {
        BOOT_MANAGER: {
            "type": 0x10100002,
            "description": {"type": 0x10100002, "name": "Windows Boot Manager"},
            "elements": {
                0x23000003: DEFAULT_OS,
                0x24000001: [DEFAULT_OS, TEMPORARY_OS],
            },
        },
        DEFAULT_OS: {
            "type": 0x10200003,
            "name": "Windows Default",
            "elements": {0x12000002: "\\Windows\\system32\\winload.efi"},
        },
        TEMPORARY_OS: {
            "type": 0x10200003,
            "name": "Windows Temporary",
            "elements": {0x12000002: "\\Windows\\system32\\winload.efi"},
        },
    }
    if not with_temporary:
        objects.pop(TEMPORARY_OS)
    return {"objects": objects}


def test_synthetic_default_is_configuration_not_actual_selection():
    result = analyze_boot_selection(synthetic_bcd_model())

    assert result["boot_manager"]["guid"] == BOOT_MANAGER
    assert result["boot_manager"]["role"] == "boot_manager"
    assert result["default_entry"]["guid"] == DEFAULT_OS
    assert result["default_entry"]["source_key"].endswith("\\Elements\\23000003\\Element")
    assert [entry["guid"] for entry in result["display_order"]] == [DEFAULT_OS, TEMPORARY_OS]

    assert result["selected_entry"]["guid"] == DEFAULT_OS
    assert result["selected_entry"]["basis"] == "bcd_default"
    assert result["selected_entry"]["certainty"] == "configured_default"
    assert result["conclusion"]["actual_selection_known"] is False
    assert result["actual_selection_known"] is False
    assert result["actual_selection_guid"] is None
    assert result["certainty"] == "configured_default"

    actual_claims = [claim for claim in result["claims"] if claim["claim"] == "actual_last_selection"]
    assert len(actual_claims) == 1
    assert actual_claims[0]["provable"] is False
    assert actual_claims[0]["source_key"] is None


def test_synthetic_one_time_selection_observation_is_observed():
    result = analyze_boot_selection(
        synthetic_bcd_model(),
        observed_selection={"guid": TEMPORARY_OS, "source_key": "case-42:boot-menu-observation"},
    )

    assert result["observation"]["guid"] == TEMPORARY_OS
    assert result["observation"]["provided"] is True
    assert result["selected_entry"]["guid"] == TEMPORARY_OS
    assert result["selected_entry"]["basis"] == "caller_observation"
    assert result["selected_entry"]["certainty"] == "observed"
    assert result["selected_entry"]["source_key"] == "case-42:boot-menu-observation"
    assert result["conclusion"]["actual_selection_known"] is True
    assert result["actual_selection_guid"] == TEMPORARY_OS
    assert result["certainty"] == "observed"

    observed_claims = [claim for claim in result["claims"] if claim["claim"] == "observed_selection"]
    assert len(observed_claims) == 1
    assert observed_claims[0]["provable"] is True
    assert observed_claims[0]["source_key"] == "case-42:boot-menu-observation"


def test_removing_the_observation_returns_to_configured_default_only():
    observed = analyze_boot_selection(synthetic_bcd_model(), observed_selection=TEMPORARY_OS)
    assert observed["conclusion"]["actual_selection_known"] is True

    without_observation = analyze_boot_selection(synthetic_bcd_model())

    assert without_observation["default_entry"]["guid"] == DEFAULT_OS
    assert without_observation["selected_entry"]["guid"] == DEFAULT_OS
    assert without_observation["selected_entry"]["basis"] == "bcd_default"
    assert without_observation["conclusion"]["actual_selection_known"] is False
    assert without_observation["actual_selection_guid"] is None
    assert without_observation["certainty"] == "configured_default"
    assert "does not prove" in without_observation["conclusion"]["statement"]


def test_missing_observation_object_is_reported_and_not_resolved():
    result = analyze_boot_selection(
        synthetic_bcd_model(),
        observed_selection={"guid": MISSING_OS, "source_key": "case-42:boot-menu-observation"},
    )

    assert result["selected_entry"]["guid"] == MISSING_OS
    assert result["selected_entry"]["resolved"] is False
    assert result["conclusion"]["actual_selection_known"] is False
    assert result["certainty"] == "unresolved"
    assert any(
        item["guid"] == MISSING_OS and item["referenced_as"] == "observed_selection" for item in result["missing_objects"]
    )


def test_missing_default_object_degrades_to_unresolved():
    model = synthetic_bcd_model()
    model["objects"][BOOT_MANAGER]["elements"][0x23000003] = MISSING_OS

    result = analyze_boot_selection(model)

    assert result["default_entry"]["guid"] == MISSING_OS
    assert result["default_entry"]["resolved"] is False
    assert result["selected_entry"]["resolved"] is False
    assert result["conclusion"]["actual_selection_known"] is False
    assert result["certainty"] == "unresolved"
    assert any(item["guid"] == MISSING_OS and item["referenced_as"] == "default_entry" for item in result["missing_objects"])
    assert "does not define a resolvable default" in result["conclusion"]["statement"]


def test_read_bcd_roles_decodes_object_roles():
    roles = {entry["guid"]: entry for entry in read_bcd_roles(synthetic_bcd_model())}

    assert roles[BOOT_MANAGER]["role"] == "boot_manager"
    assert roles[BOOT_MANAGER]["role_detail"] == "windows_boot_manager"
    assert roles[DEFAULT_OS]["role"] == "boot_loader"
    assert roles[DEFAULT_OS]["role_detail"] == "windows_boot_loader"
    assert roles[DEFAULT_OS]["source_key"].startswith("\\Objects\\")


def test_real_bcd_default_is_not_reported_as_actual_selection(bcd_hive):
    from regipy.registry import RegistryHive

    result = BootSelectionPlugin(RegistryHive(bcd_hive), as_json=True)
    result.run()

    assert result.entries["boot_manager"]["guid"] == "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
    assert result.entries["default_entry"]["guid"] == "{733b62e5-f608-11eb-825c-c112f60133ab}"
    assert result.entries["default_entry"]["name"] == "Windows 10"
    assert result.entries["selected_entry"]["basis"] == "bcd_default"
    assert result.entries["conclusion"]["actual_selection_known"] is False
    assert result.entries["missing_objects"] == []


def test_temporary_option_outside_display_order_is_observed_with_caveat():
    model = synthetic_bcd_model()
    model["objects"][BOOT_MANAGER]["elements"][0x24000001] = [DEFAULT_OS]

    observed = analyze_boot_selection(
        model,
        observed_selection={"guid": TEMPORARY_OS, "source_key": "case-42:boot-menu-observation"},
    )

    assert observed["selected_entry"]["guid"] == TEMPORARY_OS
    assert observed["selected_entry"]["basis"] == "caller_observation"
    assert observed["selected_entry"]["certainty"] == "observed"
    assert observed["observation"]["in_display_order"] is False
    assert observed["observed_selection_in_display_order"] is False
    assert "temporary option" in observed["conclusion"]["statement"]
    assert any(
        claim["claim"] == "observed_selection_in_display_order" and claim["provable"] is True for claim in observed["claims"]
    )

    without_observation = analyze_boot_selection(model)

    assert without_observation["selected_entry"]["guid"] == DEFAULT_OS
    assert without_observation["conclusion"]["actual_selection_known"] is False
    assert without_observation["certainty"] == "configured_default"
    assert "does not prove" in without_observation["conclusion"]["statement"]


def test_observation_context_uses_manager_whose_display_order_lists_the_entry():
    firmware_manager = "{55555555-5555-5555-5555-555555555555}"
    model = synthetic_bcd_model()
    model["objects"][BOOT_MANAGER]["elements"][0x24000001] = [DEFAULT_OS]
    model["objects"][firmware_manager] = {
        "type": 0x10100001,
        "name": "Firmware Boot Manager",
        "elements": {0x24000001: [TEMPORARY_OS, BOOT_MANAGER]},
    }

    result = analyze_boot_selection(model, observed_selection=TEMPORARY_OS)

    assert result["selection_context"]["boot_manager_guid"] == firmware_manager
    assert result["selection_context"]["display_order_source_key"].endswith("\\Elements\\24000001\\Element")
    assert result["selection_path"][0]["guid"] == firmware_manager
    assert result["selection_path"][0]["relationship"] == "boot_manager"
    assert result["selection_path"][1]["guid"] == TEMPORARY_OS


def test_missing_display_order_object_is_reported_without_breaking_default():
    model = synthetic_bcd_model()
    model["objects"][BOOT_MANAGER]["elements"][0x24000001] = [DEFAULT_OS, MISSING_OS]

    result = analyze_boot_selection(model)

    assert result["default_entry"]["guid"] == DEFAULT_OS
    assert result["selected_entry"]["guid"] == DEFAULT_OS
    assert any(item["guid"] == MISSING_OS and item["referenced_as"] == "display_order" for item in result["missing_objects"])


def test_no_boot_manager_is_reported_as_missing():
    result = analyze_boot_selection({"objects": {}})

    assert result["boot_manager"] is None
    assert result["selected_entry"]["resolved"] is False
    assert result["conclusion"]["actual_selection_known"] is False
    assert result["certainty"] == "unresolved"
    assert any(item["referenced_as"] == "boot_manager" for item in result["missing_objects"])
