# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from collections import OrderedDict

import pytest

from cpe import CPE
from cpe.configuration import (
    ConfigurationExplainer,
    DeviceInventory,
    Decision,
    EXAMPLE_CONFIG,
    Observation,
    Truth,
    explain,
    explain_configuration,
    synthetic_devices,
)


def _device(device_id, components):
    return OrderedDict((
        ("device_id", device_id),
        ("components", OrderedDict(components)),
    ))


def test_synthetic_devices_cover_affected_pending_and_excluded():
    devices = synthetic_devices()

    affected = explain(EXAMPLE_CONFIG, devices["affected"])
    pending = explain(EXAMPLE_CONFIG, devices["pending"])
    excluded = explain(EXAMPLE_CONFIG, devices["excluded"])

    assert affected.status == Decision.AFFECTED
    assert pending.status == Decision.UNDETERMINED
    assert excluded.status == Decision.EXCLUDED

    assert affected["status"] == "affected"
    assert pending["status"] == "undetermined"
    assert excluded["status"] == "excluded"


def test_inventory_distinguishes_seen_absent_and_pending():
    device = _device("states", (
        ("os", OrderedDict((
            ("cpe", "cpe:/o:acme:linux:1.2"),
            ("observation", Observation.SEEN),
        ))),
        ("plugin", OrderedDict((
            ("observation", Observation.ABSENT),
        ))),
        ("mitigation", OrderedDict((
            ("observation", Observation.PENDING),
        ))),
    ))

    result = explain(EXAMPLE_CONFIG, device)
    inventory = result["inventory"]

    assert inventory["os"]["state"] == "seen"
    assert inventory["plugin"]["state"] == "absent"
    assert inventory["mitigation"]["state"] == "pending"


def test_pending_exclusion_is_unknown_not_satisfied():
    config = OrderedDict((
        ("id", "advisory"),
        ("operator", "EXCLUDE"),
        ("key", "mitigation"),
        ("cpe", "cpe:/a:acme:backup_agent:3.1:patched"),
    ))
    device = _device("pending-exclusion", (
        ("mitigation", OrderedDict((
            ("observation", Observation.PENDING),
        ))),
    ))

    result = explain(config, device)

    assert result.truth == Truth.UNKNOWN
    assert result.status == Decision.UNDETERMINED
    assert result["excluded_by"] == []
    clause = result.clauses["mitigation"]
    assert clause["evidence"][0]["observation"] == Observation.PENDING


def test_explicit_absence_can_satisfy_an_exclusion():
    config = OrderedDict((
        ("id", "advisory"),
        ("operator", "EXCLUDE"),
        ("key", "mitigation"),
        ("cpe", "cpe:/a:acme:backup_agent:3.1:patched"),
    ))
    device = _device("absent-exclusion", (
        ("mitigation", OrderedDict((
            ("observation", Observation.ABSENT),
        ))),
    ))

    result = explain(config, device)

    assert result.truth == Truth.TRUE
    assert result.status == Decision.AFFECTED


def test_or_and_evidence_contains_component_values():
    config = OrderedDict((
        ("id", "advisory"),
        ("operator", "AND"),
        ("children", [
            OrderedDict((
                ("id", "system"),
                ("key", "os"),
                ("cpe", "cpe:/o:acme:linux:1.2"),
            )),
            OrderedDict((
                ("id", "plugin"),
                ("operator", "OR"),
                ("children", [
                    OrderedDict((
                        ("key", "plugin"),
                        ("cpe", "cpe:/a:acme:backup_agent:3.0"),
                    )),
                    OrderedDict((
                        ("key", "plugin"),
                        ("cpe", "cpe:/a:acme:backup_agent:3.1"),
                    )),
                ]),
            )),
        ]),
    ))
    device = _device("evidence", (
        ("os", "cpe:/o:acme:linux:1.2"),
        ("plugin", "cpe:/a:acme:backup_agent:3.1"),
    ))

    result = explain(config, device)

    assert result.status == Decision.AFFECTED
    system_evidence = result.evidence["os"]
    assert system_evidence["observation"] == Observation.SEEN
    assert system_evidence["observed_cpe"] == "cpe:/o:acme:linux:1.2"
    assert system_evidence["components"]["vendor"]["expected"] == "acme"
    assert system_evidence["components"]["product"]["observed"] == "linux"
    assert system_evidence["components"]["version"]["matched"] is True


def test_explicit_absence_of_required_plugin_excludes_device():
    device = _device("no-plugin", (
        ("os", "cpe:/o:acme:linux:1.2"),
        ("plugin", OrderedDict((
            ("observation", Observation.ABSENT),
        ))),
        ("mitigation", OrderedDict((
            ("observation", Observation.ABSENT),
        ))),
    ))

    result = explain(EXAMPLE_CONFIG, device)

    assert result.status == Decision.EXCLUDED
    assert result["excluded_by"] == []


def test_system_version_change_only_revokes_dependent_conclusions():
    explainer = ConfigurationExplainer(EXAMPLE_CONFIG)
    explainer.add_device(synthetic_devices()["affected"])

    before = explainer.explain("device-affected")
    assert before.status == Decision.AFFECTED
    assert before.nodes["plugin-clause"].truth == Truth.TRUE

    revision = explainer.revise_system_version(
        "device-affected", "cpe:/o:acme:linux:2.0")

    assert revision["previous_status"] == Decision.AFFECTED
    assert revision["current_status"] == Decision.EXCLUDED
    assert revision["changed"] is True

    assert "system-clause" in revision.revoked
    assert "root" in revision.revoked
    assert "plugin-clause" in revision.preserved
    assert "mitigation-clause" in revision.preserved

    assert revision.current.clauses["system-clause"].truth == Truth.FALSE
    assert revision.current.clauses["plugin-clause"].truth == Truth.TRUE


def test_revision_preserves_other_devices():
    explainer = ConfigurationExplainer(EXAMPLE_CONFIG)
    for device in synthetic_devices().values():
        explainer.add_device(device)

    revision = explainer.revise_system_version(
        "device-affected", "cpe:/o:acme:linux:2.0")

    assert revision.device_id == "device-affected"
    assert explainer.explain("device-pending").status == \
        Decision.UNDETERMINED
    assert explainer.explain("device-excluded").status == Decision.EXCLUDED
    # The plugin clause of the revised device is not retracted.
    assert "plugin-clause" in revision.preserved


def test_inventory_entries_can_be_given_as_component_fields():
    device = _device("components", (
        ("os", OrderedDict((
            ("vendor", "acme"),
            ("product", "linux"),
            ("version", "1.2"),
            ("observation", Observation.SEEN),
        ))),
        ("plugin", OrderedDict((
            ("vendor", "acme"),
            ("product", "backup_agent"),
            ("version", "3.1"),
            ("observation", Observation.SEEN),
        ))),
        ("mitigation", OrderedDict((
            ("observation", Observation.ABSENT),
        ))),
    ))

    result = explain(EXAMPLE_CONFIG, device)

    assert result.status == Decision.AFFECTED


def test_explain_configuration_accepts_a_device_list():
    results = explain_configuration(
        EXAMPLE_CONFIG, list(synthetic_devices().values()))

    assert [result.status for result in results] == [
        Decision.AFFECTED,
        Decision.UNDETERMINED,
        Decision.EXCLUDED,
    ]


def test_inventory_set_returns_old_and_new_evidence():
    inventory = DeviceInventory.from_device(synthetic_devices()["affected"])
    old, new = inventory.set("os", cpe="cpe:/o:acme:linux:2.0")

    assert old is not None
    assert old.observation == Observation.SEEN
    assert new.observation == Observation.SEEN
    assert isinstance(new.cpe, CPE)
    assert new.cpe.cpe_str == "cpe:/o:acme:linux:2.0"


def test_missing_inventory_item_is_pending_and_keeps_expected_components():
    result = explain(
        EXAMPLE_CONFIG,
        _device("missing", (("os", "cpe:/o:acme:linux:1.2"),)))

    assert result.inventory["plugin"]["state"] == Observation.PENDING
    evidence = result.evidence["plugin"]
    assert evidence["observation"] == Observation.PENDING
    assert evidence["components"]["vendor"]["expected"] == "acme"
    assert evidence["components"]["product"]["expected"] == "backup_agent"


def test_exclude_list_is_shorthand_for_exclusion_nodes():
    config = OrderedDict(EXAMPLE_CONFIG)
    config = OrderedDict((
        ("id", "advisory-exclude-list"),
        ("operator", "AND"),
        ("children", EXAMPLE_CONFIG["children"][:2]),
        ("exclude", [EXAMPLE_CONFIG["children"][2]]),
    ))

    devices = synthetic_devices()
    assert explain(config, devices["affected"]).status ==         Decision.AFFECTED
    assert explain(config, devices["pending"]).status ==         Decision.UNDETERMINED
    assert explain(config, devices["excluded"]).status ==         Decision.EXCLUDED


def test_record_name_can_identify_an_inventory_component():
    device = OrderedDict((
        ("device_id", "named-records"),
        ("components", [
            OrderedDict((
                ("name", "os"),
                ("state", "seen"),
                ("cpe", "cpe:/o:acme:linux:1.2"),
            )),
            OrderedDict((
                ("name", "plugin"),
                ("state", "seen"),
                ("cpe", "cpe:/a:acme:backup_agent:3.1"),
            )),
            OrderedDict((
                ("name", "mitigation"),
                ("state", "absent"),
            )),
        ]),
    ))

    result = explain(EXAMPLE_CONFIG, device)

    assert result.status == Decision.AFFECTED
    assert result.inventory["os"]["state"] == Observation.SEEN


def test_revision_separates_invalidated_and_revalidated_conclusions():
    explainer = ConfigurationExplainer(EXAMPLE_CONFIG)
    explainer.add_device(synthetic_devices()["affected"])

    revision = explainer.revise_system_version(
        "device-affected", "cpe:/o:acme:linux:2.0")

    assert "system-clause" in revision.invalidated
    assert "plugin-clause" not in revision.invalidated
    assert revision.revalidated == []


def test_revise_system_version_accepts_a_bare_version():
    explainer = ConfigurationExplainer(EXAMPLE_CONFIG)
    explainer.add_device(synthetic_devices()["affected"])

    revision = explainer.revise_system_version(
        "device-affected", "2.0")

    assert revision.current_status == Decision.EXCLUDED
    assert revision.current.inventory["os"]["cpes"] == [
        "cpe:/o:acme:linux:2.0"]
