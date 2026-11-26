import datetime as dt
import struct

from regipy.testimony import (
    ChangeNotice,
    DependencyScope,
    InterpretationInfo,
    OfflineExport,
    ReceiptRecorder,
    SourceSnapshot,
    audit_export,
    build_offline_export,
    dumps_offline_export,
    read_offline_export,
    write_offline_export,
)
from regipy.utils import convert_wintime

RUN_PLUGIN = "synthetic_run_activity"
INSTALL_PLUGIN = "synthetic_install_activity"
OLD_PLUGIN_VERSION = "1.0.0"
NEW_PLUGIN_VERSION = "2.0.0"

ALPHA_KEY = r"SyntheticHive\Cases\Alpha"
BETA_KEY = r"SyntheticHive\Cases\Beta"

ALPHA_LAST_RUN_FILETIME = 133_800_000_000_000_000
BETA_INSTALL_FILETIME = 133_900_000_000_000_000


def filetime_utc(raw_value: bytes) -> str:
    timestamp = struct.unpack("<Q", raw_value)[0]
    return convert_wintime(timestamp, as_json=True)


def filetime_utc_plus_eight(raw_value: bytes) -> str:
    timestamp = struct.unpack("<Q", raw_value)[0]
    parsed = convert_wintime(timestamp)
    return (parsed + dt.timedelta(hours=8)).isoformat()


def synthetic_batch() -> dict[str, dict[str, bytes]]:
    return {
        ALPHA_KEY: {
            "LastRunTime": struct.pack("<Q", ALPHA_LAST_RUN_FILETIME),
            "RunCount": struct.pack("<I", 3),
        },
        BETA_KEY: {
            "InstallTime": struct.pack("<Q", BETA_INSTALL_FILETIME),
            "Publisher": b"Contoso Ltd",
        },
    }


def run_activity_plugin(batch, *, plugin_version=OLD_PLUGIN_VERSION, time_interpreter=filetime_utc):
    recorder = ReceiptRecorder(plugin_name=RUN_PLUGIN, plugin_version=plugin_version)
    raw_time = batch[ALPHA_KEY]["LastRunTime"]
    raw_count = batch[ALPHA_KEY]["RunCount"]

    time_dependency = recorder.observe(
        ALPHA_KEY,
        "LastRunTime",
        data=raw_time,
        value_type="REG_QWORD",
        hive_name="SYNTHETIC_HIVE",
    )
    count_dependency = recorder.observe(
        ALPHA_KEY,
        "RunCount",
        data=raw_count,
        value_type="REG_DWORD",
        hive_name="SYNTHETIC_HIVE",
    )

    time_conclusion = {
        "testimony_id": "T-RUN-TIME",
        "case_id": "CASE-42",
        "last_run": time_interpreter(raw_time),
        "source_value": "LastRunTime",
    }
    count_value = struct.unpack("<I", raw_count)[0]
    count_conclusion = {
        "testimony_id": "T-RUN-COUNT",
        "case_id": "CASE-42",
        "run_count": count_value,
        "repeat_execution": count_value > 1,
    }

    interpretation_version = "2.0.0" if time_interpreter is filetime_utc_plus_eight else "1.0.0"
    time_receipt = recorder.receipt(
        "T-RUN-TIME",
        time_conclusion,
        [time_dependency],
        interpretation={
            "name": "run_time_policy",
            "version": interpretation_version,
            "definition": {
                "epoch": "1601-01-01T00:00:00Z",
                "unit": "100ns",
                "display_offset": "+08:00" if interpretation_version == "2.0.0" else "Z",
            },
        },
    )
    count_receipt = recorder.receipt(
        "T-RUN-COUNT",
        count_conclusion,
        [count_dependency],
        interpretation={
            "name": "dword_count_policy",
            "version": "1.0.0",
            "definition": {"byte_order": "little", "conclusion": "repeat_execution when count > 1"},
        },
    )
    return [time_conclusion, count_conclusion], [time_receipt, count_receipt]


def install_activity_plugin(batch):
    recorder = ReceiptRecorder(plugin_name=INSTALL_PLUGIN, plugin_version=OLD_PLUGIN_VERSION)
    raw_time = batch[BETA_KEY]["InstallTime"]
    raw_publisher = batch[BETA_KEY]["Publisher"]

    time_dependency = recorder.observe(
        BETA_KEY,
        "InstallTime",
        data=raw_time,
        value_type="REG_QWORD",
        hive_name="SYNTHETIC_HIVE",
    )
    publisher_dependency = recorder.observe(
        BETA_KEY,
        "Publisher",
        data=raw_publisher,
        value_type="REG_SZ",
        hive_name="SYNTHETIC_HIVE",
    )

    time_conclusion = {
        "testimony_id": "T-INSTALL-TIME",
        "case_id": "CASE-43",
        "installed_at": filetime_utc(raw_time),
    }
    publisher_conclusion = {
        "testimony_id": "T-PUBLISHER",
        "case_id": "CASE-43",
        "publisher": raw_publisher.decode("utf-8"),
    }

    time_receipt = recorder.receipt(
        "T-INSTALL-TIME",
        time_conclusion,
        [time_dependency],
        interpretation={
            "name": "install_time_policy",
            "version": "1.0.0",
            "definition": {"epoch": "1601-01-01T00:00:00Z", "unit": "100ns", "display_offset": "Z"},
        },
    )
    publisher_receipt = recorder.receipt(
        "T-PUBLISHER",
        publisher_conclusion,
        [publisher_dependency],
        interpretation={
            "name": "literal_string_policy",
            "version": "1.0.0",
            "definition": {"encoding": "utf-8", "transform": "none"},
        },
    )
    return [time_conclusion, publisher_conclusion], [time_receipt, publisher_receipt]


def build_v1_export(batch):
    run_findings, run_receipts = run_activity_plugin(batch)
    install_findings, install_receipts = install_activity_plugin(batch)
    return build_offline_export(
        run_findings + install_findings,
        run_receipts + install_receipts,
        metadata={"case_batch": "SYNTHETIC-SMALL-BATCH", "hive": "SYNTHETIC_HIVE"},
    )


def current_interpretations():
    definitions = [
        InterpretationInfo("run_time_policy", "1.0.0", definition={"display_offset": "Z"}),
        InterpretationInfo("run_time_policy", "2.0.0", definition={"display_offset": "+08:00"}),
        InterpretationInfo("dword_count_policy", "1.0.0"),
        InterpretationInfo("install_time_policy", "1.0.0"),
        InterpretationInfo("literal_string_policy", "1.0.0"),
    ]
    return {(item.name, item.version): item for item in definitions}


def scoped_time_change():
    return ChangeNotice(
        change_id="TIME-INTERP-2026-01",
        plugin_name=RUN_PLUGIN,
        old_plugin_versions=(OLD_PLUGIN_VERSION,),
        new_plugin_version=NEW_PLUGIN_VERSION,
        interpretation_name="run_time_policy",
        old_interpretation_version="1.0.0",
        new_interpretation_version="2.0.0",
        affected_scopes=(DependencyScope(value_name="LastRunTime", component="value"),),
        reason="LastRunTime display basis changed from UTC to UTC+08:00",
    )


def audit_upgrade(export, batch):
    return audit_export(
        export,
        active_plugins={RUN_PLUGIN: NEW_PLUGIN_VERSION, INSTALL_PLUGIN: OLD_PLUGIN_VERSION},
        interpretations=current_interpretations(),
        changes=[scoped_time_change()],
        source=SourceSnapshot(batch),
    )


def test_export_ids_and_bytes_are_deterministic(tmp_path):
    batch = synthetic_batch()
    first = build_v1_export(batch)
    second = build_v1_export(batch)

    assert dumps_offline_export(first) == dumps_offline_export(second)
    assert [item["receipt_id"] for item in first.receipts] == [item["receipt_id"] for item in second.receipts]

    export_path = tmp_path / "testimony-export.json"
    write_offline_export(first, export_path)
    on_disk = export_path.read_text(encoding="utf-8")
    write_offline_export(second, export_path)
    assert export_path.read_text(encoding="utf-8") == on_disk
    assert on_disk.endswith("\n")


def test_only_time_testimony_from_changed_plugin_is_suspended(tmp_path):
    batch = synthetic_batch()
    export = build_v1_export(batch)
    export_path = tmp_path / "v1-export.json"
    write_offline_export(export, export_path)

    loaded = read_offline_export(export_path)
    report = audit_upgrade(loaded, batch)

    assert report.total == 4
    assert [item.testimony_id for item in report.suspended] == ["T-RUN-TIME"]
    assert [item.testimony_id for item in report.reusable] == [
        "T-INSTALL-TIME",
        "T-PUBLISHER",
        "T-RUN-COUNT",
    ]
    assert report.missing_interpretation == []
    assert report.invalid == []

    suspended = report.suspended[0]
    assert suspended.affected_dependencies[0]["key_path"] == ALPHA_KEY
    assert suspended.affected_dependencies[0]["value_name"] == "LastRunTime"
    assert suspended.affected_dependencies[0]["sha256"]
    assert "TIME-INTERP-2026-01" in suspended.reasons[0]

    reusable_count = next(item for item in report.reusable if item.testimony_id == "T-RUN-COUNT")
    assert "scoped outside this testimony" in reusable_count.explanations[0]
    assert reusable_count.dependencies[0]["value_name"] == "RunCount"

    markdown = report.to_markdown()
    assert "`T-RUN-TIME`" in markdown
    assert "`T-RUN-COUNT`" in markdown
    assert "`T-INSTALL-TIME`" in markdown


def test_unscoped_plugin_upgrade_conservatively_suspends_whole_plugin():
    batch = synthetic_batch()
    export = build_v1_export(batch)
    report = audit_export(
        export,
        active_plugins={RUN_PLUGIN: NEW_PLUGIN_VERSION, INSTALL_PLUGIN: OLD_PLUGIN_VERSION},
        interpretations=current_interpretations(),
        changes=[ChangeNotice(plugin_name=RUN_PLUGIN, reason="opaque release")],
        source=SourceSnapshot(batch),
    )

    assert {item.testimony_id for item in report.suspended} == {"T-RUN-TIME", "T-RUN-COUNT"}
    assert {item.testimony_id for item in report.reusable} == {"T-INSTALL-TIME", "T-PUBLISHER"}


def test_old_export_remains_readable_but_reports_missing_interpretation(tmp_path):
    dependency = ReceiptRecorder(
        plugin_name="legacy_time_plugin",
        plugin_version="0.9.0",
    ).observe(r"Legacy\Case", "LegacyTime", observed_value=133_000_000_000_000_000)
    conclusion = {"testimony_id": "T-LEGACY-LOCAL", "old_display_time": "2022-01-01 00:00:00"}
    receipt = ReceiptRecorder(
        plugin_name="legacy_time_plugin",
        plugin_version="0.9.0",
    ).receipt(
        "T-LEGACY-LOCAL",
        conclusion,
        [dependency],
        interpretation_name="legacy_local_filetime_policy",
        interpretation_version="0.9.0",
        interpretation_definition={"timezone": "host-local", "ambiguous_dst": "caller-confirmed"},
    )
    old_export = build_offline_export([conclusion], [receipt])
    export_path = tmp_path / "legacy-export.json"
    write_offline_export(old_export, export_path)

    loaded = read_offline_export(export_path)
    assert isinstance(loaded, OfflineExport)
    assert loaded.findings[0]["old_display_time"] == "2022-01-01 00:00:00"

    report = audit_export(
        loaded,
        active_plugins={"legacy_time_plugin": "0.9.0"},
        interpretations=[],
    )
    assert len(report.missing_interpretation) == 1
    missing = report.missing_interpretation[0]
    assert missing.testimony_id == "T-LEGACY-LOCAL"
    assert missing.missing_interpretation is True
    assert "legacy_local_filetime_policy@0.9.0" in missing.reasons[0]
    assert report.reusable == []
    assert report.review_queue[0].testimony_id == "T-LEGACY-LOCAL"


def test_source_value_change_is_detected_separately():
    batch = synthetic_batch()
    export = build_v1_export(batch)
    tampered_batch = synthetic_batch()
    tampered_batch[ALPHA_KEY]["LastRunTime"] = struct.pack("<Q", ALPHA_LAST_RUN_FILETIME + 10)

    report = audit_upgrade(export, tampered_batch)
    time_finding = next(item for item in report.findings if item.testimony_id == "T-RUN-TIME")
    assert time_finding.disposition == "suspended"
    assert any("source fingerprint changed" in reason for reason in time_finding.reasons)


def test_new_time_interpretation_produces_different_conclusion_but_stable_receipt_shape():
    old_findings, old_receipts = run_activity_plugin(synthetic_batch())
    new_findings, new_receipts = run_activity_plugin(
        synthetic_batch(),
        plugin_version=NEW_PLUGIN_VERSION,
        time_interpreter=filetime_utc_plus_eight,
    )

    assert old_findings[0]["last_run"] != new_findings[0]["last_run"]
    assert old_receipts[0].plugin.version == OLD_PLUGIN_VERSION
    assert new_receipts[0].plugin.version == NEW_PLUGIN_VERSION
    assert old_receipts[0].interpretation.version == "1.0.0"
    assert new_receipts[0].interpretation.version == "2.0.0"
    assert old_receipts[0].dependencies[0].sha256 == new_receipts[0].dependencies[0].sha256
