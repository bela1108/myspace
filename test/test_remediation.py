from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pretend
import pytest
from packaging.version import Version

import pip_audit._cli
from pip_audit._remediation import (
    RemediationCalendar,
    RemediationCalendarError,
    RemediationStatus,
    build_report,
    parse_reference,
    render_json,
    render_markdown,
)
from pip_audit._service.interface import ResolvedDependency, VulnerabilityResult

SHANGHAI = ZoneInfo("Asia/Shanghai")
UTC = timezone.utc


def _asset():
    return Path(__file__).parent / "assets" / "remediation.calendar.json"


def _calendar():
    return RemediationCalendar.load(_asset())


def _data():
    return json.loads(_asset().read_text(encoding="utf-8"))


def _by_group(report):
    return {entry.group_id: entry for entry in report.entries}


def _replay_window_data():
    return {
        "schema_version": 1,
        "timezone": "UTC",
        "maintenance_calendars": [
            {
                "effective_at": "2026-01-01T00:00:00Z",
                "windows": [{"weekdays": ["tue"], "start": "02:00", "end": "04:00"}],
                "holidays": [],
            },
            {
                "effective_at": "2026-01-07T00:00:00Z",
                "windows": [{"weekdays": ["fri"], "start": "02:00", "end": "04:00"}],
                "holidays": [],
            },
        ],
        "version_groups": [
            {
                "id": "g1",
                "package": "pkg",
                "versions": ["1.0"],
                "alerts": [
                    {
                        "id": "A",
                        "first_seen": "2026-01-05T12:00:00Z",
                        "sla_business_days": 1,
                    }
                ],
            },
            {
                "id": "g2",
                "package": "pkg",
                "versions": ["2.0"],
                "alerts": [
                    {
                        "id": "A",
                        "first_seen": "2026-01-07T12:00:00Z",
                        "sla_business_days": 1,
                    }
                ],
            },
        ],
        "patches": [
            {"group": "g1", "alert": "A", "available_at": "2026-01-05T12:00:00Z"},
            {"group": "g2", "alert": "A", "available_at": "2026-01-07T12:00:00Z"},
        ],
    }


def _replay_holiday_data():
    windows = [
        {
            "weekdays": ["mon", "tue", "wed", "thu", "fri"],
            "start": "00:00",
            "end": "23:59",
        }
    ]
    return {
        "schema_version": 1,
        "timezone": "UTC",
        "maintenance_calendars": [
            {
                "effective_at": "2026-01-01T00:00:00Z",
                "windows": windows,
                "holidays": ["2026-01-08", "2026-01-09"],
            },
            {
                "effective_at": "2026-01-10T00:00:00Z",
                "windows": windows,
                "holidays": ["2026-01-12"],
            },
        ],
        "version_groups": [
            {
                "id": "g",
                "package": "pkg",
                "versions": ["1.0"],
                "alerts": [
                    {
                        "id": "A",
                        "first_seen": "2026-01-06T00:00:00Z",
                        "sla_business_days": 3,
                    }
                ],
            }
        ],
        "patches": [
            {
                "group": "g",
                "alert": "A",
                "available_at": "2026-01-06T00:00:00Z",
                "fixed_version": "1.0.1",
            }
        ],
    }


def _cli_result():
    dep = ResolvedDependency(name="demo-pkg", version=Version("1.4.0"))
    vuln = VulnerabilityResult.create(["CVE-2026-1000"], "description", [Version("1.4.1")], None)
    return [(dep, [vuln])]


def _install_cli(monkeypatch, result):
    source = pretend.stub(fix=lambda fix: None)
    auditor = pretend.stub(audit=lambda source: result)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *args, **kwargs: source)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *args, **kwargs: auditor)


def _run_cli(monkeypatch, args):
    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *parse_args: parser.parse_args(args))
    with pytest.raises(SystemExit) as exc:
        pip_audit._cli.audit()
    return exc.value.code


def test_holiday_and_version_split_overdue_from_waiting_patch():
    report = build_report(_calendar(), datetime(2026, 11, 27, tzinfo=SHANGHAI))
    entries = _by_group(report)
    stable = entries["retail-stable"]
    legacy = entries["retail-legacy"]

    assert stable.first_seen == datetime(2026, 11, 3, 9, 0, tzinfo=SHANGHAI)
    assert stable.patch_available_at == datetime(2026, 11, 3, 15, 0, tzinfo=SHANGHAI)
    assert stable.actionable_at == datetime(2026, 11, 5, 2, 0, tzinfo=SHANGHAI)
    assert stable.due_date == date(2026, 11, 20)
    assert stable.status is RemediationStatus.Overdue

    assert legacy.status is RemediationStatus.WaitingPatch
    assert legacy.actionable_at == datetime(2026, 12, 12, 1, 0, tzinfo=SHANGHAI)
    assert legacy.projected is True

    assert report.summary["overdue_groups"] == ["retail-stable"]
    assert report.summary["waiting_patch_groups"] == ["retail-legacy"]


def test_holiday_is_replayed_even_when_a_later_calendar_removes_it():
    report = build_report(_calendar(), datetime(2026, 11, 21, tzinfo=SHANGHAI))
    stable = _by_group(report)["retail-stable"]
    assert stable.due_date == date(2026, 11, 20)
    assert stable.status is RemediationStatus.Overdue


def test_deadline_day_is_not_overdue_until_it_ends():
    report = build_report(_calendar(), datetime(2026, 11, 20, tzinfo=SHANGHAI))
    stable = _by_group(report)["retail-stable"]
    assert stable.status is RemediationStatus.Actionable
    assert stable.business_days_remaining == 0


def test_new_calendar_only_changes_windows_after_it_takes_effect():
    calendar = RemediationCalendar.from_dict(_replay_window_data())
    report = build_report(calendar, datetime(2026, 1, 20, tzinfo=UTC))
    entries = _by_group(report)

    assert entries["g1"].actionable_at == datetime(2026, 1, 6, 2, 0, tzinfo=UTC)
    assert entries["g2"].actionable_at == datetime(2026, 1, 9, 2, 0, tzinfo=UTC)
    assert calendar.next_window_start(datetime(2026, 1, 5, 12, 0, tzinfo=UTC)) == datetime(
        2026, 1, 6, 2, 0, tzinfo=UTC
    )
    assert calendar.next_window_start(datetime(2026, 1, 7, 12, 0, tzinfo=UTC)) == datetime(
        2026, 1, 9, 2, 0, tzinfo=UTC
    )


def test_business_day_deadline_replays_holiday_history():
    calendar = RemediationCalendar.from_dict(_replay_holiday_data())
    report = build_report(calendar, datetime(2026, 1, 20, tzinfo=UTC))
    entry = _by_group(report)["g"]
    assert entry.actionable_at == datetime(2026, 1, 6, 0, 0, tzinfo=UTC)
    assert entry.due_date == date(2026, 1, 14)


def test_weekly_report_recomputes_each_week():
    report = build_report(_calendar(), datetime(2026, 11, 27, tzinfo=SHANGHAI), weekly=True)
    assert report.mode == "weekly"
    assert report.weeks is not None
    rows = {row.week: row for row in report.weeks}

    assert rows["2026-W45"].evaluated_at == datetime(2026, 11, 8, 23, 59, 59, tzinfo=SHANGHAI)
    w45 = {entry.group_id: entry.status for entry in rows["2026-W45"].entries}
    assert w45 == {
        "retail-stable": RemediationStatus.Actionable,
        "retail-legacy": RemediationStatus.WaitingPatch,
    }

    w47 = {entry.group_id: entry.status for entry in rows["2026-W47"].entries}
    assert w47 == {
        "retail-stable": RemediationStatus.Overdue,
        "retail-legacy": RemediationStatus.WaitingPatch,
    }
    assert rows["2026-W48"].evaluated_at == datetime(2026, 11, 27, tzinfo=SHANGHAI)


def test_weekly_report_follows_the_reference_date():
    early = build_report(_calendar(), datetime(2026, 11, 10, tzinfo=SHANGHAI), weekly=True)
    assert early.weeks is not None
    assert [row.week for row in early.weeks] == ["2026-W45", "2026-W46"]
    assert early.weeks[-1].evaluated_at == datetime(2026, 11, 10, tzinfo=SHANGHAI)
    assert early.summary["overdue_groups"] == []
    assert _by_group(early)["retail-stable"].status is RemediationStatus.Actionable


def test_digest_is_stable_and_reference_sensitive():
    as_of = datetime(2026, 11, 27, tzinfo=SHANGHAI)
    first = build_report(_calendar(), as_of)
    second = build_report(_calendar(), as_of)
    assert first.digest == second.digest
    assert build_report(_calendar(), as_of + timedelta(days=1)).digest != first.digest
    assert build_report(_calendar(), as_of, weekly=True).digest != first.digest


def test_audit_result_annotation():
    dep = ResolvedDependency(name="demo-pkg", version=Version("1.4.0"))
    vuln = VulnerabilityResult.create(["CVE-2026-1000"], "description", [Version("1.4.1")], None)
    report = build_report(
        _calendar(),
        datetime(2026, 11, 27, tzinfo=SHANGHAI),
        {dep: [vuln]},
    )
    stable = _by_group(report)["retail-stable"]
    legacy = _by_group(report)["retail-legacy"]
    assert stable.observed is True
    assert stable.alert_observed is True
    assert stable.observed_versions == ("1.4.0",)
    assert legacy.observed is False
    assert report.summary["observed"] == 1
    assert report.summary["not_observed"] == 1


def test_renderers_include_calendar_and_weekly_sections():
    report = build_report(_calendar(), datetime(2026, 11, 27, tzinfo=SHANGHAI), weekly=True)
    payload = json.loads(render_json(report))
    assert payload["remediation_calendar"]["summary"]["overdue_groups"] == ["retail-stable"]

    markdown = render_markdown(report)
    assert "## Remediation calendar" in markdown
    assert "### Weekly report" in markdown
    assert "retail-stable" in markdown


def test_rejects_empty_calendar_versions():
    data = _data()
    data["maintenance_calendars"] = []
    with pytest.raises(RemediationCalendarError, match="at least one version"):
        RemediationCalendar.from_dict(data)


def test_rejects_duplicate_calendar_effective_at():
    data = _data()
    duplicate = json.loads(json.dumps(data["maintenance_calendars"][0]))
    data["maintenance_calendars"].append(duplicate)
    with pytest.raises(RemediationCalendarError, match="unique"):
        RemediationCalendar.from_dict(data)


def test_rejects_invalid_window():
    data = _data()
    data["maintenance_calendars"][0]["windows"][0]["end"] = "01:00"
    with pytest.raises(RemediationCalendarError, match="end must be after start"):
        RemediationCalendar.from_dict(data)


def test_rejects_unknown_timezone():
    data = _data()
    data["timezone"] = "Mars/Olympus"
    with pytest.raises(RemediationCalendarError, match="unknown timezone"):
        RemediationCalendar.from_dict(data)


def test_rejects_patch_for_unknown_group():
    data = _data()
    data["patches"][0]["group"] = "missing"
    with pytest.raises(RemediationCalendarError, match="does not match any version group"):
        RemediationCalendar.from_dict(data)


def test_rejects_invalid_version_selector():
    data = _data()
    data["version_groups"][0]["versions"] = ["not a version"]
    with pytest.raises(RemediationCalendarError, match="invalid version"):
        RemediationCalendar.from_dict(data)


def test_parse_reference_uses_start_of_day_for_dates():
    calendar = _calendar()
    assert parse_reference("2026-11-27", calendar) == datetime(2026, 11, 27, tzinfo=SHANGHAI)
    assert parse_reference("2026-11-27T12:00:00+08:00", calendar) == datetime(
        2026, 11, 27, 12, tzinfo=SHANGHAI
    )
    now = datetime(2026, 11, 27, 12, tzinfo=UTC)
    assert parse_reference(None, calendar, now=now) == now
    with pytest.raises(RemediationCalendarError):
        parse_reference("not-a-date", calendar)


def test_cli_merges_remediation_into_json(monkeypatch, capsys):
    _install_cli(monkeypatch, _cli_result())
    _run_cli(
        monkeypatch,
        [
            "--format",
            "json",
            "--progress-spinner",
            "off",
            "--remediation-calendar",
            str(_asset()),
            "--as-of",
            "2026-11-27",
            "--weekly-report",
        ],
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["dependencies"][0]["name"] == "demo-pkg"
    remediation = payload["remediation"]
    assert remediation["mode"] == "weekly"
    assert remediation["as_of"] == "2026-11-27T00:00:00+08:00"
    assert remediation["summary"]["overdue_groups"] == ["retail-stable"]
    assert remediation["summary"]["waiting_patch_groups"] == ["retail-legacy"]
    assert remediation["summary"]["observed"] == 1
    assert len(remediation["weeks"]) >= 1


def test_cli_writes_sidecar_report(monkeypatch, capsys, tmp_path):
    _install_cli(monkeypatch, _cli_result())
    sidecar = tmp_path / "remediation.json"
    _run_cli(
        monkeypatch,
        [
            "--format",
            "columns",
            "--progress-spinner",
            "off",
            "--remediation-calendar",
            str(_asset()),
            "--as-of",
            "2026-11-27",
            "--remediation-output",
            str(sidecar),
        ],
    )
    captured = capsys.readouterr()
    assert "demo-pkg" in captured.out
    assert "remediation_calendar" not in captured.out
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert payload["remediation_calendar"]["mode"] == "calendar"
    assert payload["remediation_calendar"]["summary"]["overdue_groups"] == ["retail-stable"]


def test_cli_markdown_sidecar_report(monkeypatch, capsys, tmp_path):
    _install_cli(monkeypatch, _cli_result())
    sidecar = tmp_path / "remediation.md"
    _run_cli(
        monkeypatch,
        [
            "--format",
            "columns",
            "--progress-spinner",
            "off",
            "--remediation-calendar",
            str(_asset()),
            "--as-of",
            "2026-11-27",
            "--remediation-output",
            str(sidecar),
            "--remediation-format",
            "markdown",
        ],
    )
    assert sidecar.read_text(encoding="utf-8").startswith("## Remediation calendar")


def test_cli_requires_calendar_for_remediation_options(monkeypatch):
    _install_cli(monkeypatch, _cli_result())
    code = _run_cli(monkeypatch, ["--as-of", "2026-11-27"])
    assert code == 2


def test_cli_rejects_invalid_calendar(monkeypatch, tmp_path):
    _install_cli(monkeypatch, _cli_result())
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    code = _run_cli(
        monkeypatch,
        [
            "--progress-spinner",
            "off",
            "--remediation-calendar",
            str(bad),
        ],
    )
    assert code == 1


def test_future_calendar_version_does_not_change_a_past_report():
    data = _data()
    calendar_before = RemediationCalendar.from_dict(data)
    future = json.loads(json.dumps(data["maintenance_calendars"][1]))
    future["effective_at"] = "2027-01-01T00:00:00+08:00"
    future["holidays"] = ["2026-11-05"]
    data["maintenance_calendars"].append(future)
    calendar_after = RemediationCalendar.from_dict(data)

    as_of = datetime(2026, 11, 27, tzinfo=SHANGHAI)
    before = build_report(calendar_before, as_of)
    after = build_report(calendar_after, as_of)
    assert before.digest == after.digest
    assert before.to_dict() == after.to_dict()


def test_effective_calendar_version_changes_the_remaining_schedule():
    data = _data()
    revised = json.loads(json.dumps(data["maintenance_calendars"][0]))
    revised["effective_at"] = "2026-11-04T00:00:00+08:00"
    revised["holidays"] = ["2026-11-05", "2026-11-06", "2026-11-19"]
    data["maintenance_calendars"].append(revised)
    calendar = RemediationCalendar.from_dict(data)

    report = build_report(calendar, datetime(2026, 11, 27, tzinfo=SHANGHAI))
    stable = _by_group(report)["retail-stable"]
    assert stable.actionable_at == datetime(2026, 11, 10, 2, 0, tzinfo=SHANGHAI)


def test_toml_calendar_is_supported():
    path = Path(__file__).parent / "assets" / "remediation.calendar.toml"
    calendar = RemediationCalendar.load(path)
    report = build_report(calendar, datetime(2026, 1, 10, tzinfo=UTC))
    entry = _by_group(report)["g"]
    assert entry.actionable_at == datetime(2026, 1, 5, 0, 0, tzinfo=UTC)
    assert entry.due_date == date(2026, 1, 5)
    assert entry.status is RemediationStatus.Overdue


def test_cli_outputs_calendar_without_audit_rows(monkeypatch, capsys):
    dep = ResolvedDependency(name="demo-pkg", version=Version("1.4.0"))
    _install_cli(monkeypatch, [(dep, [])])
    parser = pip_audit._cli._parser()
    args = [
        "--format",
        "columns",
        "--progress-spinner",
        "off",
        "--remediation-calendar",
        str(_asset()),
        "--as-of",
        "2026-11-27",
    ]
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *parse_args: parser.parse_args(args))
    pip_audit._cli.audit()
    payload = json.loads(capsys.readouterr().out)
    assert payload["remediation_calendar"]["summary"]["overdue_groups"] == ["retail-stable"]


def test_projection_uses_only_calendars_known_at_the_reference_date():
    as_of = datetime(2026, 11, 10, tzinfo=SHANGHAI)
    report = build_report(_calendar(), as_of)
    legacy = _by_group(report)["retail-legacy"]
    assert legacy.actionable_at == datetime(2026, 12, 15, 2, 0, tzinfo=SHANGHAI)


def test_weekly_projection_advances_when_a_calendar_arrives():
    report = build_report(_calendar(), datetime(2026, 11, 27, tzinfo=SHANGHAI), weekly=True)
    assert report.weeks is not None
    rows = {row.week: row for row in report.weeks}
    early = {entry.group_id: entry for entry in rows["2026-W45"].entries}
    late = {entry.group_id: entry for entry in rows["2026-W48"].entries}
    assert early["retail-legacy"].actionable_at == datetime(2026, 12, 15, 2, 0, tzinfo=SHANGHAI)
    assert late["retail-legacy"].actionable_at == datetime(2026, 12, 12, 1, 0, tzinfo=SHANGHAI)


def test_build_report_accepts_a_date_reference():
    report = build_report(_calendar(), date(2026, 11, 27))
    assert report.as_of == datetime(2026, 11, 27, tzinfo=SHANGHAI)
    assert report.summary["overdue_groups"] == ["retail-stable"]


def test_cli_writes_audit_file_and_remediation_stdout(monkeypatch, capsys, tmp_path):
    _install_cli(monkeypatch, _cli_result())
    audit_file = tmp_path / "audit.json"
    _run_cli(
        monkeypatch,
        [
            "--format",
            "json",
            "--progress-spinner",
            "off",
            "--output",
            str(audit_file),
            "--remediation-calendar",
            str(_asset()),
            "--as-of",
            "2026-11-27",
        ],
    )
    captured = capsys.readouterr()
    assert "--- remediation calendar ---" not in captured.out
    remediation = json.loads(captured.out)["remediation_calendar"]
    assert remediation["summary"]["overdue_groups"] == ["retail-stable"]
    audit = json.loads(audit_file.read_text(encoding="utf-8"))
    assert audit["dependencies"][0]["name"] == "demo-pkg"


def test_load_accepts_string_paths():
    calendar = RemediationCalendar.load(str(_asset()))
    assert [group.id for group in calendar.groups] == [
        "retail-stable",
        "retail-legacy",
    ]
