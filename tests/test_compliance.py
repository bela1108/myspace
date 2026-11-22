from __future__ import annotations

import json
from pathlib import Path

import pytest
from jinja2 import DictLoader
from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2.compliance import main
from jinja2.compliance import ManagedSection
from jinja2.compliance import MarkerSource
from jinja2.compliance import review_file
from jinja2.compliance import review_template
from jinja2.compliance import ReviewConfig
from jinja2.compliance import ReviewError

EXAMPLE_ROOT = Path(__file__).parent.parent / "examples" / "compliance"


def _review(
    source: str,
    *,
    loader: DictLoader | None = None,
    name: str = "t.html",
    marker: MarkerSource | str = "host_notice",
):
    return review_template(
        source,
        managed_sections=["impact"],
        marker=marker,
        template_name=name,
        loader=loader,
    )


def test_marker_variable_satisfies_requirement() -> None:
    result = _review("{{ impact }}{{ host_notice }}")

    assert result.status == "pass", result.format_text()


def test_marker_literal_in_template_body_does_not_count() -> None:
    result = _review("{{ impact }}HOST NOTICE: host_notice")

    assert result.status == "fail"
    finding = result.errors[0]
    assert finding.code == "E_MISSING_MARKER"
    assert finding.section == "impact"


def test_branch_without_marker_reports_reachable_condition() -> None:
    result = _review("{% if visible %}{{ host_notice }}{% endif %}{{ impact }}")

    assert result.status == "fail"
    finding = result.errors[0]
    assert finding.code == "E_MISSING_MARKER"
    assert [condition.expression for condition in finding.path] == ["visible"]
    assert finding.path[0].truth is False


def test_empty_loop_is_reported_as_the_missing_path() -> None:
    result = _review("{% for item in items %}{{ host_notice }}{% endfor %}{{ impact }}")

    assert result.status == "fail"
    text = result.format_text()
    assert "items is empty" in text
    assert "E_MISSING_MARKER" in text


def test_section_and_marker_inside_same_loop_pass() -> None:
    result = _review("{% for item in items %}{{ impact }}{{ host_notice }}{% endfor %}")

    assert result.status == "pass", result.format_text()


def test_static_include_of_host_marker_counts() -> None:
    loader = DictLoader({"_host_notice.html": "HOST NOTICE"})
    result = _review(
        "{{ impact }}{% include '_host_notice.html' %}",
        loader=loader,
        marker=MarkerSource.template("_host_notice.html"),
    )

    assert result.status == "pass", result.format_text()


def test_marker_template_include_on_only_one_branch_fails() -> None:
    loader = DictLoader({"_host_notice.html": "HOST NOTICE"})
    result = _review(
        "{{ impact }}{% if visible %}{% include '_host_notice.html' %}{% endif %}",
        loader=loader,
        marker=MarkerSource.template("_host_notice.html"),
    )

    assert result.status == "fail"
    assert result.errors[0].code == "E_MISSING_MARKER"
    assert "visible is empty" in result.format_text()


def test_parent_marker_in_overridden_default_block_does_not_count() -> None:
    loader = DictLoader(
        {
            "base.html": (
                "{% block body %}{{ impact }}"
                "{% include '_host_notice.html' %}{% endblock %}"
            ),
            "_host_notice.html": "HOST NOTICE",
        }
    )
    result = _review(
        "{% extends 'base.html' %}{% block body %}{{ impact }}{% endblock %}",
        loader=loader,
        name="child.html",
        marker=MarkerSource.template("_host_notice.html"),
    )

    assert result.status == "fail"
    assert result.errors[0].code == "E_MISSING_MARKER"


def test_child_override_can_reach_parent_marker_with_super() -> None:
    loader = DictLoader(
        {
            "base.html": (
                "{% block body %}{{ impact }}"
                "{% include '_host_notice.html' %}{% endblock %}"
            ),
            "_host_notice.html": "HOST NOTICE",
        }
    )
    result = _review(
        "{% extends 'base.html' %}{% block body %}{{ super() }}{% endblock %}",
        loader=loader,
        name="child.html",
        marker=MarkerSource.template("_host_notice.html"),
    )

    assert result.status == "pass", result.format_text()


def test_unreachable_parent_default_block_is_not_checked() -> None:
    loader = DictLoader({"base.html": "{% block body %}{{ impact }}{% endblock %}"})
    result = _review(
        "{% extends 'base.html' %}"
        "{% block body %}{{ impact }}{{ host_notice }}{% endblock %}",
        loader=loader,
        name="child.html",
    )

    assert result.status == "pass", result.format_text()


def test_unreachable_static_branch_is_not_checked() -> None:
    result = _review("{% if false %}{{ impact }}{% endif %}{{ host_notice }}")

    assert result.status == "pass", result.format_text()


def test_dynamic_include_goes_to_manual_review() -> None:
    result = _review("{% include tpl %}{{ impact }}{{ host_notice }}")

    assert result.status == "manual"
    codes = {finding.code for finding in result.manual}
    assert "M_DYNAMIC_REFERENCE" in codes


def test_dynamic_extends_goes_to_manual_review() -> None:
    result = _review(
        "{% extends layout %}"
        "{% block body %}{{ impact }}{{ host_notice }}{% endblock %}"
    )

    assert result.status == "manual"
    assert result.manual[0].code == "M_DYNAMIC_REFERENCE"


def test_dynamic_section_reference_goes_to_manual_review() -> None:
    result = review_template(
        "{{ sections[key] }}{{ host_notice }}",
        managed_sections=[ManagedSection("impact", variables=frozenset({"sections"}))],
        marker="host_notice",
    )

    assert result.status == "manual"
    assert any(finding.code == "M_DYNAMIC_REFERENCE" for finding in result.manual)


def test_literal_section_selector() -> None:
    config = ReviewConfig.from_mapping(
        {
            "managed_sections": [
                {"name": "impact", "literals": ["data-managed=impact"]}
            ],
            "marker": "host_notice",
        }
    )
    result = review_template("<div data-managed=impact></div>{{ host_notice }}", config)

    assert result.status == "pass", result.format_text()


def test_literal_marker_source_is_rejected() -> None:
    with pytest.raises(ReviewError):
        ReviewConfig.from_mapping(
            {
                "managed_sections": ["impact"],
                "marker": {"kind": "literal", "value": "HOST NOTICE"},
            }
        )


def test_acceptance_counterexample_reports_empty_items_path() -> None:
    config = ReviewConfig.from_mapping(
        json.loads((EXAMPLE_ROOT / "compliance.json").read_text(encoding="utf-8"))
    )
    result = review_file(
        EXAMPLE_ROOT / "templates" / "incident.html",
        config,
        search_path=EXAMPLE_ROOT / "templates",
    )

    assert result.status == "fail", result.format_text()
    finding = result.errors[0]
    assert finding.code == "E_MISSING_MARKER"
    assert finding.section == "incident"
    assert any(condition.describe() == "items is empty" for condition in finding.path)
    assert "items is empty" in result.format_text()


def test_cli_emits_json_and_failure_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["--config", str(EXAMPLE_ROOT / "compliance.json"), "--json"])

    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "fail"
    assert payload["findings"][0]["code"] == "E_MISSING_MARKER"


def test_elif_chain_checks_each_else_path() -> None:
    result = _review(
        "{% if a %}{{ host_notice }}{% elif b %}{{ host_notice }}"
        "{% elif c %}{{ host_notice }}{% endif %}{{ impact }}"
    )

    assert result.status == "fail"
    finding = result.errors[0]
    assert [condition.expression for condition in finding.path] == ["a", "b", "c"]


def test_dynamic_include_may_provide_marker() -> None:
    result = _review("{% include tpl %}{{ impact }}")

    assert result.status == "manual"
    assert result.errors == ()


def test_review_file_accepts_inline_configuration() -> None:
    result = review_file(
        EXAMPLE_ROOT / "templates" / "incident.html",
        managed_sections=[{"name": "incident", "blocks": ["incident"]}],
        marker={"kind": "template", "value": "_host_notice.html"},
        search_path=EXAMPLE_ROOT / "templates",
    )

    assert result.status == "fail"
    assert result.errors[0].code == "E_MISSING_MARKER"


def test_counterexample_preview_and_empty_path_render_differ() -> None:
    env = Environment(loader=FileSystemLoader(EXAMPLE_ROOT / "templates"))
    template = env.get_template("incident.html")

    assert "HOST NOTICE" in template.render(title="preview", items=["one"])
    assert "HOST NOTICE" not in template.render(title="preview", items=[])


def test_conditional_expression_branches_are_checked() -> None:
    result = _review('{{ host_notice if visible else "" }}{{ impact }}')

    assert result.status == "fail"
    assert result.errors[0].path[0].expression == "visible"
    assert result.errors[0].path[0].truth is False


def test_marker_call_source() -> None:
    result = review_template(
        "{{ impact }}{{ render_notice() }}",
        managed_sections=["impact"],
        marker=MarkerSource.call("render_notice"),
    )

    assert result.status == "pass", result.format_text()


def test_captured_marker_variable_counts_when_emitted() -> None:
    result = _review(
        "{% set notice %}{{ host_notice }}{% endset %}{{ impact }}{{ notice }}"
    )

    assert result.status == "pass", result.format_text()


def test_captured_section_without_marker_fails_when_emitted() -> None:
    result = _review("{% set body %}{{ impact }}{% endset %}{{ body }}")

    assert result.status == "fail"
    assert result.errors[0].code == "E_MISSING_MARKER"
