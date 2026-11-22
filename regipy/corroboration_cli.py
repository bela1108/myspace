"""Command line interface for offline registry corroboration."""

from __future__ import annotations

import json

import click

from regipy.corroboration import (
    TOOL_NAME,
    TOOL_VERSION,
    CorroborationCase,
    corroborate,
    replace_identity_record,
)


@click.command()
@click.argument("case_path", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", type=click.Path(dir_okay=False), help="Write the JSON review here.")
@click.option("--markdown", type=click.Path(dir_okay=False), help="Write a Markdown review here.")
@click.option("--replace-export", help="Export id for a counterfactual identity-record replacement.")
@click.option("--replace-record", help="Record id to replace, for example volume, source or name:0.")
@click.option("--replace-value", help="JSON value merged into the selected record.")
@click.option("--replace-note", default=None, help="Optional note stored with the replacement result.")
@click.option("--fail-on-conflict", is_flag=True, default=False, help="Exit with status 2 when the verdict is conflict.")
@click.option("--quiet", is_flag=True, default=False, help="Suppress the one-line verdict summary.")
def main(
    case_path: str,
    output: str | None,
    markdown: str | None,
    replace_export: str | None,
    replace_record: str | None,
    replace_value: str | None,
    replace_note: str | None,
    fail_on_conflict: bool,
    quiet: bool,
) -> None:
    """Run an offline identity-corroboration review for a JSON case file."""

    case = CorroborationCase.from_json_file(case_path)

    replacement_requested = any([replace_export, replace_record, replace_value])
    if replacement_requested:
        if not (replace_export and replace_record and replace_value):
            raise click.UsageError("--replace-export, --replace-record and --replace-value must be supplied together.")
        try:
            replacement = json.loads(replace_value)
        except json.JSONDecodeError as exc:
            raise click.BadParameter(f"--replace-value is not valid JSON: {exc}") from exc
        result = replace_identity_record(
            case,
            replace_export,
            replace_record,
            replacement,
            note=replace_note,
        )
    else:
        result = corroborate(case)

    if output:
        result.write_json(output)
    if markdown:
        result.write_markdown(markdown)
    if not output and not markdown:
        click.echo(result.to_json())

    if not quiet:
        click.echo(f"{TOOL_NAME} {TOOL_VERSION}: verdict={result.verdict.value}", err=True)
        if result.replacement:
            click.echo(
                "replacement invalidated: " + (", ".join(result.replacement["invalidated_association_ids"]) or "none"),
                err=True,
            )

    if fail_on_conflict and result.verdict.value == "conflict":
        raise click.exceptions.Exit(2)


if __name__ == "__main__":
    main()
