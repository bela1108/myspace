"""Verify sealed audit log segments or an exported sealed copy."""

import json

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import DEFAULT_DB_ALIAS

from auditlog.sealing import verify_file, verify_segments


class Command(BaseCommand):
    help = "Verifies sealed segments and reports the first inconsistency."

    def add_arguments(self, parser: CommandParser):
        parser.add_argument(
            "path",
            nargs="?",
            default=None,
            help="Optional exported segment document to verify independently.",
        )
        parser.add_argument(
            "-d",
            "--database",
            default=DEFAULT_DB_ALIAS,
            dest="using",
            help="Database alias to verify when no export path is given.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            default=False,
            dest="json_output",
            help="Write the verification report as JSON.",
        )

    def handle(self, *args, **options):
        if options["path"]:
            mismatches = verify_file(options["path"], fail_fast=True)
            scope = "exported copy"
        else:
            mismatches = verify_segments(using=options["using"], fail_fast=True)
            scope = "database %s" % options["using"]

        if mismatches:
            mismatch = mismatches[0]
            if options["json_output"]:
                self.stdout.write(
                    json.dumps(
                        {"ok": False, "first_mismatch": mismatch.to_dict()},
                        sort_keys=True,
                        indent=2,
                    )
                )
            raise CommandError("Integrity check failed: %s" % mismatch)

        if options["json_output"]:
            self.stdout.write(json.dumps({"ok": True, "scope": scope}, sort_keys=True))
        else:
            self.stdout.write("Verified %s; no inconsistencies found." % scope)
