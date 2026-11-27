"""Export sealed audit log segments as a self-contained document."""

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import DEFAULT_DB_ALIAS

from auditlog.sealing import AuditLogIntegrityError, export_segments, write_export


class Command(BaseCommand):
    help = (
        "Exports sealed segments with their entries. Export stops at the first "
        "missing or modified entry unless --no-verify is given."
    )

    def add_arguments(self, parser: CommandParser):
        parser.add_argument("path", help="Destination JSON file.")
        parser.add_argument(
            "-d",
            "--database",
            default=DEFAULT_DB_ALIAS,
            dest="using",
            help="Database alias to export from.",
        )
        parser.add_argument(
            "--no-verify",
            action="store_false",
            default=True,
            dest="verify",
            help="Export even when the first inconsistency is already known.",
        )

    def handle(self, *args, **options):
        try:
            document = export_segments(
                using=options["using"], verify=options["verify"]
            )
        except AuditLogIntegrityError as exc:
            raise CommandError("Export refused: %s" % exc.first_mismatch)

        path = write_export(document, options["path"])
        self.stdout.write(
            "Exported %s segments (%s entries) to %s"
            % (
                len(document["segments"]),
                len(document["entries"]),
                path,
            )
        )
