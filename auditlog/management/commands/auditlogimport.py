"""Restore a verified sealed segment export into a database."""

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import DEFAULT_DB_ALIAS

from auditlog.sealing import AuditLogIntegrityError, import_segments, read_export


class Command(BaseCommand):
    help = "Restores a verified segment export into another database."

    def add_arguments(self, parser: CommandParser):
        parser.add_argument("path", help="Exported JSON file to restore.")
        parser.add_argument(
            "-d",
            "--database",
            default=DEFAULT_DB_ALIAS,
            dest="using",
            help="Destination database alias.",
        )
        parser.add_argument(
            "--replace",
            action="store_true",
            default=False,
            help="Replace existing log entries and segments with the export.",
        )

    def handle(self, *args, **options):
        data = read_export(options["path"])
        try:
            result = import_segments(
                data, using=options["using"], replace=options["replace"]
            )
        except AuditLogIntegrityError as exc:
            raise CommandError("Import refused: %s" % exc.first_mismatch)
        except ValueError as exc:
            raise CommandError(str(exc))

        self.stdout.write(
            "Restored %s segments and %s entries (%s already present)."
            % (
                result["segments"],
                result["entries"],
                result["skipped_entries"],
            )
        )
