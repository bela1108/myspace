"""Seal the next committed range of audit log entries."""

from django.core.management.base import BaseCommand, CommandParser
from django.db import DEFAULT_DB_ALIAS

from auditlog.sealing import plan_segment, seal_segment


class Command(BaseCommand):
    help = "Seals a verifiable segment of committed audit log entries."

    def add_arguments(self, parser: CommandParser):
        parser.add_argument(
            "-d",
            "--database",
            default=DEFAULT_DB_ALIAS,
            dest="using",
            help="Database alias to read and write.",
        )
        parser.add_argument(
            "--limit",
            "--max-entries",
            default=None,
            type=int,
            dest="limit",
            help="Maximum number of entries to seal in this segment.",
        )
        parser.add_argument(
            "--start-after",
            default=None,
            type=int,
            dest="start_after",
            help="Only seal entries with a primary key greater than this value.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            dest="dry_run",
            help="Print the reviewable summary without writing a segment.",
        )

    def handle(self, *args, **options):
        using = options["using"]
        limit = options["limit"]
        start_after = options["start_after"]

        if options["dry_run"]:
            plan = plan_segment(using=using, start_after=start_after, limit=limit)
            if plan is None:
                self.stdout.write("No unsealed log entries.")
                return
            self._write_summary(plan, dry_run=True)
            return

        segment = seal_segment(using=using, start_after=start_after, limit=limit)
        if segment is None:
            self.stdout.write("No unsealed log entries.")
            return
        self._write_summary(segment.summary(), dry_run=False)

    def _write_summary(self, summary, dry_run=False):
        prefix = "Would seal" if dry_run else "Sealed"
        self.stdout.write(
            "%s segment %s: %s entries (id %s..%s)"
            % (
                prefix,
                summary["sequence"],
                summary["entry_count"],
                summary["first_entry_id"],
                summary["last_entry_id"],
            )
        )
        self.stdout.write("digest: %s" % summary["digest"])
        self.stdout.write("previous: %s" % (summary["previous_digest"] or "<none>"))
