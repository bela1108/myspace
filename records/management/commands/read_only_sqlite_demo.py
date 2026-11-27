import json
import os
import stat
import tempfile
from pathlib import Path

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError

from records.models import LifecycleStatus
from records.services import change_status, create_tracked_object, find_tracked_object


class Command(BaseCommand):
    help = "Create two temporary SQLite databases and verify a read-only archive route."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", dest="as_json")

    def handle(self, *args, **options):
        with tempfile.TemporaryDirectory(prefix="django-origin-routing-") as directory:
            base = Path(directory)
            business_path = base / "business.sqlite3"
            compliance_path = base / "compliance.sqlite3"
            result = self._run(business_path, compliance_path)

        if options["as_json"]:
            self.stdout.write(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            self.stdout.write(self.style.SUCCESS(json.dumps(result, ensure_ascii=False, indent=2)))

    def _run(self, business_path, compliance_path):
        object_id = 7771001
        database_settings = {
            "default": self._sqlite_settings(business_path),
            "business": self._sqlite_settings(business_path),
            "compliance": self._sqlite_settings(compliance_path),
        }
        self._configure_connections(database_settings)

        for alias in ("business", "compliance"):
            call_command("migrate", "records", database=alias, verbosity=0, interactive=False)

        business_receipt = create_tracked_object(
            object_id=object_id,
            name="same-primary-key-business",
            status=LifecycleStatus.PENDING,
            origin_db="business",
        )
        compliance_receipt = create_tracked_object(
            object_id=object_id,
            name="same-primary-key-compliance",
            status=LifecycleStatus.ARCHIVED,
            origin_db="compliance",
        )

        initial_search = find_tracked_object(
            object_id=object_id,
            search_aliases=("business", "compliance"),
        )

        readonly_error = self._freeze_compliance(compliance_path)
        try:
            change_status(
                object_id=object_id,
                to_status=LifecycleStatus.ACTIVE,
                origin_db="compliance",
            )
        except OperationalError as exc:
            readonly_write_error = str(exc)
        else:
            readonly_write_error = "compliance write unexpectedly succeeded"

        business_change = change_status(
            object_id=object_id,
            to_status=LifecycleStatus.ACTIVE,
            origin_db="business",
        )
        final_search = find_tracked_object(
            object_id=object_id,
            search_aliases=("business", "compliance"),
            origin_db="business",
        )

        return {
            "temporary_directory": str(compliance_path.parent),
            "business_database": str(business_path),
            "compliance_database": str(compliance_path),
            "initial_origin_status": initial_search.origin_status,
            "initial_candidate_databases": [item.database for item in initial_search.candidates],
            "created": {
                "business": self._receipt(business_receipt),
                "compliance": self._receipt(compliance_receipt),
            },
            "compliance_file_mode_after_freeze": readonly_error,
            "compliance_write_error": readonly_write_error,
            "business_write_receipt": self._receipt(business_change),
            "final_business_origin_status": final_search.origin_status,
            "final_business_status": final_search.candidates[0].object.status,
            "final_business_database": final_search.origin_db,
        }

    def _freeze_compliance(self, compliance_path):
        connections.close_all()
        os.chmod(compliance_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        mode = oct(compliance_path.stat().st_mode & 0o777)
        uri = compliance_path.resolve().as_uri() + "?mode=ro"
        connections._settings["compliance"] = {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": uri,
            "OPTIONS": {"uri": True},
            "ATOMIC_REQUESTS": False,
            "AUTOCOMMIT": True,
            "CONN_MAX_AGE": 0,
            "CONN_HEALTH_CHECKS": True,
            "TIME_ZONE": None,
            "TEST": {"CHARSET": None, "COLLATION": None, "MIGRATE": True, "MIRROR": None, "NAME": None},
        }
        if hasattr(connections._connections, "compliance"):
            delattr(connections._connections, "compliance")
        return mode

    def _configure_connections(self, database_settings):
        connections.close_all()
        connections._settings = database_settings
        storage = getattr(connections._connections, "_storage", None)
        if storage is not None:
            for alias in tuple(vars(storage)):
                delattr(connections._connections, alias)
        if "settings" in connections.__dict__:
            del connections.__dict__["settings"]
        connections["default"].ensure_connection()

    def _sqlite_settings(self, path):
        return {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": str(path),
        }

    def _receipt(self, receipt):
        return {
            "database": receipt.database,
            "object_id": receipt.object_id,
            "status": receipt.status,
            "origin_status": receipt.origin_status,
            "signal_db": receipt.signal.signal_db,
            "instance_state_db": receipt.signal.instance_state_db,
            "event_id": receipt.event_id,
        }
