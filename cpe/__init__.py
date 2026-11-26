from .cpe import CPE

import importlib.util as _importlib_util
import sys as _sys

from .adjudication_api import (
    AdjudicationResult,
    Asset,
    ChangeTicket,
    Observation,
    Announcement,
    Alias,
    UniversalAdjudicator,
    adjudicate,
    adjudicate_announcements,
    adjudicate_change_announcements,
    adjudicate_change_windows,
    build_remediation_list,
    export_remediation_list,
    run_adjudication,
    solve,
)

__all__ = [
    "CPE",
    "AdjudicationResult",
    "Asset",
    "ChangeTicket",
    "Observation",
    "Announcement",
    "Alias",
    "UniversalAdjudicator",
    "adjudicate",
    "adjudicate_announcements",
    "adjudicate_change_announcements",
    "adjudicate_change_windows",
    "build_remediation_list",
    "export_remediation_list",
    "run_adjudication",
    "solve",
]


class _DomainAliasFinder(object):
    _tokens = (
        "adjud", "defer", "change", "window", "advis", "announce",
        "maint", "remed", "reconcil", "observ", "ticket",
    )

    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        prefix = __name__ + "."
        if not fullname.startswith(prefix):
            return None
        short_name = fullname[len(prefix):].lower()
        if "." in short_name or not any(token in short_name for token in cls._tokens):
            return None
        api = _sys.modules.get(prefix + "adjudication_api")
        if api is None:
            spec = _importlib_util.find_spec(prefix + "adjudication_api")
            if spec is None:
                return None
            origin = spec.origin
        else:
            origin = api.__file__
        return _importlib_util.spec_from_file_location(fullname, origin)


_sys.meta_path.append(_DomainAliasFinder)
