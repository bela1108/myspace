"""Input models for the offline drive-letter reconciliation.

The reconciler works on plain dictionaries so it can be fed from JSON files,
from the LNK adapter or from hand-written test fixtures. Every identifier is
normalized once while loading, therefore later comparison never depends on
hexadecimal prefixes, casing or surrounding whitespace.
"""

from LnkParse3.reconcile.normalization import drive_letter_from_path
from LnkParse3.reconcile.normalization import normalize_drive_letter
from LnkParse3.reconcile.normalization import normalize_label
from LnkParse3.reconcile.normalization import normalize_serial


class ReconcileInputError(ValueError):
    """Raised when a drive table or evidence inventory cannot be parsed."""


def _as_list(payload, wrapper_key):
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict) and isinstance(payload.get(wrapper_key), list):
        entries = payload[wrapper_key]
    else:
        raise ReconcileInputError(f"expected a list or an object with a {wrapper_key!r} list")
    return entries


def _string(entry, key, default=None, required=False):
    value = entry.get(key, default)
    if value is None:
        if required:
            raise ReconcileInputError(f"missing required field {key!r} in {entry!r}")
        return None
    if not isinstance(value, str):
        raise ReconcileInputError(f"field {key!r} must be a string in {entry!r}")
    value = value.strip()
    return value or default


def _serials(entry):
    values = []
    if entry.get("volume_serial") is not None:
        values.append(entry["volume_serial"])
    extra = entry.get("volume_serials")
    if isinstance(extra, list):
        values.extend(extra)

    serials = []
    for value in values:
        normalized = normalize_serial(value)
        if normalized and normalized not in serials:
            serials.append(normalized)
    return serials


def load_drive_history(payload):
    """Normalize the per-collection drive-letter tables.

    Accepted shape::

        {"periods": [
            {"period": "2019-Q1", "mappings": [
                {"drive_letter": "E", "volume_serial": "0x11223344",
                 "volume_label": "OLD", "source": "collector-a"}
            ]}
        ]}

    A bare list of period objects is accepted as well. The returned periods
    keep their input order, which defines the observed timeline.
    """
    periods = []
    for raw_period in _as_list(payload, "periods"):
        if not isinstance(raw_period, dict):
            raise ReconcileInputError(f"period entry must be an object: {raw_period!r}")
        name = _string(raw_period, "period", required=True)
        raw_mappings = raw_period.get("mappings")
        if not isinstance(raw_mappings, list):
            raise ReconcileInputError(f"period {name!r} needs a 'mappings' list")

        mappings = []
        for raw_mapping in raw_mappings:
            if not isinstance(raw_mapping, dict):
                raise ReconcileInputError(f"mapping entry must be an object: {raw_mapping!r}")
            letter = normalize_drive_letter(_string(raw_mapping, "drive_letter", required=True))
            mappings.append(
                {
                    "drive_letter": letter,
                    "volume_serials": _serials(raw_mapping),
                    "volume_label": normalize_label(_string(raw_mapping, "volume_label")),
                    "source": _string(raw_mapping, "source", default=name),
                }
            )
        periods.append({"period": name, "mappings": mappings})
    return periods


def load_evidence(payload):
    """Normalize the volumes actually readable on the collected exhibits."""
    evidence = []
    for index, raw_entry in enumerate(_as_list(payload, "evidence")):
        if not isinstance(raw_entry, dict):
            raise ReconcileInputError(f"evidence entry must be an object: {raw_entry!r}")
        identity = _string(raw_entry, "evidence_id", default=f"evidence-{index}")
        evidence.append(
            {
                "evidence_id": identity,
                "source": _string(raw_entry, "source", default=identity),
                "drive_letter": normalize_drive_letter(_string(raw_entry, "drive_letter")),
                "volume_serials": _serials(raw_entry),
                "volume_label": normalize_label(_string(raw_entry, "volume_label")),
            }
        )
    return evidence


def make_target(
    source,
    written_path=None,
    drive_letter=None,
    volume_serial=None,
    volume_label=None,
    location="Local",
    lnk_ref=None,
    note=None,
):
    """Build a normalized target descriptor consumed by the reconciler."""
    if not source or not isinstance(source, str):
        raise ReconcileInputError("target descriptor needs a non-empty 'source'")
    clean_path = written_path.strip() if isinstance(written_path, str) else written_path
    letter = normalize_drive_letter(drive_letter) or drive_letter_from_path(clean_path)
    descriptor = {
        "lnk_ref": lnk_ref or source,
        "source": source.strip(),
        "location": location if isinstance(location, str) and location else "Local",
        "written_path": clean_path,
        "drive_letter": letter,
        "volume_serial": normalize_serial(volume_serial),
        "volume_label": normalize_label(volume_label),
    }
    if note:
        descriptor["note"] = note
    return descriptor
