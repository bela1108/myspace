"""Offline reconciliation of LNK targets against historical drive mappings.

The engine keeps three layers of knowledge strictly separated:

1. what the shortcut itself claims (the target as written inside the LNK);
2. which volume the written drive letter pointed at in each historical
   acquisition period (the drive history);
3. which original evidence volumes have actually been collected (the evidence
   inventory).

Reusing a drive letter for another volume only changes the current meaning of
the letter: the VolumeID embedded in the LNK keeps pointing at the original
volume, so historical attribution and collected-evidence matching stay stable.
"""

from LnkParse3.reconcile.models import load_drive_history
from LnkParse3.reconcile.models import load_evidence
from LnkParse3.reconcile.normalization import drive_letter_from_path
from LnkParse3.reconcile.normalization import normalize_path_key


def _candidate(mapping, target):
    """Build one historical volume candidate and record how it was matched."""
    candidate = dict(mapping)
    matched_by = []

    if target["volume_serial"] and target["volume_serial"] in mapping["volume_serials"]:
        matched_by.append("volume_serial")
    if target["volume_label"] and target["volume_label"] == mapping["volume_label"]:
        matched_by.append("volume_label")
    if not matched_by:
        matched_by.append("drive_letter")

    candidate["matched_by"] = matched_by
    candidate["matches_lnk_volume_id"] = "volume_serial" in matched_by
    candidate["authoritative"] = (
        "volume_serial" in matched_by
        or "volume_label" in matched_by
        or (not target["volume_serial"] and not target["volume_label"])
    )
    return candidate


def _attribution(target, periods, mappings_by_period):
    """Resolve the target letter for every recorded collection period."""
    letter = target["drive_letter"] or drive_letter_from_path(target["written_path"])
    by_period = []
    conflict_periods = []
    unobserved_periods = []

    for period in periods:
        letter_mappings = [
            mapping
            for mapping in mappings_by_period.get(period, [])
            if mapping["drive_letter"] == letter
        ]

        if not letter_mappings:
            by_period.append({"period": period, "observed": False, "candidates": []})
            unobserved_periods.append(period)
            continue

        candidates = [_candidate(mapping, target) for mapping in letter_mappings]
        authoritative = [item for item in candidates if item["authoritative"]]
        has_conflict = (
            len({serial for item in authoritative for serial in item["volume_serials"]}) > 1
        )

        by_period.append({"period": period, "observed": True, "candidates": candidates})
        if has_conflict:
            conflict_periods.append(period)

    candidate_serials = sorted(
        {
            serial
            for entry in by_period
            for candidate in entry["candidates"]
            for serial in candidate["volume_serials"]
        }
    )

    return {
        "target_drive_letter": letter,
        "by_period": by_period,
        "attribution_conflict": bool(conflict_periods),
        "conflict_periods": conflict_periods,
        "unobserved_periods": unobserved_periods,
        "candidate_volume_serials": candidate_serials,
    }


def _collected_evidence(target, evidence):
    """Match evidence by the stable embedded serial, never by drive letter."""
    if not target["volume_serial"]:
        return {"matched": False, "match_basis": None, "items": []}

    matched = [dict(item) for item in evidence if target["volume_serial"] in item["volume_serials"]]
    return {
        "matched": bool(matched),
        "match_basis": "volume_serial",
        "items": matched,
    }


def reconcile_target(target, drive_history_payload, evidence_payload):
    """Reconcile one target descriptor against raw history and evidence."""
    drive_history = load_drive_history(drive_history_payload)
    evidence = load_evidence(evidence_payload)
    periods = [period["period"] for period in drive_history]
    mappings_by_period = {period["period"]: period["mappings"] for period in drive_history}

    result = dict(target)
    result["path_key"] = normalize_path_key(target["written_path"])
    result["historical_attribution"] = _attribution(target, periods, mappings_by_period)
    result["collected_evidence"] = _collected_evidence(target, evidence)
    return result


def _same_name_groups(results):
    """Group targets that spell the same path but may originate separately."""
    grouped = {}
    for result in results:
        path_key = result["path_key"]
        if path_key:
            grouped.setdefault(path_key, []).append(result)

    groups = []
    for path_key, members in sorted(grouped.items()):
        if len(members) < 2:
            continue
        serials = sorted({member["volume_serial"] for member in members if member["volume_serial"]})
        groups.append(
            {
                "path_key": path_key,
                "written_path": members[0]["written_path"],
                "multiple_sources": len(serials) > 1,
                "distinct_volume_serials": serials,
                "members": [
                    {
                        "lnk_ref": member["lnk_ref"],
                        "source": member["source"],
                        "volume_serial": member["volume_serial"],
                        "evidence_collected": member["collected_evidence"]["matched"],
                    }
                    for member in members
                ],
            }
        )
    return groups


def build_reconciliation(targets, drive_history_payload, evidence_payload):
    """Run the full offline reconciliation and return a JSON-ready report."""
    drive_history = load_drive_history(drive_history_payload)
    evidence = load_evidence(evidence_payload)

    results = [reconcile_target(target, drive_history, evidence) for target in targets]

    return {
        "periods": [period["period"] for period in drive_history],
        "targets": results,
        "same_name_groups": _same_name_groups(results),
        "targets_with_attribution_conflicts": [
            result["lnk_ref"]
            for result in results
            if result["historical_attribution"]["attribution_conflict"]
        ],
    }
