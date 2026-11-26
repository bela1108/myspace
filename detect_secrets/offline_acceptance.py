import argparse
import json
from math import comb
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence


class InvalidAcceptanceEvidence(ValueError):
    pass


def hypergeometric_upper_bound(population_size: int, sample_size: int, observed: int, alpha: float) -> int:
    if min(population_size, sample_size, observed) < 0:
        raise ValueError('counts must be non-negative')
    if sample_size > population_size:
        raise ValueError('sample_size cannot exceed population_size')
    if observed > sample_size:
        raise ValueError('observed cannot exceed sample_size')
    if not 0 < alpha < 1:
        raise ValueError('alpha must be between 0 and 1')

    if sample_size == population_size:
        return observed

    lower = observed
    upper = population_size
    while lower < upper:
        candidate = (lower + upper + 1) // 2
        if _lower_tail_probability(population_size, sample_size, observed, candidate) > alpha:
            lower = candidate
        else:
            upper = candidate - 1

    return lower


def _lower_tail_probability(
    population_size: int,
    sample_size: int,
    observed: int,
    defective: int,
) -> float:
    denominator = comb(population_size, sample_size)
    numerator = sum(
        comb(defective, selected) * comb(population_size - defective, sample_size - selected)
        for selected in range(observed + 1)
    )
    return numerator / denominator


def build_acceptance_report(evidence: Mapping[str, Any]) -> Dict[str, Any]:
    frozen_manifest = _mapping(evidence, 'frozen_manifest')
    scan_completion = _mapping(evidence, 'scan_completion')
    sampling_records = _sequence(evidence, 'sampling_records')
    blind_reviews = _mapping(evidence, 'blind_reviews')

    manifest_files = _sequence(frozen_manifest, 'files')
    scan_files = _sequence(scan_completion, 'scanned_files')
    manifest_entries = _index_manifest_files(manifest_files)
    scanned_ids = _index_scan_files(scan_files)
    review_entries = _index_review_files(_sequence(blind_reviews, 'files'))

    strata = _build_strata(frozen_manifest)
    alpha_by_stratum = _index_alpha_by_stratum(_mapping(evidence, 'alpha_by_stratum'))
    if sum(alpha_by_stratum.values()) > _number(evidence, 'alpha_budget', allow_int=False):
        raise InvalidAcceptanceEvidence('allocated significance levels exceed alpha_budget')

    report_strata: List[Dict[str, int]] = []
    total_negative_files = 0
    total_sample_size = 0
    total_observed_problem_files = 0
    total_missing_review_files = 0
    total_upper_bound = 0

    for stratum in strata:
        name = _string(stratum, 'stratum')
        sample_ids = _sample_ids_for_stratum(sampling_records, name)
        stratum_files = [file_id for file_id, entry in manifest_entries.items() if entry['stratum'] == name]

        if len(set(sample_ids)) != len(sample_ids):
            raise InvalidAcceptanceEvidence(f'sampling record for {name} contains a duplicate file')
        if any(file_id not in manifest_entries for file_id in sample_ids):
            raise InvalidAcceptanceEvidence(f'sampling record for {name} references an unknown file')
        if any(manifest_entries[file_id]['stratum'] != name for file_id in sample_ids):
            raise InvalidAcceptanceEvidence(f'sampling record for {name} crosses a stratum boundary')

        negative_ids = [
            file_id for file_id in stratum_files
            if file_id in scanned_ids and not bool(scan_files_set_is_positive(scanned_ids[file_id]))
        ]
        negative_id_set = set(negative_ids)
        if any(file_id not in negative_id_set for file_id in sample_ids):
            raise InvalidAcceptanceEvidence(f'sampling record for {name} includes a non-negative file')

        problem_files = 0
        missing_review_files = 0
        for file_id in sample_ids:
            review = review_entries.get(file_id)
            if review is None or not _has_conclusive_review(review):
                problem_files += 1
                missing_review_files += 1
                continue

            verdict = _string(review, 'verdict')
            if verdict == 'positive':
                problem_files += 1
            elif verdict != 'negative':
                raise InvalidAcceptanceEvidence(f'unsupported review verdict for sampled file in {name}')

        alpha = alpha_by_stratum[name]
        upper_bound = hypergeometric_upper_bound(
            population_size=len(negative_ids),
            sample_size=len(sample_ids),
            observed=problem_files,
            alpha=alpha,
        )

        report_strata.append({
            'stratum': name,
            'negative_files': len(negative_ids),
            'sample_size': len(sample_ids),
            'problem_files': problem_files,
            'missing_review_files': missing_review_files,
            'upper_bound': upper_bound,
        })
        total_negative_files += len(negative_ids)
        total_sample_size += len(sample_ids)
        total_observed_problem_files += problem_files
        total_missing_review_files += missing_review_files
        total_upper_bound += upper_bound

    unscanned_files = sum(1 for file_id in manifest_entries if file_id not in scanned_ids)
    return {
        'strata': report_strata,
        'totals': {
            'negative_files': total_negative_files,
            'sample_size': total_sample_size,
            'problem_files': total_observed_problem_files,
            'missing_review_files': total_missing_review_files,
            'unscanned_files': unscanned_files,
            'upper_bound': total_upper_bound,
        },
    }


def scan_files_set_is_positive(scan_entry: Mapping[str, Any]) -> Any:
    return scan_entry.get('is_positive', False)


def _has_conclusive_review(review: Mapping[str, Any]) -> bool:
    verdict = review.get('verdict')
    return verdict in ('positive', 'negative')


def _index_manifest_files(files: Sequence[Any]) -> Dict[str, Dict[str, str]]:
    entries: Dict[str, Dict[str, str]] = {}
    for item in files:
        entry = _mapping_value(item, 'frozen_manifest.files')
        file_id = _string(entry, 'file_id')
        if file_id in entries:
            raise InvalidAcceptanceEvidence('frozen_manifest contains duplicate file_id')
        entries[file_id] = {
            'stratum': _string(entry, 'stratum'),
        }
    return entries


def _index_scan_files(files: Sequence[Any]) -> Dict[str, Dict[str, Any]]:
    entries: Dict[str, Dict[str, Any]] = {}
    for item in files:
        entry = _mapping_value(item, 'scan_completion.scanned_files')
        file_id = _string(entry, 'file_id')
        if file_id in entries:
            raise InvalidAcceptanceEvidence('scan_completion contains duplicate file_id')
        entries[file_id] = entry
    return entries


def _index_review_files(files: Sequence[Any]) -> Dict[str, Dict[str, Any]]:
    entries: Dict[str, Dict[str, Any]] = {}
    for item in files:
        entry = _mapping_value(item, 'blind_reviews.files')
        file_id = _string(entry, 'file_id')
        if file_id in entries:
            raise InvalidAcceptanceEvidence('blind_reviews contains duplicate file_id')
        entries[file_id] = entry
    return entries


def _build_strata(manifest: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    strata = _sequence(manifest, 'strata')
    names = []
    for item in strata:
        entry = _mapping_value(item, 'frozen_manifest.strata')
        names.append(_string(entry, 'stratum'))
    if len(set(names)) != len(names):
        raise InvalidAcceptanceEvidence('frozen_manifest contains duplicate stratum name')
    return [_mapping_value(item, 'frozen_manifest.strata') for item in strata]


def _index_alpha_by_stratum(allocation: Mapping[str, Any]) -> Dict[str, float]:
    values = _mapping(allocation, 'values')
    result = {}
    for name, value in values.items():
        alpha = float(value)
        if not 0 < alpha < 1:
            raise InvalidAcceptanceEvidence(f'significance level for {name} must be between 0 and 1')
        result[name] = alpha
    return result


def _sample_ids_for_stratum(records: Sequence[Any], stratum_name: str) -> List[str]:
    matches = []
    for item in records:
        record = _mapping_value(item, 'sampling_records')
        if _string(record, 'stratum') == stratum_name:
            matches.append(record)

    if len(matches) != 1:
        raise InvalidAcceptanceEvidence(f'expected exactly one sampling record for {stratum_name}')

    sample = _sequence(matches[0], 'sampled_files')
    return [_string(_mapping_value(item, 'sampled_files'), 'file_id') for item in sample]


def _mapping(source: Mapping[str, Any], key: str) -> Dict[str, Any]:
    value = source.get(key)
    if not isinstance(value, Mapping):
        raise InvalidAcceptanceEvidence(f'{key} must be an object')
    return dict(value)


def _sequence(source: Mapping[str, Any], key: str) -> List[Any]:
    value = source.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise InvalidAcceptanceEvidence(f'{key} must be an array')
    return list(value)


def _mapping_value(value: Any, path: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidAcceptanceEvidence(f'{path} entries must be objects')
    return dict(value)


def _string(source: Mapping[str, Any], key: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        raise InvalidAcceptanceEvidence(f'{key} must be a non-empty string')
    return value


def _number(source: Mapping[str, Any], key: str, allow_int: bool) -> float:
    value = source.get(key)
    if allow_int and isinstance(value, int) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, float) or isinstance(value, bool):
        raise InvalidAcceptanceEvidence(f'{key} must be a number')
    return value


def load_evidence(filename: str) -> Dict[str, Any]:
    with open(filename) as file_handle:
        value = json.load(file_handle)
    if not isinstance(value, Mapping):
        raise InvalidAcceptanceEvidence('evidence document must be an object')
    return dict(value)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='Build an offline detect-secrets acceptance report.')
    parser.add_argument('evidence', help='Path to the offline acceptance evidence JSON document.')
    args = parser.parse_args(argv)

    try:
        report = build_acceptance_report(load_evidence(args.evidence))
    except (OSError, json.JSONDecodeError, InvalidAcceptanceEvidence) as error:
        parser.exit(1, f'{error}\n')

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
