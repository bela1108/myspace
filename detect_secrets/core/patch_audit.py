from dataclasses import dataclass
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple

from . import scan
from .potential_secret import PotentialSecret
from .secrets_collection import SecretsCollection
from ..settings import get_settings


@dataclass(frozen=True)
class ModifiedRange:
    old_start: int
    old_length: int
    new_start: int
    new_length: int

    @property
    def old_end(self) -> int:
        return self.old_start + self.old_length - 1

    @property
    def new_end(self) -> int:
        return self.new_start + self.new_length - 1


@dataclass(frozen=True, eq=False)
class SecretOccurrence:
    secret: PotentialSecret
    range: ModifiedRange

    @property
    def key(self) -> Tuple[str, str]:
        return (self.secret.type, self.secret.secret_hash)


@dataclass(frozen=True)
class PatchSecret:
    secret: PotentialSecret
    status: str
    old_location: Optional[PotentialSecret] = None
    candidates: Tuple[PotentialSecret, ...] = ()
    old_occurrences: Tuple['SecretOccurrence', ...] = ()
    new_occurrences: Tuple['SecretOccurrence', ...] = ()

    def json(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            **self.secret.json(),
            'status': self.status,
        }
        if self.old_location is not None:
            output['moved_from'] = self.old_location.json()
        if self.candidates:
            output['candidates'] = [candidate.json() for candidate in self.candidates]
        return output


@dataclass(frozen=True)
class PatchAuditReport:
    new_secrets: Tuple[PatchSecret, ...]
    moved_secrets: Tuple[PatchSecret, ...]
    ambiguous_secrets: Tuple[PatchSecret, ...]
    removed_secrets: Tuple[PatchSecret, ...]

    @property
    def total_new_secrets(self) -> int:
        return len(self.new_secrets)

    def json(self) -> Dict[str, Any]:
        return {
            'total_new_secrets': self.total_new_secrets,
            'results': {
                'new': [item.json() for item in self.new_secrets],
                'moved': [item.json() for item in self.moved_secrets],
                'ambiguous': [item.json() for item in self.ambiguous_secrets],
                'removed': [item.json() for item in self.removed_secrets],
            },
        }


def audit_patch(diff: str, baseline: Optional[SecretsCollection] = None) -> PatchAuditReport:
    get_settings().disable_filters('detect_secrets.filters.common.is_invalid_file')
    ranges = _get_modified_ranges(diff)
    old_scan = _collect_scan_results(scan.scan_diff(diff, only_added=False))
    new_scan = _collect_scan_results(scan.scan_diff(diff))

    new_items: List[PatchSecret] = []
    moved_items: List[PatchSecret] = []
    ambiguous_items: List[PatchSecret] = []
    removed_items: List[PatchSecret] = []

    for filename in sorted(set(old_scan.keys()) | set(new_scan.keys())):
        modified_ranges = ranges.get(filename, [])
        old_occurrences = _map_to_ranges(
            old_scan.get(filename, []),
            modified_ranges,
            line_in_range=_in_old_range,
        )
        new_occurrences = _map_to_ranges(
            new_scan.get(filename, []),
            modified_ranges,
            line_in_range=_in_new_range,
        )
        old_by_range = _group_occurrences(old_occurrences)
        new_by_range = _group_occurrences(new_occurrences)
        matched_old_occurrences: Set[SecretOccurrence] = set()
        matched_new_occurrences: Set[SecretOccurrence] = set()

        for modified_range in sorted(
            new_by_range,
            key=lambda item: (item.new_start, item.old_start),
        ):
            for item in _match_occurrences(
                old_occurrences=old_by_range.get(modified_range, []),
                new_occurrences=new_by_range[modified_range],
            ):
                if item.status == 'moved':
                    moved_items.append(item)
                else:
                    ambiguous_items.append(item)
                matched_old_occurrences.update(item.old_occurrences)
                matched_new_occurrences.update(item.new_occurrences)

        known_keys = _known_secret_keys(baseline, filename)
        for occurrence in new_occurrences:
            if occurrence in matched_new_occurrences:
                continue
            if occurrence.key in known_keys:
                continue
            new_items.append(PatchSecret(secret=occurrence.secret, status='new'))

        for occurrence in old_occurrences:
            if occurrence in matched_old_occurrences:
                continue
            removed_items.append(PatchSecret(secret=occurrence.secret, status='removed'))

    return PatchAuditReport(
        new_secrets=tuple(new_items),
        moved_secrets=tuple(moved_items),
        ambiguous_secrets=tuple(ambiguous_items),
        removed_secrets=tuple(removed_items),
    )


def _collect_scan_results(
    secrets: Iterable[PotentialSecret],
) -> Dict[str, List[PotentialSecret]]:
    output: Dict[str, List[PotentialSecret]] = {}
    for secret in secrets:
        output.setdefault(secret.filename, []).append(secret)
    return output


def _get_modified_ranges(diff: str) -> Dict[str, List[ModifiedRange]]:
    from unidiff import PatchSet

    output: Dict[str, List[ModifiedRange]] = {}
    for patched_file in PatchSet.from_string(diff):
        output[patched_file.path] = [
            ModifiedRange(
                old_start=hunk.source_start,
                old_length=hunk.source_length,
                new_start=hunk.target_start,
                new_length=hunk.target_length,
            )
            for hunk in patched_file
        ]
    return output


def _map_to_ranges(
    secrets: Iterable[PotentialSecret],
    ranges: Sequence[ModifiedRange],
    line_in_range: Callable[[int, ModifiedRange], bool],
) -> List[SecretOccurrence]:
    output = []
    for secret in secrets:
        modified_range = _find_range(secret.line_number, ranges, line_in_range)
        if modified_range is not None:
            output.append(SecretOccurrence(secret=secret, range=modified_range))
    return output


def _find_range(
    line_number: int,
    ranges: Sequence[ModifiedRange],
    line_in_range: Callable[[int, ModifiedRange], bool],
) -> Optional[ModifiedRange]:
    for modified_range in ranges:
        if line_in_range(line_number, modified_range):
            return modified_range
    return None


def _in_old_range(line_number: int, modified_range: ModifiedRange) -> bool:
    return (
        modified_range.old_length > 0
        and modified_range.old_start <= line_number <= modified_range.old_end
    )


def _in_new_range(line_number: int, modified_range: ModifiedRange) -> bool:
    return (
        modified_range.new_length > 0
        and modified_range.new_start <= line_number <= modified_range.new_end
    )


def _group_occurrences(
    occurrences: Iterable[SecretOccurrence],
) -> Dict[ModifiedRange, List[SecretOccurrence]]:
    output: Dict[ModifiedRange, List[SecretOccurrence]] = {}
    for occurrence in occurrences:
        output.setdefault(occurrence.range, []).append(occurrence)
    return output


def _match_occurrences(
    old_occurrences: Sequence[SecretOccurrence],
    new_occurrences: Sequence[SecretOccurrence],
) -> Iterable[PatchSecret]:
    old_by_key = _group_by_key(old_occurrences)
    new_by_key = _group_by_key(new_occurrences)

    for key in sorted(set(old_by_key) | set(new_by_key)):
        old_matches = old_by_key.get(key, ())
        new_matches = new_by_key.get(key, ())
        if not old_matches or not new_matches:
            continue

        if len(old_matches) == 1 and len(new_matches) == 1:
            yield PatchSecret(
                secret=new_matches[0].secret,
                status='moved',
                old_location=old_matches[0].secret,
                old_occurrences=tuple(old_matches),
                new_occurrences=tuple(new_matches),
            )
            continue

        candidates = tuple(item.secret for item in old_matches)
        for occurrence in new_matches:
            yield PatchSecret(
                secret=occurrence.secret,
                status='ambiguous',
                candidates=candidates,
                old_occurrences=tuple(old_matches),
                new_occurrences=tuple(new_matches),
            )


def _group_by_key(
    occurrences: Iterable[SecretOccurrence],
) -> Dict[Tuple[str, str], Tuple[SecretOccurrence, ...]]:
    output: Dict[Tuple[str, str], List[SecretOccurrence]] = {}
    for occurrence in occurrences:
        output.setdefault(occurrence.key, []).append(occurrence)
    return {key: tuple(items) for key, items in output.items()}


def _known_secret_keys(
    baseline: Optional[SecretsCollection],
    filename: str,
) -> Set[Tuple[str, str]]:
    if baseline is None or filename not in baseline.files:
        return set()
    return {
        (secret.type, secret.secret_hash)
        for secret in baseline[filename]
    }
