import json
import os
from typing import Callable
from typing import Optional

from ..core.patch_audit import PatchAuditReport
from ..core.patch_audit import audit_patch
from ..core.secrets_collection import SecretsCollection


def audit_patch_file(
    patch_filename: str,
    baseline: Optional[SecretsCollection] = None,
) -> PatchAuditReport:
    if not os.path.isfile(patch_filename):
        raise FileNotFoundError(patch_filename)
    with open(patch_filename) as f:
        return audit_patch(f.read(), baseline=baseline)


def print_patch_audit_report(
    report: PatchAuditReport,
    as_json: bool = False,
    print_fn: Callable[..., None] = print,
) -> None:
    if as_json:
        print_fn(json.dumps(report.json(), indent=2))
        return

    for item in report.moved_secrets:
        old_location = item.old_location
        if old_location is None:
            continue
        print_fn(
            f'MOVED: {item.secret.filename}:{item.secret.line_number} '
            f'<- {old_location.filename}:{old_location.line_number}',
        )

    for item in report.ambiguous_secrets:
        candidate_text = ', '.join(
            f'{candidate.filename}:{candidate.line_number}'
            for candidate in item.candidates
        )
        print_fn(
            f'AMBIGUOUS: {item.secret.filename}:{item.secret.line_number} '
            f'could have moved from {candidate_text}',
        )

    for item in report.new_secrets:
        print_fn(f'NEW: {item.secret.filename}:{item.secret.line_number}')

    for item in report.removed_secrets:
        print_fn(f'REMOVED: {item.secret.filename}:{item.secret.line_number}')

    print_fn(f'\nTotal new secrets detected: {report.total_new_secrets}')
