import json
from datetime import datetime
from typing import Any
from typing import Dict
from typing import List

from .engine import ClosureReport
from .engine import ReportDiff
from .model import BranchScope
from .model import EvidenceBundle
from .model import ReceiptKind
from .model import ReceiptStatus
from .model import RotationReceipt
from .model import RotationWindow


def parse_datetime(value: str) -> datetime:
    # datetime.fromisoformat only learnt about 'Z' in 3.11.
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def load_case(path: str) -> EvidenceBundle:
    with open(path) as file:
        data = json.load(file)
    return bundle_from_dict(data)


def save_case(bundle: EvidenceBundle, path: str) -> None:
    with open(path, 'w') as file:
        json.dump(bundle_to_dict(bundle), file, indent=2, sort_keys=True)
        file.write('\n')


def bundle_from_dict(data: Dict[str, Any]) -> EvidenceBundle:
    scope_data = data['scope']
    return EvidenceBundle(
        version=int(data['version']),
        fingerprint=str(data['fingerprint']),
        environment=str(data['environment']),
        evaluated_at=parse_datetime(str(data['evaluated_at'])),
        scope=BranchScope(
            name=str(scope_data['name']),
            branches=frozenset(str(branch) for branch in scope_data['branches']),
            frozen_at=str(scope_data['frozen_at']),
        ),
        receipts=tuple(
            receipt_from_dict(receipt_data)
            for receipt_data in data.get('receipts', [])
        ),
    )


def bundle_to_dict(bundle: EvidenceBundle) -> Dict[str, Any]:
    return {
        'version': bundle.version,
        'fingerprint': bundle.fingerprint,
        'environment': bundle.environment,
        'evaluated_at': bundle.evaluated_at.isoformat(),
        'scope': {
            'name': bundle.scope.name,
            'frozen_at': bundle.scope.frozen_at,
            'branches': sorted(bundle.scope.branches),
        },
        'receipts': [receipt_to_dict(receipt) for receipt in bundle.receipts],
    }


def receipt_from_dict(data: Dict[str, Any]) -> RotationReceipt:
    window = data['window']
    return RotationReceipt(
        receipt_id=str(data['receipt_id']),
        fingerprint=str(data['fingerprint']),
        window=RotationWindow(
            opens_at=parse_datetime(str(window['opens_at'])),
            closes_at=parse_datetime(str(window['closes_at'])),
        ),
        environment=str(data['environment']),
        revocation_scope=frozenset(str(branch) for branch in data['revocation_scope']),
        status=ReceiptStatus(data.get('status', ReceiptStatus.APPROVED.value)),
        kind=ReceiptKind(data.get('kind', ReceiptKind.ROTATION.value)),
        based_on=data.get('based_on'),
    )


def receipt_to_dict(receipt: RotationReceipt) -> Dict[str, Any]:
    return {
        'receipt_id': receipt.receipt_id,
        'fingerprint': receipt.fingerprint,
        'environment': receipt.environment,
        'window': {
            'opens_at': receipt.window.opens_at.isoformat(),
            'closes_at': receipt.window.closes_at.isoformat(),
        },
        'revocation_scope': sorted(receipt.revocation_scope),
        'status': receipt.status.value,
        'kind': receipt.kind.value,
        'based_on': receipt.based_on,
    }


def report_to_dict(report: ClosureReport) -> Dict[str, Any]:
    return {
        'fingerprint': report.fingerprint,
        'environment': report.environment,
        'evidence_version': report.evidence_version,
        'evaluated_at': report.evaluated_at.isoformat(),
        'closable_branches': list(report.closable_branches),
        'open_branches': list(report.open_branches),
        'decisions': [
            {
                'branch': decision.branch,
                'status': decision.status.value,
                'supporting_receipts': list(decision.supporting_receipts),
                'reasons': list(decision.reasons),
            }
            for decision in report.decisions
        ],
    }


def diff_to_dict(diff: ReportDiff) -> Dict[str, Any]:
    return {
        'original_evidence_version': diff.original_evidence_version,
        'current_evidence_version': diff.current_evidence_version,
        'reopened': list(diff.reopened),
        'still_closable': list(diff.still_closable),
        'newly_closable': list(diff.newly_closable),
        'still_open': list(diff.still_open),
    }


def fingerprints_from_baseline(path: str) -> List[str]:
    """Extracts only the hashed secrets from a detect-secrets baseline.

    The baseline never contains plaintext secrets, and this loader only reads
    the ``hashed_secret`` fields, so the closure flow stays plaintext-free.
    """
    with open(path) as file:
        data = json.load(file)
    return sorted({
        str(entry['hashed_secret'])
        for entries in data.get('results', {}).values()
        for entry in entries
    })
