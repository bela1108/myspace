"""Accept synthetic COSE evidence envelopes without releasing plaintext."""

import json
import os

from pycose import (
    accept_envelope,
    check_envelope,
    require_publication_receipt,
)
from pycose import headers
from pycose.algorithms import A128GCM, A128KW
from pycose.keys import SymmetricKey
from pycose.keys.keyops import UnwrapOp, WrapOp
from pycose.keys.keyparam import KpAlg, KpKid, KpKeyOps
from pycose.messages import EncMessage
from pycose.messages.recipient import KeyWrap


MANIFEST = {
    "recipients": {
        "auditor": {
            "purposes": ["audit"],
            "attachment_groups": ["exhibits", "chain-of-custody"],
        },
        "counsel": {
            "purposes": ["litigation"],
            "attachment_groups": ["exhibits", "privileged"],
        },
    }
}


def _key(node):
    return SymmetricKey(
        k=os.urandom(16),
        optional_params={
            KpAlg: A128KW,
            KpKid: node.encode("utf-8"),
            KpKeyOps: [WrapOp, UnwrapOp],
        },
    )


def build_envelope():
    keys = {node: _key(node) for node in ("auditor", "counsel")}
    recipients = [
        KeyWrap(
            uhdr={headers.Algorithm: A128KW, headers.KID: node.encode("utf-8")},
            key=keys[node],
        )
        for node in keys
    ]
    message = EncMessage(
        phdr={headers.Algorithm: A128GCM, headers.IV: os.urandom(12)},
        uhdr={headers.KID: b"synthetic-evidence-1"},
        payload=b"synthetic evidence payload",
        recipients=recipients,
    )
    return message.encode(), keys


def main():
    envelope, keys = build_envelope()
    requests = {
        "recipient_requests": {
            "auditor": {"purpose": "audit", "attachment_groups": ["exhibits"]},
            "counsel": {"purpose": "litigation", "attachment_groups": ["privileged"]},
        }
    }
    report = accept_envelope(envelope, MANIFEST, keys, requests)
    require_publication_receipt(report, envelope, MANIFEST, requests)

    print(
        json.dumps(
            {
                "accepted": report.accepted,
                "receipt_id": report.receipt.receipt_id,
                "scopes": {
                    item.node: {
                        "allowed_purposes": list(item.allowed_purposes),
                        "allowed_attachment_groups": list(
                            item.allowed_attachment_groups
                        ),
                        "requested_purpose": item.requested_purpose,
                        "requested_attachment_groups": list(
                            item.requested_attachment_groups or ()
                        ),
                    }
                    for item in report.recipients
                },
            },
            indent=2,
            sort_keys=True,
        )
    )

    conflicting_manifest = [
        {
            "node": "auditor",
            "purposes": ["audit"],
            "attachment_groups": ["chain-of-custody"],
        },
        {
            "node": "auditor",
            "purposes": ["litigation"],
            "attachment_groups": ["privileged"],
        },
        {
            "node": "counsel",
            "purposes": ["litigation"],
            "attachment_groups": ["privileged"],
        },
    ]
    rejected = check_envelope(envelope, conflicting_manifest, keys, requests)
    print(
        json.dumps(
            {
                "conflict_report": {
                    "accepted": rejected.accepted,
                    "receipt": rejected.receipt,
                    "error_type": rejected.error_type,
                    "error": rejected.errors[0],
                }
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
