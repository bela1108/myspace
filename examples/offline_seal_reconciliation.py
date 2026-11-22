"""End-to-end offline seal reconciliation demonstration."""

from __future__ import annotations

import json
from pathlib import Path

from seal_reconciliation.models import (
    Authorization,
    SealStatement,
    SourceLocation,
    public_key_from_dict,
    public_key_to_dict,
)
from seal_reconciliation.reconciler import Reconciler
from seal_reconciliation.report import (
    render_finance_page,
    render_json_report,
    render_security_page,
)
from seal_reconciliation.signing import issue_statement
from securesystemslib.signer import CryptoSigner


OUTPUT_DIR = Path(__file__).resolve().parent.parent / "demo_output"


def build_authorizations(officers: dict[str, CryptoSigner]) -> list[Authorization]:
    """Paper ledger ranges; liu is on leave and delegates the upper half."""
    liu_key = officers["liu"].public_key.keyid
    chen_key = officers["chen"].public_key.keyid
    zhao_key = officers["zhao"].public_key.keyid
    return [
        Authorization(
            officer_id="liu",
            keyid=liu_key,
            start=100,
            end=149,
            category="payment",
            note="保留半段（请假期间）",
        ),
        Authorization(
            officer_id="chen",
            keyid=chen_key,
            start=150,
            end=199,
            category="payment",
            note="代理 liu 的半段",
        ),
        Authorization(
            officer_id="zhao",
            keyid=zhao_key,
            start=100,
            end=149,
            category="contract",
        ),
    ]


def build_statements(officers: dict[str, CryptoSigner]) -> list[SealStatement]:
    """Simulate the archive: primary volume plus a backup volume."""
    liu = officers["liu"]
    chen = officers["chen"]
    zhao = officers["zhao"]
    statements = [
        issue_statement(
            liu,
            "ST-001",
            "payment",
            120,
            b"payment order A-120",
            SourceLocation("primary-archive", "p.001", 1),
        ),
        issue_statement(
            chen,
            "ST-002",
            "payment",
            160,
            b"payment order B-160 (proxy)",
            SourceLocation("primary-archive", "p.002", 3),
        ),
        issue_statement(
            zhao,
            "ST-003",
            "contract",
            130,
            b"contract C-130",
            SourceLocation("primary-archive", "p.010", 2),
        ),
    ]

    # ST-001 re-appears in the backup: identical signed material, new location.
    backup_copy = SealStatement(
        statement_id=statements[0].statement_id,
        category=statements[0].category,
        seal_number=statements[0].seal_number,
        material_digest=statements[0].material_digest,
        keyid=statements[0].keyid,
        signature=statements[0].signature,
        source=SourceLocation("backup-tape-7", "p.001", 1),
    )
    statements.append(backup_copy)

    # Number 120 is allowed to repeat in another category.
    statements.append(
        issue_statement(
            zhao,
            "ST-004",
            "contract",
            120,
            b"contract D-120 cross-category",
            SourceLocation("primary-archive", "p.011", 4),
        )
    )

    # Collision: same payment number 160 on materially different content.
    statements.append(
        issue_statement(
            chen,
            "ST-005",
            "payment",
            160,
            b"payment order B-160 conflicting content",
            SourceLocation("primary-archive", "p.040", 5),
        )
    )

    # Forged statement: valid key id but a tampered signature.
    forged = issue_statement(
        liu,
        "ST-006",
        "payment",
        130,
        b"payment order A-130",
        SourceLocation("primary-archive", "p.005", 2),
    )
    tampered_sig = forged.signature.__class__(
        keyid=forged.keyid,
        sig="00" * 32,
    )
    statements.append(
        SealStatement(
            statement_id=forged.statement_id,
            category=forged.category,
            seal_number=forged.seal_number,
            material_digest=forged.material_digest,
            keyid=forged.keyid,
            signature=tampered_sig,
            source=forged.source,
        )
    )

    # Out-of-range usage: 300 is outside every contract authorization.
    statements.append(
        issue_statement(
            zhao,
            "ST-007",
            "contract",
            300,
            b"contract E-300 beyond ledger",
            SourceLocation("primary-archive", "p.061", 1),
        )
    )
    return statements


def persist_archive(
    officers: dict[str, CryptoSigner],
    authorizations: list[Authorization],
    statements: list[SealStatement],
) -> None:
    """Write the offline inputs to disk, as an archive service would."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    registry = {
        signer.public_key.keyid: public_key_to_dict(signer.public_key)
        for signer in officers.values()
    }
    payload = {
        "authorizations": [item.to_dict() for item in authorizations],
        "key_registry": registry,
        "statements": [item.to_dict() for item in statements],
    }
    (OUTPUT_DIR / "archive_bundle.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def load_archive() -> tuple[list[Authorization], dict, list[SealStatement]]:
    """Reload everything from disk, proving the reconciliation is offline."""
    bundle = json.loads(
        (OUTPUT_DIR / "archive_bundle.json").read_text(encoding="utf-8")
    )
    authorizations = [
        Authorization.from_dict(item) for item in bundle["authorizations"]
    ]
    key_registry = {
        keyid: public_key_from_dict(data)
        for keyid, data in bundle["key_registry"].items()
    }
    statements = [SealStatement.from_dict(item) for item in bundle["statements"]]
    return authorizations, key_registry, statements


def main() -> None:
    officers = {
        name: CryptoSigner.generate_ed25519()
        for name in ("liu", "chen", "zhao")
    }
    authorizations = build_authorizations(officers)
    statements = build_statements(officers)
    persist_archive(officers, authorizations, statements)

    loaded_auth, loaded_keys, loaded_statements = load_archive()
    report = Reconciler(loaded_auth, loaded_keys).reconcile(loaded_statements)

    (OUTPUT_DIR / "finance_page.md").write_text(
        render_finance_page(report), encoding="utf-8"
    )
    (OUTPUT_DIR / "security_page.md").write_text(
        render_security_page(report), encoding="utf-8"
    )
    (OUTPUT_DIR / "reconciliation_report.json").write_text(
        render_json_report(report), encoding="utf-8"
    )
    print(render_finance_page(report))
    print()
    print(render_security_page(report))


if __name__ == "__main__":
    main()
