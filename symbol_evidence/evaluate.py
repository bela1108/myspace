"""Grade source-location claims against PE debug identities and sign-off rows."""

from .model import (
    DEBUG_RECORD_MATCH,
    DIGEST_VERIFIED,
    NAME_ONLY,
    NO_EVIDENCE,
    ClaimEvidence,
)


def _same_reference(left, right):
    return bool(left) and bool(right) and left.strip().lower() == right.strip().lower()


def _candidate_notes(claim, entry):
    notes = []
    if claim.digest is not None and claim.digest.is_complete:
        if entry.digest is not None and entry.digest.is_complete:
            if claim.digest.matches(entry.digest):
                notes.append("digest")
            else:
                notes.append("digest_mismatch")
    if any(entry.matches_name(value) for value in claim.name_candidates):
        notes.append("name")
    if claim.identity_key and entry.identity_key == claim.identity_key:
        notes.append("identity")
    if _same_reference(claim.receipt, entry.reference):
        notes.append("reference")
    return notes


def _candidate_conflicts(claim, entry, identities, pe_sha256, pdb_sha256):
    conflicts = []
    notes = _candidate_notes(claim, entry)

    if "digest_mismatch" in notes:
        conflicts.append(
            "签收表第 %s 行摘要与声明不一致" % (entry.row if entry.row else "?")
        )
    if entry.pe_digest is not None and entry.pe_digest.is_complete:
        if pe_sha256 and not entry.pe_digest.matches(pe_sha256):
            conflicts.append(
                "签收表第 %s 行 PE 摘要与实际镜像不一致"
                % (entry.row if entry.row else "?")
            )
    if entry.identity_key and identities:
        if not any(entry.matches_identity(identity) for identity in identities):
            conflicts.append(
                "签收表第 %s 行 GUID/Age 与 PE 调试记录不一致"
                % (entry.row if entry.row else "?")
            )
    if pdb_sha256 and entry.digest is not None and entry.digest.is_complete:
        if not entry.digest.matches(pdb_sha256):
            conflicts.append(
                "签收表第 %s 行符号文件摘要与实际 PDB 不一致"
                % (entry.row if entry.row else "?")
            )
    return conflicts


def _candidate_score(notes):
    score = 0
    if "digest" in notes:
        score += 100
    if "identity" in notes:
        score += 50
    if "name" in notes:
        score += 20
    if "reference" in notes:
        score += 10
    return score


def evaluate_claim(
    claim,
    identities,
    signoff_entries=None,
    pe_sha256=None,
    pdb_sha256=None,
):
    """Return a :class:`ClaimEvidence` for one claim.

    The level is the *strongest non-conflicting* evidence found.  A complete
    digest only becomes ``digest_verified`` when a sign-off row supplies the
    same complete digest.  A short/partial digest is recorded but is never
    compared or promoted.
    """

    identities = list(identities or [])
    signoff_entries = list(signoff_entries or [])
    reasons = []
    conflicts = []
    checks = {
        "name_match": False,
        "identity_checked": False,
        "identity_match": False,
        "identity_confirmed": False,
        "digest_present": bool(claim.digest),
        "digest_complete": bool(claim.digest and claim.digest.is_complete),
        "digest_match": False,
        "signoff_match": False,
        "receipt_match": False,
        "pe_digest_checked": False,
        "pe_digest_match": False,
        "pdb_digest_checked": bool(pdb_sha256),
        "pdb_digest_match": False,
    }

    name_identities = [
        identity for identity in identities if claim.matches_name(identity)
    ]
    checks["name_match"] = bool(name_identities)
    if name_identities:
        reasons.append(
            "显示名匹配 PE 调试记录中的 PDB 名称 %s"
            % (name_identities[0].pdb_name or name_identities[0].pdb_path or "?")
        )
    elif claim.name_candidates and identities:
        reasons.append("显示名未匹配 PE 调试记录中的 PDB 名称")

    matched_identity = None
    if claim.identity_key:
        checks["identity_checked"] = True
        identity_matches = [
            identity
            for identity in identities
            if claim.identity_key == identity.identity_key
        ]
        if identity_matches:
            matched_identity = identity_matches[0]
            checks["identity_match"] = True
            checks["identity_confirmed"] = True
            reasons.append(
                "声明的构建身份与 PE 调试记录 %s 吻合" % matched_identity.identity_key
            )
        elif identities:
            conflicts.append(
                "声明的构建身份 %s 与 PE 调试记录不一致" % claim.identity_key
            )
    else:
        reasons.append("声明未提供 GUID/Age 或 NB10/Age，无法做构建身份比对")

    if claim.digest is not None and not claim.digest.is_complete:
        reasons.append(
            "声明摘要不完整（%s 长度 %s，应为 %s 位），不能作为已证实依据"
            % (
                claim.digest.algorithm,
                len(claim.digest.value),
                claim.digest.expected_length or "?",
            )
        )
    elif claim.digest is None:
        reasons.append("声明未提供文件摘要")

    candidate_objects = []
    for entry in signoff_entries:
        notes = _candidate_notes(claim, entry)
        if not notes:
            continue
        entry_conflicts = _candidate_conflicts(
            claim, entry, identities, pe_sha256, pdb_sha256
        )
        candidate_objects.append(
            {
                "entry": entry,
                "notes": notes,
                "conflicts": entry_conflicts,
                "score": _candidate_score(notes),
            }
        )

    clean_candidates = [item for item in candidate_objects if not item["conflicts"]]
    if clean_candidates:
        best_candidate = max(clean_candidates, key=lambda item: item["score"])
    elif candidate_objects:
        best_candidate = max(candidate_objects, key=lambda item: item["score"])
        conflicts.extend(best_candidate["conflicts"])
    else:
        best_candidate = None
    best_entry = best_candidate["entry"] if best_candidate else None
    best_notes = best_candidate["notes"] if best_candidate else []

    if best_candidate:
        checks["signoff_match"] = True
        if "digest" in best_notes:
            checks["digest_match"] = True
            reasons.append(
                "签收表第 %s 行提供了完整且一致的摘要"
                % (best_entry.row if best_entry.row else "?")
            )
        if "reference" in best_notes:
            checks["receipt_match"] = True
            reasons.append("签收单号与声明一致")
        if best_entry.identity_key and identities:
            if any(best_entry.matches_identity(identity) for identity in identities):
                checks["identity_confirmed"] = True
                if not checks["identity_match"]:
                    reason = (
                        "签收表的构建身份与 PE 调试记录 %s 吻合"
                        % best_entry.identity_key
                    )
                    reasons.append(reason)
                if matched_identity is None:
                    matched_identity = next(
                        (
                            identity
                            for identity in identities
                            if best_entry.matches_identity(identity)
                        ),
                        None,
                    )
        if best_entry.pe_digest is not None and best_entry.pe_digest.is_complete:
            checks["pe_digest_checked"] = True
            if pe_sha256 and best_entry.pe_digest.matches(pe_sha256):
                checks["pe_digest_match"] = True
                reasons.append("签收表的 PE 摘要与实际镜像 SHA-256 一致")
    else:
        reasons.append("签收表中没有与该声明匹配的行")

    if claim.pe_digest is not None and claim.pe_digest.is_complete:
        checks["pe_digest_checked"] = True
        if pe_sha256 and claim.pe_digest.matches(pe_sha256):
            checks["pe_digest_match"] = True
            reasons.append("声明的 PE 摘要与实际镜像 SHA-256 一致")
        elif pe_sha256:
            conflicts.append("声明的 PE 摘要与实际镜像不一致")
        else:
            reasons.append("未提供实际 PE 摘要，无法核对声明的 PE 摘要")
    elif claim.pe_digest is not None:
        reasons.append("声明的 PE 摘要不完整，不能作为已证实依据")

    if pdb_sha256 and claim.digest is not None and claim.digest.is_complete:
        if claim.digest.matches(pdb_sha256):
            checks["pdb_digest_match"] = True
            reasons.append("声明的符号文件摘要与实际 PDB SHA-256 一致")
        else:
            conflicts.append("声明的符号文件摘要与实际 PDB 不一致")

    if (
        matched_identity
        and name_identities
        and not any(
            matched_identity.identity_key == identity.identity_key
            for identity in name_identities
        )
    ):
        conflicts.append("名称匹配与构建身份匹配指向不同的调试记录")

    level = NO_EVIDENCE
    if checks["name_match"] or checks["identity_match"] or checks["identity_confirmed"]:
        level = NAME_ONLY
    if checks["identity_confirmed"]:
        level = DEBUG_RECORD_MATCH
    if checks["digest_match"] and checks["digest_complete"] and not conflicts:
        level = DIGEST_VERIFIED

    if not checks["digest_complete"] and claim.digest is not None:
        reasons.append("摘要不完整，导出中的 verified 必为 false")

    return ClaimEvidence(
        claim=claim,
        level=level,
        checks=checks,
        reasons=reasons,
        conflicts=conflicts,
        identity=matched_identity,
        signoff=best_entry,
        matched_identities=name_identities,
    )


def evaluate_claims(
    claims,
    identities,
    signoff_entries=None,
    pe_sha256=None,
    pdb_sha256=None,
):
    return [
        evaluate_claim(
            claim,
            identities,
            signoff_entries=signoff_entries,
            pe_sha256=pe_sha256,
            pdb_sha256=pdb_sha256,
        )
        for claim in claims
    ]
