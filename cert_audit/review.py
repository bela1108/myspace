# coding: utf-8
"""
Review a public-material archive against a credential manifest.

Three review situations are always retained as findings, including the
certificates involved:

* duplicate friendly names (two same-subject certificates sharing a name),
* leaves without a locally confirmable chain,
* leaves with no authorized usage.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .chains import SIGNATURE_VERIFY_AVAILABLE, confirm_chain


FINDING_DUPLICATE_FRIENDLY_NAME = 'duplicate_friendly_name'
FINDING_NO_CONFIRMABLE_CHAIN = 'no_confirmable_chain'
FINDING_UNAUTHORIZED_USAGE = 'unauthorized_usage'

REVIEW_FINDINGS = (
    FINDING_DUPLICATE_FRIENDLY_NAME,
    FINDING_NO_CONFIRMABLE_CHAIN,
    FINDING_UNAUTHORIZED_USAGE,
)


def _leaf_certs(archive):
    return [archive_cert for archive_cert in archive.certs if not archive_cert.is_ca]


def _usage_intersection(archive_cert, requested_usage):
    eku = set(archive_cert.extended_key_usages)
    requested = set(requested_usage)
    if 'any_extended_key_usage' in eku:
        return sorted(requested)
    return sorted(eku & requested)


def _issuer_allowed(approval, chain_result, archive):
    if not approval.allowed_issuer_selectors:
        return True
    path_fingerprints = set(chain_result['path'][1:])
    for selector in approval.allowed_issuer_selectors:
        for fingerprint in path_fingerprints:
            if selector.matches(archive.get(fingerprint)):
                return True
    return False


def _review_leaf(archive, archive_cert, manifest, verify_signatures):
    chain_result = confirm_chain(archive, archive_cert, verify_signatures)
    approvals = manifest.leaf_approvals_for(archive_cert)

    approved = False
    approval_notes = []
    granted_usage = set()
    for approval in approvals:
        allowed_usage = approval.usage or manifest.allowed_usage
        matched_usage = _usage_intersection(archive_cert, allowed_usage)
        issuer_ok = _issuer_allowed(approval, chain_result, archive)
        if matched_usage and issuer_ok:
            approved = True
            granted_usage.update(matched_usage)
        else:
            if not matched_usage:
                approval_notes.append('no matching EKU for %s' % approval.selector.describe())
            if not issuer_ok:
                approval_notes.append('approved issuer absent from chain for %s' % approval.selector.describe())

    if not approvals:
        approval_notes.append('no manifest entry matches this leaf')

    return {
        'fingerprint_sha256': archive_cert.fingerprint,
        'subject': archive_cert.subject,
        'friendly_names': list(archive_cert.friendly_names),
        'is_ca': archive_cert.is_ca,
        'extended_key_usages': archive_cert.extended_key_usages,
        'chain': chain_result,
        'manifest_matches': len(approvals),
        'approved': approved,
        'granted_usage': sorted(granted_usage),
        'approval_notes': approval_notes,
    }


def _review_intermediates(archive, manifest):
    results = []
    for archive_cert in archive.certs:
        if not archive_cert.is_ca:
            continue
        approvals = manifest.intermediate_approvals_for(archive_cert)
        results.append({
            'fingerprint_sha256': archive_cert.fingerprint,
            'subject': archive_cert.subject,
            'friendly_names': list(archive_cert.friendly_names),
            'is_self_issued': archive_cert.is_self_issued,
            'manifest_matches': len(approvals),
            'approved': bool(approvals),
        })
    return results


def _duplicate_friendly_name_findings(archive):
    findings = []
    for friendly_name, archive_certs in sorted(archive.friendly_name_index.items()):
        unique = []
        for archive_cert in archive_certs:
            if archive_cert not in unique:
                unique.append(archive_cert)
        if len(unique) < 2:
            continue
        subjects = sorted(set(archive_cert.subject for archive_cert in unique))
        findings.append({
            'type': FINDING_DUPLICATE_FRIENDLY_NAME,
            'friendly_name': friendly_name,
            'same_subject': len(subjects) == 1,
            'subjects': subjects,
            'certificates': [archive_cert.fingerprint for archive_cert in unique],
        })
    return findings


def review_archive(archive, manifest, verify_signatures=True):
    """
    Review one archive against a manifest.

    :param archive:
        An :class:`~cert_audit.archive.Archive`
    :param manifest:
        A :class:`~cert_audit.manifest.CredentialManifest`
    :param verify_signatures:
        When True (default) signatures are checked if cryptography is
        installed; otherwise the chain is confirmed structurally.
    :return:
        A JSON-serializable review result.
    """
    leaves = [
        _review_leaf(archive, archive_cert, manifest, verify_signatures)
        for archive_cert in _leaf_certs(archive)
    ]

    findings = _duplicate_friendly_name_findings(archive)
    for leaf in leaves:
        if not leaf['chain']['confirmed']:
            findings.append({
                'type': FINDING_NO_CONFIRMABLE_CHAIN,
                'fingerprint_sha256': leaf['fingerprint_sha256'],
                'subject': leaf['subject'],
                'reason': leaf['chain']['reason'],
                'partial_path': list(leaf['chain']['path']),
            })
        if not leaf['approved']:
            findings.append({
                'type': FINDING_UNAUTHORIZED_USAGE,
                'fingerprint_sha256': leaf['fingerprint_sha256'],
                'subject': leaf['subject'],
                'reasons': list(leaf['approval_notes']),
            })

    intermediates = _review_intermediates(archive, manifest)
    confirmed_leaves = [leaf for leaf in leaves if leaf['chain']['confirmed']]
    approved_leaves = [leaf for leaf in leaves if leaf['approved']]
    ready_for_handover = bool(leaves) and len(confirmed_leaves) == len(leaves) and \
        len(approved_leaves) == len(leaves)

    return {
        'source': archive.source,
        'signature_verification': {
            'enabled': bool(verify_signatures),
            'cryptography_available': SIGNATURE_VERIFY_AVAILABLE,
        },
        'inventory': archive.inventory(),
        'leaves': leaves,
        'intermediates': intermediates,
        'findings': findings,
        'summary': {
            'leaf_count': len(leaves),
            'confirmable_chain_count': len(confirmed_leaves),
            'approved_leaf_count': len(approved_leaves),
            'duplicate_friendly_name_count': sum(
                1 for finding in findings if finding['type'] == FINDING_DUPLICATE_FRIENDLY_NAME
            ),
            'no_confirmable_chain_count': sum(
                1 for finding in findings if finding['type'] == FINDING_NO_CONFIRMABLE_CHAIN
            ),
            'unauthorized_usage_count': sum(
                1 for finding in findings if finding['type'] == FINDING_UNAUTHORIZED_USAGE
            ),
            'private_key_material_present': archive.private_key_material_present,
            'ready_for_handover': ready_for_handover,
        },
    }
