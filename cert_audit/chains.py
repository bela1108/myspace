# coding: utf-8
"""
Local certificate chain confirmation without private keys.

Chain construction uses only public material contained in the archive:
CA flags, issuer names, subject/authority key identifiers and (when the
optional cryptography package is installed) cryptographic verification of
each signature with the issuer's public key. Nothing here ever reads a
private key.
"""

from __future__ import unicode_literals, division, absolute_import, print_function


SIGNATURE_VERIFY_AVAILABLE = False
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    SIGNATURE_VERIFY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without cryptography
    InvalidSignature = Exception


_HASH_ALGORITHMS = {}
if SIGNATURE_VERIFY_AVAILABLE:
    _HASH_ALGORITHMS = {
        'md5': hashes.MD5,
        'sha1': hashes.SHA1,
        'sha224': hashes.SHA224,
        'sha256': hashes.SHA256,
        'sha384': hashes.SHA384,
        'sha512': hashes.SHA512,
        'sha512_224': hashes.SHA512_224,
        'sha512_256': hashes.SHA512_256,
    }


def _hash(name):
    algorithm = _HASH_ALGORITHMS.get(name)
    if algorithm is None:
        raise ValueError('Unsupported hash algorithm: %s' % name)
    return algorithm()


def verify_signature(child_cert, issuer_cert):
    """
    Verify child_cert with the public key of issuer_cert.

    :return:
        True when the signature is valid, False otherwise. If cryptography
        is unavailable, None is returned to indicate that only structural
        matching was possible.
    """
    if not SIGNATURE_VERIFY_AVAILABLE:
        return None
    try:
        public_key = load_der_public_key(issuer_cert.public_key.dump())
        signature = child_cert.signature
        tbs_bytes = child_cert['tbs_certificate'].dump()
        algorithm = child_cert.signature_algo
        key_type = issuer_cert.public_key.algorithm

        if key_type == 'rsa':
            if algorithm == 'rsassa_pss':
                params = child_cert['signature_algorithm']['parameters'].parsed
                public_key.verify(
                    signature,
                    tbs_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(_hash(params['mask_gen_algorithm']['parameters'].native)),
                        salt_length=params['salt_length'].native,
                    ),
                    _hash(params['hash_algorithm'].native),
                )
            else:
                public_key.verify(
                    signature,
                    tbs_bytes,
                    padding.PKCS1v15(),
                    _hash(child_cert.hash_algo),
                )
        elif key_type == 'ec':
            public_key.verify(signature, tbs_bytes, ec.ECDSA(_hash(child_cert.hash_algo)))
        elif key_type == 'dsa':
            public_key.verify(signature, tbs_bytes, _hash(child_cert.hash_algo))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _index_cas(archive):
    by_subject = {}
    by_ski = {}
    for archive_cert in archive.certs:
        if not archive_cert.is_ca:
            continue
        by_subject.setdefault(archive_cert.subject, []).append(archive_cert)
        if archive_cert.subject_key_identifier:
            by_ski.setdefault(archive_cert.subject_key_identifier, []).append(archive_cert)
    return by_subject, by_ski


def _candidate_issuers(archive_cert, by_subject, by_ski):
    cert = archive_cert.certificate
    candidates = []
    akid = archive_cert.authority_key_identifier
    if akid and akid in by_ski:
        candidates.extend(by_ski[akid])

    same_name = by_subject.get(cert.issuer.human_friendly, [])
    for candidate in same_name:
        if candidate in candidates:
            continue
        if not akid or not candidate.subject_key_identifier or \
                candidate.subject_key_identifier == akid:
            candidates.append(candidate)
    return candidates


def confirm_chain(archive, archive_cert, verify_signatures=True):
    """
    Build the locally confirmable chain for one certificate.

    :return:
        A dict with confirmed (bool), path (list of fingerprints ordered
        leaf to root), signature_verified (bool/None) and reason (None or a
        short machine-readable explanation).
    """
    by_subject, by_ski = _index_cas(archive)
    path = [archive_cert.fingerprint]
    seen = set(path)
    current = archive_cert
    signatures_checked = 0
    signatures_valid = 0

    while not current.is_self_issued:
        candidates = _candidate_issuers(current, by_subject, by_ski)
        accepted = None
        for candidate in candidates:
            if candidate.fingerprint in seen:
                continue
            if not candidate.is_ca:
                continue
            if current.certificate.issuer.human_friendly != candidate.subject:
                continue
            if verify_signatures:
                valid = verify_signature(current.certificate, candidate.certificate)
                if valid is False:
                    continue
                if valid is True:
                    signatures_checked += 1
                    signatures_valid += 1
            accepted = candidate
            break

        if accepted is None:
            if not candidates:
                reason = 'missing_issuer'
            else:
                reason = 'issuer_not_ca_or_bad_signature'
            return {
                'confirmed': False,
                'path': path,
                'signature_verified': None if signatures_checked == 0 else signatures_checked == signatures_valid,
                'reason': reason,
            }

        path.append(accepted.fingerprint)
        seen.add(accepted.fingerprint)
        current = accepted

    if not current.is_ca:
        return {
            'confirmed': False,
            'path': path,
            'signature_verified': None,
            'reason': 'self_issued_terminus_not_ca',
        }
    if verify_signatures:
        valid = verify_signature(current.certificate, current.certificate)
        if valid is False:
            return {
                'confirmed': False,
                'path': path,
                'signature_verified': False,
                'reason': 'root_self_signature_invalid',
            }
        if valid is True:
            signatures_checked += 1
            signatures_valid += 1

    return {
        'confirmed': True,
        'path': path,
        'signature_verified': None if signatures_checked == 0 else signatures_checked == signatures_valid,
        'reason': None,
    }
