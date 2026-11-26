from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from hashlib import sha256
from typing import Iterable, List, Optional, Sequence, Set, Tuple, Union, Type

import cbor2
from certvalidator import CertificateValidator
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pycose.algorithms import CoseAlg, CoseAlgorithm
from pycose.exceptions import CoseException, CoseInvalidCertificate


def _as_utc(moment: Optional[datetime]) -> datetime:
    """Return a timezone-aware UTC datetime."""

    if moment is None:
        return datetime.now(timezone.utc)
    if isinstance(moment, date) and not isinstance(moment, datetime):
        return datetime.combine(moment, time.min, tzinfo=timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _certificate_to_der(certificate) -> bytes:
    """Normalize a DER/PEM/asn1crypto/cryptography certificate to DER bytes."""

    if isinstance(certificate, str):
        certificate = certificate.encode()
    if isinstance(certificate, bytes):
        if certificate.lstrip().startswith(b'-----BEGIN'):
            certificate = x509.load_pem_x509_certificate(certificate)
        else:
            return certificate
    elif hasattr(certificate, 'public_bytes') and not isinstance(certificate, x509.Certificate):
        if hasattr(certificate, 'dump'):
            return certificate.dump()
    if isinstance(certificate, x509.Certificate):
        return certificate.public_bytes(serialization.Encoding.DER)
    if hasattr(certificate, 'dump'):
        return certificate.dump()
    raise TypeError(f"Unsupported certificate type: {type(certificate)!r}")


def load_certificate(certificate) -> x509.Certificate:
    """Load a certificate from DER, PEM, asn1crypto or cryptography input."""

    if isinstance(certificate, x509.Certificate):
        return certificate
    der = _certificate_to_der(certificate)
    return x509.load_der_x509_certificate(der)


def certificate_sha256(certificate) -> str:
    """Return the SHA-256 fingerprint of a certificate in lowercase hex."""

    return sha256(_certificate_to_der(certificate)).hexdigest()


def _validity(certificate: x509.Certificate) -> Tuple[datetime, datetime]:
    if hasattr(certificate, 'not_valid_before_utc'):
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    return (
        certificate.not_valid_before.replace(tzinfo=timezone.utc),
        certificate.not_valid_after.replace(tzinfo=timezone.utc),
    )


def _crl_times(crl) -> Tuple[Optional[datetime], Optional[datetime]]:
    last_update = getattr(crl, 'last_update_utc', None) or getattr(crl, 'last_update', None)
    next_update = getattr(crl, 'next_update_utc', None) or getattr(crl, 'next_update', None)
    if last_update is not None and last_update.tzinfo is None:
        last_update = last_update.replace(tzinfo=timezone.utc)
    if next_update is not None and next_update.tzinfo is None:
        next_update = next_update.replace(tzinfo=timezone.utc)
    return last_update, next_update


def _load_crl(crl) -> x509.CertificateRevocationList:
    if isinstance(crl, x509.CertificateRevocationList):
        return crl
    if isinstance(crl, str):
        crl = crl.encode()
    if not isinstance(crl, bytes):
        raise TypeError(f"Unsupported CRL type: {type(crl)!r}")
    if crl.lstrip().startswith(b'-----BEGIN'):
        return x509.load_pem_x509_crl(crl)
    return x509.load_der_x509_crl(crl)


def _revocation_status(crl, issuer: x509.Certificate, moment: datetime):
    """Return (applicable, revoked, stale) for a CRL at a moment."""

    _, next_update = _crl_times(crl)
    if next_update is not None and moment > next_update:
        return False, False, True
    try:
        if not crl.is_signature_valid(issuer.public_key()):
            return False, False, False
    except Exception:
        return False, False, False
    return True, False, False


@dataclass(frozen=True)
class X509ValidationResult:
    """Outcome of an offline, locally anchored X.509 path validation."""

    valid: bool
    path: Tuple[x509.Certificate, ...]
    reasons: Tuple[str, ...]
    revoked: bool = False


def validate_local_certificate_path(
        end_entity_cert,
        intermediate_certs: Iterable = (),
        trust_roots: Iterable = (),
        *,
        moment: Optional[datetime] = None,
        key_usage: Optional[Set[str]] = None,
        extended_key_usage: Optional[Set[str]] = None,
        extended_optional: bool = False,
        crls: Iterable = (),
        revocation_mode: str = 'soft-fail') -> X509ValidationResult:
    """Validate an X.509 path using only caller-supplied local material.

    The validator never fetches certificates, CRLs or OCSP responses.  A path
    is built from ``end_entity_cert`` through ``intermediate_certs`` to one of
    ``trust_roots`` and is checked at ``moment`` (default: now).  Revocation is
    evaluated against the supplied CRLs at that same moment, which is essential
    for historical reviews: a later revocation must not rewrite the conclusion
    that was true when a receipt was signed.
    """

    if revocation_mode not in {'soft-fail', 'hard-fail', 'require'}:
        raise ValueError("revocation_mode must be 'soft-fail', 'hard-fail' or 'require'")

    moment = _as_utc(moment)
    leaf = load_certificate(end_entity_cert)
    intermediates = [load_certificate(cert) for cert in intermediate_certs]
    roots = [load_certificate(cert) for cert in trust_roots]
    local_crls = [_load_crl(crl) for crl in crls]

    reasons: List[str] = []

    if not roots:
        return X509ValidationResult(False, (leaf,), ('no local trust anchors supplied',))

    root_fingerprints = {certificate_sha256(root) for root in roots}

    def build_path(path: Tuple[x509.Certificate, ...], current: x509.Certificate):
        if certificate_sha256(current) in root_fingerprints:
            return path
        for issuer in intermediates + roots:
            if issuer.subject != current.issuer:
                continue
            if any(certificate_sha256(issuer) == certificate_sha256(item) for item in path):
                continue
            try:
                current.verify_directly_issued_by(issuer)
            except Exception:
                continue
            result = build_path(path + (issuer,), issuer)
            if result is not None:
                return result
        return None

    path = build_path((leaf,), leaf)
    if path is None:
        return X509ValidationResult(
            False,
            (leaf,),
            ('unable to build certificate path to a local trust anchor',),
        )

    for index, certificate in enumerate(path):
        not_before, not_after = _validity(certificate)
        if moment < not_before:
            reasons.append(f'certificate {index} is not valid until {not_before.isoformat()}')
        if moment > not_after:
            reasons.append(f'certificate {index} expired at {not_after.isoformat()}')

        basic_constraints = None
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            pass

        if index > 0 and basic_constraints is not None and not basic_constraints.ca:
            reasons.append(f'certificate {index} is not a CA certificate')

        if index > 0 and basic_constraints is not None and basic_constraints.ca:
            try:
                key_usage_ext = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
                if not key_usage_ext.key_cert_sign:
                    reasons.append(f'certificate {index} is not allowed to sign certificates')
            except x509.ExtensionNotFound:
                pass

    if key_usage:
        try:
            usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
            for required in key_usage:
                try:
                    allowed = getattr(usage, required)
                except ValueError:
                    allowed = False
                if not allowed:
                    reasons.append(f'leaf certificate lacks required key usage: {required}')
        except x509.ExtensionNotFound:
            pass

    if extended_key_usage is not None:
        try:
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            allowed = {name.dotted_string for name in eku}
            missing = set(extended_key_usage) - allowed
            if missing:
                reasons.append('leaf certificate lacks required extended key usage: '
                               + ', '.join(sorted(missing)))
        except x509.ExtensionNotFound:
            if not extended_optional:
                reasons.append('leaf certificate has no extended key usage extension')

    revoked = False
    for index, certificate in enumerate(path[:-1]):
        issuer = path[index + 1]
        applicable = []
        stale = False
        for crl in local_crls:
            if crl.issuer != certificate.issuer:
                continue
            applies, _, crl_stale = _revocation_status(crl, issuer, moment)
            stale = stale or crl_stale
            if applies:
                applicable.append(crl)

        if not applicable:
            if revocation_mode == 'require' or (revocation_mode == 'hard-fail' and stale):
                reasons.append(f'no usable local revocation evidence for certificate {index}')
            continue

        for crl in applicable:
            for entry in crl:
                if entry.serial_number != certificate.serial_number:
                    continue
                revocation_date = getattr(entry, 'revocation_date_utc', None) \
                    or getattr(entry, 'revocation_date', None)
                if revocation_date is not None and revocation_date.tzinfo is None:
                    revocation_date = revocation_date.replace(tzinfo=timezone.utc)
                if revocation_date is not None and revocation_date <= moment:
                    revoked = True
                    reasons.append(
                        f'certificate {index} was revoked at {revocation_date.isoformat()}')

    return X509ValidationResult(not reasons, path, tuple(reasons), revoked)


def validate_certificate_chain(
        encoded_chain: Sequence,
        cose_key,
        trust_roots: Optional[Sequence] = None,
        key_ops: Optional[Sequence] = None,
        moment: Optional[datetime] = None,
        crls: Optional[Sequence] = None):
    """Validate a certificate chain and bind it to a CoseKey.

    This is the high-level API used by :class:`X5Chain`; it checks the leaf
    public key against ``cose_key``, COSE key operations, the local path and the
    validity/revocation state at ``moment``.
    """

    from pycose.extensions._x509_validate import validate_certificate_chain as _validate

    return _validate(
        encoded_chain,
        cose_key,
        trust_roots=trust_roots,
        key_ops=key_ops,
        moment=moment,
        crls=crls,
    )


def certificate_valid_at(certificate, moment: Optional[datetime]) -> bool:
    """Check a certificate's own validity window without path building."""

    moment = _as_utc(moment)
    not_before, not_after = _validity(load_certificate(certificate))
    return not_before <= moment <= not_after


def public_key_matches(cose_key, certificate) -> bool:
    """Check whether a certificate carries the public key of a CoseKey."""

    from pycose.extensions._x509_validate import public_key_matches as _public_key_matches

    return _public_key_matches(cose_key, load_certificate(certificate))


def key_ops_to_key_usage(key_ops):
    """Translate COSE key operations into X.509 key usage names."""

    from pycose.extensions._x509_validate import key_ops_to_key_usage as _translate

    return _translate(key_ops)


class X5Bag:
    def __init__(self, certificates: Union[List[bytes], bytes]):
        if isinstance(certificates, list) and len(certificates) == 1:
            self.certificates = certificates[0]
        else:
            self.certificates = certificates

    def encode(self) -> Union[bytes, List[bytes]]:
        return self.certificates


class X5T:
    @classmethod
    def from_certificate(cls, alg: Type['CoseAlg'], certificate: bytes, cbor_encoded: bool = False):
        """ Extract thumbprint from an encoded certificate. """
        if cbor_encoded:
            certificate = cbor2.loads(certificate)

        return cls(alg=alg, thumbprint=alg.compute_hash(certificate))

    @classmethod
    def decode(cls, item):
        """ Decode from a CBOR item. """

        return cls(alg=CoseAlgorithm.from_id(item[0]), thumbprint=item[1])

    def __init__(self, alg: Type['CoseAlg'], thumbprint: bytes):
        self.alg = alg
        self.thumbprint = thumbprint

    def __eq__(self, other: 'X5T'):
        return self.alg == other.alg and self.thumbprint == other.thumbprint

    def encode(self):
        """ Encode to a CBOR item. """
        return [self.alg, self.thumbprint]

    def matches(self, certificate: bytes, cbor_encoded: bool = False) -> bool:
        """ Determine if this thumbprint is for a given certificate."""

        if not self.thumbprint:
            return False

        if cbor_encoded:
            certificate = cbor2.loads(certificate)

        return self.thumbprint == self.alg.compute_hash(certificate)


class X5U:
    def __init__(self, uri: str):
        self.uri = uri

    def encode(self):
        return self.uri


class X5Chain:
    def __init__(self,
                 cert_chain: Union[List[bytes], bytes],
                 verify: bool = False,
                 key_usage: Optional[Set[str]] = None,
                 trust_roots: Optional[Sequence] = None,
                 moment: Optional[datetime] = None,
                 crls: Optional[Sequence] = None,
                 cose_key=None,
                 key_ops: Optional[Sequence] = None):
        if isinstance(cert_chain, list) and len(cert_chain) == 1:
            self.cert_chain = cert_chain[0]
        else:
            self.cert_chain = cert_chain

        if verify:
            if cose_key is not None:
                self.validate(
                    cose_key=cose_key,
                    trust_roots=trust_roots,
                    key_ops=key_ops,
                    moment=moment,
                    crls=crls,
                )
            else:
                self.verify_chain(
                    key_usage or {'digital_signature'},
                    trust_roots=trust_roots,
                    moment=moment,
                    crls=crls,
                )

    @property
    def certificates(self) -> List[bytes]:
        """The certificate chain, always returned as a list (leaf first)."""

        if isinstance(self.cert_chain, (list, tuple)):
            return list(self.cert_chain)
        return [self.cert_chain]

    def leaf_certificate(self) -> x509.Certificate:
        """Parse and return the leaf certificate."""

        from pycose.extensions._x509_validate import load_certificate

        if not self.certificates:
            raise CoseInvalidCertificate('The certificate chain is empty.')
        return load_certificate(self.certificates[0])

    def public_key_matches(self, cose_key) -> bool:
        """Check that the leaf certificate carries ``cose_key``'s public key."""

        from pycose.extensions._x509_validate import public_key_matches

        return public_key_matches(cose_key, self.leaf_certificate())

    def validate(self,
                 cose_key=None,
                 trust_roots: Optional[Sequence] = None,
                 key_ops: Optional[Sequence] = None,
                 moment: Optional[datetime] = None,
                 crls: Optional[Sequence] = None):
        """Validate the chain, CoseKey binding, key usage and validity time."""

        from pycose.extensions._x509_validate import validate_certificate_chain

        if cose_key is None:
            raise CoseInvalidCertificate(
                'A CoseKey is required to bind the certificate chain.'
            )
        return validate_certificate_chain(
            self.certificates,
            cose_key,
            trust_roots=trust_roots,
            key_ops=key_ops,
            moment=moment,
            crls=crls,
        )

    def verify_chain(self,
                     key_usage: Set[str],
                     trust_roots: Optional[Sequence] = None,
                     moment: Optional[datetime] = None,
                     crls: Optional[Sequence] = None,
                     extended_key_usage: Optional[Set[str]] = None,
                     extended_optional: bool = False,
                     revocation_mode: str = 'soft-fail'):
        """Validate a certificate chain.

        When local ``trust_roots`` are supplied the validation is performed by
        :func:`validate_local_certificate_path` and never touches the network.  The
        historical form of the call also accepts ``moment`` and local ``crls``.
        The legacy path (no local material) is kept for compatibility.
        """

        if trust_roots is not None or moment is not None or bool(crls):
            chain = self.cert_chain if isinstance(self.cert_chain, list) else [self.cert_chain]
            result = validate_local_certificate_path(
                chain[0],
                chain[1:],
                trust_roots or (),
                moment=moment,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                extended_optional=extended_optional,
                crls=crls or (),
                revocation_mode=revocation_mode,
            )
            if not result.valid:
                raise CoseException('; '.join(result.reasons))
            return list(result.path)

        val = CertificateValidator(
            end_entity_cert=(self.cert_chain[0] if isinstance(self.cert_chain, list)
                             else self.cert_chain),
            intermediate_certs=(self.cert_chain[1:] if isinstance(self.cert_chain, list)
                                else None),
        )
        return val.validate_usage(key_usage, extended_key_usage, extended_optional)

    def encode(self) -> Union[bytes, List[bytes]]:
        return self.cert_chain
