# coding: utf-8
"""
Small helper for building certificate-only PKCS#12 files.

The produced :class:`asn1crypto.pkcs12.Pfx` contains unencrypted certificate
bags and no key bags, so it is suitable as a display-only test archive. It is
also handy for unit tests and demonstrations that must never contain a real
private key.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto.cms import ContentInfo
from asn1crypto.core import BMPString, OctetString
from asn1crypto.pkcs12 import (
    Attribute,
    Attributes,
    AuthenticatedSafe,
    CertBag,
    Pfx,
    SafeBag,
    SafeContents,
    SetOfBMPString,
    SetOfKeyPurposeId,
    SetOfOctetString,
)
from asn1crypto.x509 import Certificate


def _attributes(friendly_name=None, local_key_id=None, trusted_usages=None):
    attributes = []
    if friendly_name is not None:
        values = SetOfBMPString()
        values.append(BMPString(friendly_name))
        attributes.append(Attribute({
            'type': 'friendly_name',
            'values': values,
        }))
    if local_key_id is not None:
        values = SetOfOctetString()
        values.append(OctetString(local_key_id))
        attributes.append(Attribute({
            'type': 'local_key_id',
            'values': values,
        }))
    if trusted_usages:
        usage_values = SetOfKeyPurposeId()
        for usage in trusted_usages:
            usage_values.append(usage)
        attributes.append(Attribute({
            'type': 'trusted_key_usage',
            'values': usage_values,
        }))
    if not attributes:
        return None
    bag_attributes = Attributes()
    for attribute in attributes:
        bag_attributes.append(attribute)
    return bag_attributes


def make_cert_safe_bag(certificate, friendly_name=None, local_key_id=None, trusted_usages=None):
    """
    :param certificate:
        An :class:`asn1crypto.x509.Certificate` or DER byte string
    :return:
        A cert-bag :class:`asn1crypto.pkcs12.SafeBag` carrying no key material
    """
    if isinstance(certificate, bytes):
        certificate = Certificate.load(certificate)
    cert_bag = CertBag({
        'cert_id': 'x509',
        'cert_value': certificate,
    })
    return SafeBag({
        'bag_id': 'cert_bag',
        'bag_value': cert_bag,
        'bag_attributes': _attributes(friendly_name, local_key_id, trusted_usages),
    })


def build_cert_only_pfx(cert_specs):
    """
    Build an unencrypted, certificate-only PFX.

    :param cert_specs:
        A list of dicts with keys:
         - ``certificate``: Certificate or DER bytes (required)
         - ``friendly_name``: unicode string (optional)
         - ``local_key_id``: byte string (optional)
         - ``trusted_usages``: list of KeyPurposeId native values (optional)
    :return:
        DER bytes of a PKCS#12 PFX with no MAC and no private key bags
    """
    safe_contents = SafeContents()
    for spec in cert_specs:
        safe_contents.append(make_cert_safe_bag(
            spec['certificate'],
            friendly_name=spec.get('friendly_name'),
            local_key_id=spec.get('local_key_id'),
            trusted_usages=spec.get('trusted_usages'),
        ))

    data_content_info = ContentInfo({
        'content_type': 'data',
        'content': safe_contents.dump(),
    })
    authenticated_safe = AuthenticatedSafe()
    authenticated_safe.append(data_content_info)
    pfx = Pfx({
        'version': 'v3',
        'auth_safe': ContentInfo({
            'content_type': 'data',
            'content': authenticated_safe.dump(),
        }),
    })
    return pfx.dump()
