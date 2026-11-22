"""
Use :class:`signxml.XMLSigner` and :class:`signxml.XMLVerifier` to sign and verify XML Signatures, respectively.
See `SignXML documentation <#synopsis>`_ for examples.
"""

from .algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureConstructionMethod, SignatureMethod
from .delivery import (
    AffectedRecipients,
    Contract,
    ContractVersion,
    DeliveryAudit,
    DeliveryCheckResult,
    DeliveryContract,
    DeliveryContractChecker,
    DeliveryDecision,
    DeliveryOutcome,
    DeliveryReport,
    DeliveryResult,
    DeliveryStatus,
    Field,
    FieldDeclaration,
    FieldOwner,
    FieldOwnership,
    FieldSpec,
    FieldStatus,
    ManualReview,
    ManualReviewSheet,
    ManualReviewTicket,
    Recipient,
    RecipientDeclaration,
    Receiver,
    ReceiverContract,
    ReceiverDeclaration,
    ReleaseContract,
    ReviewSheet,
    ReviewTicket,
    affected_recipients,
    audit_delivery,
    changed_field_ownership,
    check_contract,
    check_delivery,
    check_delivery_contract,
    delivery_contract_check,
    needs_resigning,
    reconcile_delivery,
    recipients_requiring_resignature,
    resign_required,
    verify_and_check_contract,
    verify_and_check_delivery_contract,
    verify_delivery_contract,
    verify_with_contract,
)
from .exceptions import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature
from .external import ExternalSigningKey, SigningRequest
from .processor import XMLSignatureProcessor
from .signer import SignatureReference, XMLSigner
from .util import namespaces
from .verifier import SignatureConfiguration, VerifyResult, XMLVerifier

methods = SignatureConstructionMethod
