import sys
from collections.abc import Callable, Mapping
from typing import Any, TypeAlias

from ._cbor2 import CBORDecodeEOF as CBORDecodeEOF
from ._cbor2 import CBORDecodeError as CBORDecodeError
from ._cbor2 import CBORDecoder as CBORDecoder
from ._cbor2 import CBOREncodeError as CBOREncodeError
from ._cbor2 import CBOREncoder as CBOREncoder
from ._cbor2 import CBOREncodeTypeError as CBOREncodeTypeError
from ._cbor2 import CBOREncodeValueError as CBOREncodeValueError
from ._cbor2 import CBORError as CBORError
from ._cbor2 import CBORSimpleValue as CBORSimpleValue
from ._cbor2 import CBORTag as CBORTag
from ._cbor2 import dump as dump
from ._cbor2 import dumps as dumps
from ._cbor2 import load as load
from ._cbor2 import loads as loads
from ._cbor2 import shareable_decoder as shareable_decoder
from ._cbor2 import shareable_encoder as shareable_encoder
from ._cbor2 import undefined as undefined

if sys.hexversion < 51314855:
    from ._cbor2 import frozendict as frozendict

TagHook: TypeAlias = Callable[[CBORTag, bool], Any]
SemanticDecoderCallback: TypeAlias = Callable[[Any, bool], Any]
ObjectHook: TypeAlias = Callable[[Mapping[Any, Any], bool], Any]
EncoderHook: TypeAlias = Callable[[CBOREncoder, Any], Any]
ShareableDecoderCallback: TypeAlias = Callable[[Any], Any]
ShareableDecoderInitializer: TypeAlias = Callable[[bool], tuple[Any, ShareableDecoderCallback]]

del Any, Callable, Mapping, TypeAlias, sys

from .bundles import ABSENT as ABSENT
from .bundles import AuditReport as AuditReport
from .bundles import Bundle as Bundle
from .bundles import BundleManifest as BundleManifest
from .bundles import CROSS_REF_TAG as CROSS_REF_TAG
from .bundles import ChecklistEntry as ChecklistEntry
from .bundles import ChecklistItem as ChecklistItem
from .bundles import Conclusion as Conclusion
from .bundles import DENIED as DENIED
from .bundles import EntryDescriptor as EntryDescriptor
from .bundles import EntryId as EntryId
from .bundles import EvidencePolicy as EvidencePolicy
from .bundles import EvidencePermissions as EvidencePermissions
from .bundles import FORBIDDEN as FORBIDDEN
from .bundles import HandoverReport as HandoverReport
from .bundles import LOCAL_REF_TAG as LOCAL_REF_TAG
from .bundles import MISSING as MISSING
from .bundles import NOT_AUTHORIZED as NOT_AUTHORIZED
from .bundles import NOT_FOUND as NOT_FOUND
from .bundles import PRESENT as PRESENT
from .bundles import Package as Package
from .bundles import RESOLVED as RESOLVED
from .bundles import Reference as Reference
from .bundles import ReferenceKind as ReferenceKind
from .bundles import ReferenceState as ReferenceState
from .bundles import ReferenceStatus as ReferenceStatus
from .bundles import Resolution as Resolution
from .bundles import UNAPPROVED as UNAPPROVED
from .bundles import UNAUTHORIZED as UNAUTHORIZED
from .bundles import audit as audit
from .bundles import audit_bundles as audit_bundles
from .bundles import audit_claim as audit_claim
from .bundles import audit_handover as audit_handover
from .bundles import audit_packages as audit_packages
from .bundles import build_checklist as build_checklist
from .bundles import check_bundles as check_bundles
from .bundles import check_claim as check_claim
from .bundles import check_handover as check_handover
from .bundles import check_packages as check_packages
from .bundles import closure as closure
from .bundles import cross_ref as cross_ref
from .bundles import dump_bundle as dump_bundle
from .bundles import dumps_bundle as dumps_bundle
from .bundles import handover_audit as handover_audit
from .bundles import handover_check as handover_check
from .bundles import load_bundle as load_bundle
from .bundles import load_bundles as load_bundles
from .bundles import loads_bundle as loads_bundle
from .bundles import loads_bundles as loads_bundles
from .bundles import local_ref as local_ref
from .bundles import make_bundle as make_bundle
from .bundles import parse_bundle as parse_bundle
from .bundles import public_index as public_index
from .bundles import reference_semantic_decoders as reference_semantic_decoders
from .bundles import reference_tag_hook as reference_tag_hook
from .bundles import resolve_claim as resolve_claim
from .bundles import resolve_reference as resolve_reference
from .bundles import resolve_references as resolve_references
from .bundles import trace_references as trace_references
from .bundles import verify_claim as verify_claim
from .bundles import verify_handover as verify_handover
