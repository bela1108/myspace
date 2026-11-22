"""Offline retraction receipt construction and verification.

When a STIX object (e.g. an analytic conclusion) is revoked after it has
already been delivered to external parties, this module builds per-recipient
*retraction receipts* from a delivery ledger, and verifies them offline.

Receipt scoping rules:

* Delivery scope: a recipient group only gets a receipt if the revoked
  object was actually delivered to that group according to the ledger.
* Object versions: the notice kind depends on whether the group received
  the revoked version itself or only earlier, superseded versions.
* Marking visibility: receipt contents are filtered by the group's marking
  clearance, so one batch of recipients can never infer from its receipt
  what another batch received.

Legacy delivery records that lack the object payload are surfaced as
forensic gaps instead of being silently dropped.
"""

import hashlib
import json

from stix2.canonicalization.Canonicalize import canonicalize
from stix2.utils import parse_into_datetime

RECEIPT_TYPE = 'retraction-receipt'
RECEIPT_FORMAT_VERSION = '1.0'

NOTICE_RETRACT_DELIVERED = 'retract-delivered-copy'
NOTICE_RETRACT_SUPERSEDED = 'retract-superseded-copy'

GAP_MISSING_PAYLOAD = 'missing-payload'


class RetractionError(Exception):
    """Raised when retraction receipt operations cannot be performed."""


def _canonical_digest(obj):
    """SHA-256 hex digest of the canonical JSON form of ``obj``."""
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def _payload_of(stix_object):
    if isinstance(stix_object, dict):
        return dict(stix_object)
    if hasattr(stix_object, 'serialize'):
        return json.loads(stix_object.serialize())
    raise RetractionError(
        'cannot obtain a serialized payload from %r' % (stix_object,),
    )


def _parse_modified(value):
    if value is None:
        return None
    if isinstance(value, str):
        return parse_into_datetime(value)
    return value


class RecipientGroup:
    """A named batch of recipients with a marking clearance.

    ``marking_clearance`` is the set of marking-definition IDs the group is
    allowed to see.  An object is visible to the group only if every marking
    on it is within the clearance; unmarked objects are visible to all.
    """

    def __init__(self, name, marking_clearance=()):
        self.name = name
        self.marking_clearance = frozenset(marking_clearance)

    def can_see(self, markings):
        return set(markings or ()) <= self.marking_clearance

    def __repr__(self):
        return 'RecipientGroup(%r)' % (self.name,)


class DeliveryRecord:
    """One ledger entry: an object version delivered to a recipient group.

    ``payload`` is the serialized STIX object as delivered.  Legacy records
    may lack it (``payload=None``); those are forensic gaps.
    """

    def __init__(self, group, object_id, modified, markings=(), payload=None):
        self.group = group
        self.object_id = object_id
        self.modified = modified
        self.markings = tuple(markings or ())
        self.payload = payload

    @classmethod
    def from_object(cls, group, stix_object):
        """Build a record from a STIX object or serialized dict."""
        payload = _payload_of(stix_object)
        return cls(
            group,
            payload.get('id'),
            payload.get('modified'),
            payload.get('object_marking_refs', ()),
            payload,
        )

    @property
    def has_payload(self):
        return self.payload is not None

    def payload_digest(self):
        if not self.has_payload:
            raise RetractionError(
                'record for %s has no payload to digest' % (self.object_id,),
            )
        return _canonical_digest(self.payload)

    def __repr__(self):
        return 'DeliveryRecord(%r, %r, %r)' % (
            self.group, self.object_id, self.modified,
        )


class DeliveryLedger:
    """Offline record of which object versions were delivered to whom."""

    def __init__(self, groups=(), records=()):
        self._groups = {}
        self._records = []
        for group in groups:
            self.add_group(group)
        for record in records:
            self.add(record)

    def add_group(self, group):
        self._groups[group.name] = group

    def add(self, record):
        if record.group not in self._groups:
            raise RetractionError(
                'delivery record references unknown group %r' % (record.group,),
            )
        self._records.append(record)

    @property
    def groups(self):
        return dict(self._groups)

    @property
    def records(self):
        return list(self._records)

    def group(self, name):
        try:
            return self._groups[name]
        except KeyError:
            raise RetractionError('unknown recipient group %r' % (name,))

    def forensic_gaps(self, group=None, object_id=None):
        """Delivery records missing their object payload.

        These are the forensic gaps that must be reviewed before trusting
        any receipt built from this ledger.
        """
        return [
            record for record in self._records
            if not record.has_payload
            and (group is None or record.group == group)
            and (object_id is None or record.object_id == object_id)
        ]

    def find(self, group, object_id, modified):
        for record in self._records:
            if (
                record.group == group
                and record.object_id == object_id
                and record.modified == modified
            ):
                return record
        return None


def _version_entry(record):
    return {
        'object_id': record.object_id,
        'modified': record.modified,
        'payload_sha256': record.payload_digest(),
    }


def _gap_entry(record):
    entry = {
        'object_id': record.object_id,
        'reason': GAP_MISSING_PAYLOAD,
    }
    if record.modified is not None:
        entry['modified'] = record.modified
    return entry


def _sort_key(entry):
    return (entry['object_id'], entry.get('modified') or '')


def _build_group_receipt(ledger, group, revoked_id, revoked_modified, reason):
    delivered = [
        record for record in ledger.records
        if record.group == group.name and record.object_id == revoked_id
    ]
    visible = [record for record in delivered if group.can_see(record.markings)]
    if not visible:
        return None

    gaps = [record for record in visible if not record.has_payload]
    versions = [record for record in visible if record.has_payload]

    revoked_dt = _parse_modified(revoked_modified)
    delivered_dts = [
        parsed for parsed in (_parse_modified(r.modified) for r in visible)
        if parsed is not None
    ]
    if revoked_dt is not None and any(dt >= revoked_dt for dt in delivered_dts):
        notice = NOTICE_RETRACT_DELIVERED
    else:
        notice = NOTICE_RETRACT_SUPERSEDED

    related_ids = set()
    for record in versions:
        related_ids.update(record.payload.get('object_refs', ()))
    related_ids.discard(revoked_id)

    context = []
    for record in ledger.records:
        if (
            record.group == group.name
            and record.object_id in related_ids
            and group.can_see(record.markings)
        ):
            if record.has_payload:
                context.append(record)
            else:
                gaps.append(record)

    receipt = {
        'type': RECEIPT_TYPE,
        'receipt_format': RECEIPT_FORMAT_VERSION,
        'group': group.name,
        'revoked_object': {
            'object_id': revoked_id,
            'revoked_modified': revoked_modified,
        },
        'notice': notice,
        'delivered_versions': sorted(
            (_version_entry(r) for r in versions), key=_sort_key,
        ),
        'context': sorted((_version_entry(r) for r in context), key=_sort_key),
        'forensic_gaps': sorted((_gap_entry(r) for r in gaps), key=_sort_key),
    }
    if reason is not None:
        receipt['reason'] = reason
    receipt['receipt_sha256'] = _canonical_digest(receipt)
    return receipt


def build_retraction_receipts(ledger, revoked_id, revoked_modified,
                              reason=None):
    """Build one retraction receipt per recipient group that actually
    received the revoked object, per the delivery ledger.

    Returns a dict mapping group name to receipt.  Groups which never
    received the object (or cannot see any of the delivered copies) get no
    receipt.  Each receipt only contains information derived from that
    group's own delivered, marking-visible records.
    """
    receipts = {}
    for group in ledger.groups.values():
        receipt = _build_group_receipt(
            ledger, group, revoked_id, revoked_modified, reason,
        )
        if receipt is not None:
            receipts[group.name] = receipt
    return receipts


class ReceiptVerification:
    """Result of verifying a retraction receipt against a ledger."""

    def __init__(self, problems):
        self.problems = list(problems)

    @property
    def ok(self):
        return not self.problems

    def __repr__(self):
        return 'ReceiptVerification(ok=%r, problems=%r)' % (
            self.ok, self.problems,
        )


def verify_receipt(receipt, ledger):
    """Verify a retraction receipt offline against the delivery ledger.

    Checks that the receipt's digest is self-consistent, that it matches
    what the ledger warrants for its recipient group, and that every entry
    names an object version actually delivered to and visible to that
    group (so a receipt cannot smuggle in another batch's data).
    """
    problems = []

    group_name = receipt.get('group')
    try:
        group = ledger.group(group_name)
    except RetractionError as exc:
        return ReceiptVerification([str(exc)])

    body = {k: v for k, v in receipt.items() if k != 'receipt_sha256'}
    if _canonical_digest(body) != receipt.get('receipt_sha256'):
        problems.append('receipt-self-digest-invalid')

    entries = (
        receipt.get('delivered_versions', [])
        + receipt.get('context', [])
    )
    for entry in entries:
        record = ledger.find(
            group_name, entry.get('object_id'), entry.get('modified'),
        )
        label = '%s@%s' % (entry.get('object_id'), entry.get('modified'))
        if record is None:
            problems.append('entry-not-delivered-to-group: %s' % label)
        elif not group.can_see(record.markings):
            problems.append('entry-not-visible-to-group: %s' % label)
        elif (
            record.has_payload
            and record.payload_digest() != entry.get('payload_sha256')
        ):
            problems.append('payload-digest-mismatch: %s' % label)

    revoked = receipt.get('revoked_object', {})
    expected = _build_group_receipt(
        ledger,
        group,
        revoked.get('object_id'),
        revoked.get('revoked_modified'),
        receipt.get('reason'),
    )
    if expected is None:
        problems.append('receipt-not-warranted-by-ledger')
    elif expected['receipt_sha256'] != receipt.get('receipt_sha256'):
        problems.append('receipt-digest-mismatch')

    return ReceiptVerification(problems)
