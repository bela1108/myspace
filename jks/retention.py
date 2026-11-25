"""Read-only JKS entry retention auditing.

This module never modifies a keystore.  It inspects the public certificate
material attached to private-key entries and, given caller-supplied retention
rules, decides whether each private-key entry is eligible for destruction.
"""

from __future__ import print_function

import datetime
import hashlib

from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459


#: The entry may be destroyed: every rule has expired and its public chain
#: can be rebuilt from material held elsewhere.
DESTROY = "destroy"
#: The entry must be retained because at least one retention rule still
#: covers its in-use or retention window.
RETAIN = "retain"
#: The entry cannot be destroyed yet because the evidence needed to rebuild
#: the public verification chain elsewhere is incomplete.
INSUFFICIENT_EVIDENCE = "insufficient_evidence"


def _fingerprint(der_bytes):
    """Stable identifier for a DER-encoded object (the full cert bytes)."""
    return hashlib.sha256(der_bytes).hexdigest()


def _parse_time(value):
    """Return a timezone-naive UTC datetime for an ASN.1 time value."""
    text = str(value)
    if len(text) >= 16 and text[:2] in ("19", "20"):
        year = int(text[:4])  # GeneralizedTime, YYYYMMDDHHMMSSZ
        rest = text[4:]
    else:
        year = 1900 + int(text[:2])  # UTCTime, YYMMDDHHMMSSZ
        if year < 1950:
            year += 100
        rest = text[2:]
    return datetime.datetime(year, int(rest[0:2]), int(rest[2:4]),
                             int(rest[4:6]), int(rest[6:8]), int(rest[8:10]))


class X509Cert(object):
    """A thin, read-only view over the DER bytes of an X.509 certificate.

    Identity is based on the raw DER bytes rather than the subject DN or
    serial number: synthetic and legacy certificates frequently reuse serial
    numbers or carry empty/non-unique distinguished names.
    """

    def __init__(self, der_bytes):
        self.der = bytes(der_bytes)
        self.fingerprint = _fingerprint(self.der)
        cert, _ = decoder.decode(self.der, asn1Spec=rfc2459.Certificate())
        tbs = cert["tbsCertificate"]
        self.subject_der = encoder.encode(tbs["subject"])
        self.issuer_der = encoder.encode(tbs["issuer"])
        self.subject_fp = _fingerprint(self.subject_der)
        self.issuer_fp = _fingerprint(self.issuer_der)
        self.not_before = _parse_time(tbs["validity"]["notBefore"].getComponent())
        self.not_after = _parse_time(tbs["validity"]["notAfter"].getComponent())

    @property
    def is_self_issued(self):
        return self.subject_der == self.issuer_der

    def __repr__(self):
        return "X509Cert(%s)" % self.fingerprint[:12]


class RetentionAuditException(Exception):
    """Superclass for retention-audit errors."""


class InvalidRuleException(RetentionAuditException):
    """Signifies that a caller-supplied retention rule is malformed."""


class ChainGap(object):
    """A missing certificate that prevents a chain from being rebuilt.

    :ivar str issuer_fp: Fingerprint of the issuer DN the missing cert must
      carry as its subject DN.
    :ivar str subject_fp: Fingerprint of the subject DN of the first cert that
      can no longer be linked upward.
    :ivar str reason: Machine-readable reason code for the gap.
    :ivar str needed_fingerprint: Fingerprint of the exact public certificate
      that would close the gap when known, else None.
    """

    def __init__(self, issuer_fp, subject_fp, reason, needed_fingerprint=None):
        self.issuer_fp = issuer_fp
        self.subject_fp = subject_fp
        self.reason = reason
        self.needed_fingerprint = needed_fingerprint

    def __eq__(self, other):
        if not isinstance(other, ChainGap):
            return NotImplemented
        return (self.issuer_fp == other.issuer_fp
                and self.subject_fp == other.subject_fp
                and self.reason == other.reason
                and self.needed_fingerprint == other.needed_fingerprint)

    def __repr__(self):
        return "ChainGap(reason=%r, needed=%s)" % (
            self.reason, self.needed_fingerprint)


class Blocker(object):
    """A single reason a private-key entry cannot be destroyed yet.

    :ivar str code: Machine-readable blocker code.
    :ivar str message: Human-readable explanation.
    :ivar str resolvable_by: Fingerprint of a public material that, if
      archived, would clear this blocker (None when not resolvable by
      adding public material).
    """

    def __init__(self, code, message, resolvable_by=None):
        self.code = code
        self.message = message
        self.resolvable_by = resolvable_by

    def __eq__(self, other):
        if not isinstance(other, Blocker):
            return NotImplemented
        return (self.code == other.code
                and self.message == other.message
                and self.resolvable_by == other.resolvable_by)

    def __repr__(self):
        return "Blocker(%r)" % self.code


class EntryDecision(object):
    """The retention decision for one private-key entry.

    :ivar str alias: Keystore alias of the private-key entry.
    :ivar str status: One of DESTROY, RETAIN, INSUFFICIENT_EVIDENCE.
    :ivar list[Blocker] blockers: Ordered blockers preventing destruction.
    :ivar list[str] chain_fingerprints: Fingerprints of the entry own attached
      chain certificates, leaf first.
    :ivar list[ChainGap] chain_gaps: Gaps that remain after attempting to
      rebuild the public chain elsewhere.
    :ivar dict rule_matches: Mapping of rule id to the rule verdict for this
      entry.
    """

    def __init__(self, alias, status, blockers=None, chain_fingerprints=None,
                 chain_gaps=None, rule_matches=None):
        self.alias = alias
        self.status = status
        self.blockers = blockers or []
        self.chain_fingerprints = chain_fingerprints or []
        self.chain_gaps = chain_gaps or []
        self.rule_matches = rule_matches or {}

    @property
    def can_destroy(self):
        return self.status == DESTROY

    @property
    def unblock_actions(self):
        """Fingerprints of public material whose archiving would unblock."""
        return sorted({b.resolvable_by for b in self.blockers
                       if b.resolvable_by})

    def __repr__(self):
        return "EntryDecision(%r, %r, blockers=%d)" % (
            self.alias, self.status, len(self.blockers))


class RetentionRule(object):
    """One caller-supplied retention rule.

    A rule demands retention while any of its applicable entries is still
    inside either its in-use window or its retention window.

    :param str rule_id: Unique identifier used in the report.
    :param datetime.datetime in_use_until: End of the active use period (UTC).
    :param datetime.datetime retain_until: End of the mandatory retention
      period (UTC).
    :param aliases: Aliases this rule applies to; None means every entry.
    :param str description: Optional human-readable description.
    """

    def __init__(self, rule_id, in_use_until, retain_until, aliases=None,
                 description=""):
        if retain_until < in_use_until:
            raise InvalidRuleException(
                "Rule %r: retain_until (%s) precedes in_use_until (%s)"
                % (rule_id, retain_until, in_use_until))
        self.rule_id = rule_id
        self.in_use_until = in_use_until
        self.retain_until = retain_until
        self.aliases = None if aliases is None else set(aliases)
        self.description = description

    def applies_to(self, alias):
        return self.aliases is None or alias in self.aliases

    def verdict(self, alias, now):
        """Return (in_use, retained) booleans for the entry at now."""
        if not self.applies_to(alias):
            return False, False
        return now <= self.in_use_until, now <= self.retain_until


class PublicMaterialCatalog(object):
    """Read-only registry of public X.509 material held outside the store.

    The catalog is the caller-supplied archive of public material (published
    CA bundles, archived intermediates, public records). It contains only
    certificates, never private keys. Duplicate certificates collapse onto a
    single catalog entry, so an extra copy of an already-known certificate
    never makes up for a genuinely missing intermediate.
    """

    def __init__(self, materials=None):
        self._by_fingerprint = {}
        self._by_subject = {}
        for material in materials or []:
            self.add(material)

    def add(self, der_bytes, source="external"):
        cert = der_bytes if isinstance(der_bytes, X509Cert) else X509Cert(der_bytes)
        if cert.fingerprint not in self._by_fingerprint:
            self._by_fingerprint[cert.fingerprint] = (cert, source)
            self._by_subject.setdefault(cert.subject_fp, []).append(cert)
        return cert

    def __contains__(self, fingerprint):
        return fingerprint in self._by_fingerprint

    def get(self, fingerprint):
        pair = self._by_fingerprint.get(fingerprint)
        return pair[0] if pair else None

    def source_of(self, fingerprint):
        pair = self._by_fingerprint.get(fingerprint)
        return pair[1] if pair else None

    def issuers_of(self, subject_fp):
        """Return catalog certs whose subject DN matches subject_fp."""
        return list(self._by_subject.get(subject_fp, []))

    def __len__(self):
        return len(self._by_fingerprint)

    @property
    def fingerprints(self):
        return set(self._by_fingerprint)


class PendingItem(object):
    """A caller-supplied outstanding action that may block destruction.

    Pending items capture unresolved evidence work (for example, an archived
    intermediate whose checksum still has to be verified). While a pending item
    is open and relevant to an entry, the evidence is treated as incomplete.

    :param str item_id: Unique identifier.
    :param str fingerprint: Public certificate fingerprint the item concerns,
      or None for a store-wide item.
    :param bool resolved: Whether the action has been completed.
    :param str description: Human-readable description.
    """

    def __init__(self, item_id, fingerprint=None, resolved=False, description=""):
        self.item_id = item_id
        self.fingerprint = fingerprint
        self.resolved = resolved
        self.description = description

    def affects(self, fingerprint):
        return self.fingerprint is None or self.fingerprint == fingerprint


class RetentionReport(object):
    """The full read-only retention audit result.

    :ivar datetime.datetime now: Reference instant the audit was run against.
    :ivar dict decisions: Alias -> EntryDecision for every private-key entry.
    :ivar list blockers_index: Distinct (fingerprint, blocker) unblock hints.
    """

    def __init__(self, now, decisions):
        self.now = now
        self.decisions = decisions

    @property
    def destroyable(self):
        return sorted(a for a, d in self.decisions.items() if d.can_destroy)

    @property
    def retained(self):
        return sorted(a for a, d in self.decisions.items()
                      if d.status == RETAIN)

    @property
    def blocked(self):
        return sorted(a for a, d in self.decisions.items()
                      if d.status == INSUFFICIENT_EVIDENCE)

    def unblock_recommendations(self):
        """Map public fingerprint -> aliases it would help unblock."""
        index = {}
        for alias, decision in self.decisions.items():
            for fingerprint in decision.unblock_actions:
                index.setdefault(fingerprint, set()).add(alias)
        return index


def rebuild_chain(leaf, catalog):
    """Attempt to rebuild the public chain above leaf using only catalog.

    The leaf itself is assumed to remain available (it is public material and
    is also re-published in the catalog by the caller when it must survive the
    private key). This function walks upward purely on issuer/subject DN links
    found in the external catalog; it never trusts the entry under audit.

    :returns: (rebuilt_certs, gaps). rebuilt_certs lists the catalog certs that
      were linked, starting at the leaf when the catalog holds it. gaps lists
      ChainGap objects for links that could not be satisfied externally.
    """
    rebuilt = []
    gaps = []

    leaf_in_catalog = catalog.get(leaf.fingerprint)
    if leaf_in_catalog is not None:
        rebuilt.append(leaf_in_catalog)
    else:
        gaps.append(ChainGap(
            issuer_fp=leaf.issuer_fp, subject_fp=leaf.subject_fp,
            reason="leaf_not_archived", needed_fingerprint=leaf.fingerprint))

    current = leaf
    seen = set([leaf.fingerprint])
    while not current.is_self_issued:
        candidates = [c for c in catalog.issuers_of(current.issuer_fp)
                      if c.fingerprint not in seen]
        if not candidates:
            gaps.append(ChainGap(
                issuer_fp=current.issuer_fp,
                subject_fp=current.subject_fp,
                reason="missing_intermediate"))
            break
        issuer_cert = candidates[0]
        rebuilt.append(issuer_cert)
        seen.add(issuer_cert.fingerprint)
        current = issuer_cert
    return rebuilt, gaps


def _entry_leaf_chain(entry):
    """Parse the public cert chain of a PrivateKeyEntry into X509Cert."""
    return [X509Cert(der) for _, der in entry.cert_chain]


def _rule_blockers(alias, rules, now):
    """Return blockers caused by still-active retention rules."""
    blockers = []
    matches = {}
    for rule in rules:
        in_use, retained = rule.verdict(alias, now)
        matches[rule.rule_id] = {"in_use": in_use, "retained": retained}
        if in_use:
            blockers.append(Blocker(
                "still_in_use",
                "Rule %s keeps the entry in its in-use window until %s"
                % (rule.rule_id, rule.in_use_until)))
        elif retained:
            blockers.append(Blocker(
                "retention_window_open",
                "Rule %s retains the entry until %s"
                % (rule.rule_id, rule.retain_until)))
    return blockers, matches


def _pending_blockers(chain_fingerprints, pending_items):
    """Return blockers for unresolved pending items touching the chain."""
    blockers = []
    for item in pending_items:
        if item.resolved:
            continue
        if any(item.affects(fp) for fp in chain_fingerprints):
            target = item.fingerprint if item.fingerprint in chain_fingerprints else None
            blockers.append(Blocker(
                "pending_item_open",
                "Pending item %s is unresolved: %s"
                % (item.item_id, item.description or "evidence follow-up"),
                resolvable_by=target))
    return blockers


def _gap_blockers(gaps):
    """Translate chain gaps into blockers, hinting the cert that unblocks."""
    blockers = []
    for gap in gaps:
        if gap.reason == "leaf_not_archived":
            blockers.append(Blocker(
                "leaf_not_archived",
                "The public leaf certificate is not held in the external "
                "archive; historical verification cannot be reconstructed.",
                resolvable_by=gap.needed_fingerprint))
        else:
            blockers.append(Blocker(
                "missing_intermediate",
                "No external public certificate carries the required issuer "
                "DN, so an intermediate of the verification chain is missing.",
                resolvable_by=gap.needed_fingerprint))
    return blockers


def audit_keystore(keystore, rules, catalog, pending_items=None, now=None):
    """Produce a read-only retention decision for every private-key entry.

    The keystore is never modified. For each PrivateKeyEntry the audit checks,
    in order:

      1. Retention rules (in-use window and retention window). While any rule
         still covers the entry, it must be retained regardless of evidence.
      2. Unresolved pending items that touch the entry public chain.
      3. Whether the full public verification chain can be rebuilt from the
         external public-material catalog alone. A duplicate certificate does
         not compensate for a missing intermediate, and incomplete evidence
         always yields INSUFFICIENT_EVIDENCE, never DESTROY.

    :param keystore: A loaded jks.KeyStore (read but not mutated).
    :param rules: Iterable of RetentionRule objects supplied by the caller.
    :param catalog: PublicMaterialCatalog of externally held public material.
    :param pending_items: Iterable of PendingItem objects supplied by caller.
    :param now: Reference UTC datetime; defaults to the current instant.
    :rtype: RetentionReport
    """
    if now is None:
        now = datetime.datetime.utcnow()
    pending_items = list(pending_items or [])
    rules = list(rules)
    decisions = {}

    for alias, entry in keystore.private_keys.items():
        chain = _entry_leaf_chain(entry)
        chain_fps = [c.fingerprint for c in chain]
        blockers, matches = _rule_blockers(alias, rules, now)

        if blockers:
            decisions[alias] = EntryDecision(
                alias, RETAIN, blockers=blockers,
                chain_fingerprints=chain_fps, rule_matches=matches)
            continue

        blockers = _pending_blockers(chain_fps, pending_items)
        leaf = chain[0]
        rebuilt, gaps = rebuild_chain(leaf, catalog)
        blockers.extend(_gap_blockers(gaps))

        status = DESTROY if not blockers else INSUFFICIENT_EVIDENCE
        decisions[alias] = EntryDecision(
            alias, status, blockers=blockers,
            chain_fingerprints=chain_fps, chain_gaps=gaps,
            rule_matches=matches)

    return RetentionReport(now, decisions)
