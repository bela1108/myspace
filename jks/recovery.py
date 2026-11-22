#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Offline recovery audit for JKS truststore backups.

Given the read-only entry listings exported from each restored keystore
backup, the change tickets describing a certificate switch, and the
sign-off records of every consuming party, decide for a given use
scenario:

  * which certificate generation should be restored, and
  * which historical keystores must be retained.

Two timelines are kept strictly separate:

  * ``exported_at`` -- when a keystore backup was exported from the
    duty machine, and
  * ``effective_at`` -- when a certificate switch became effective
    according to the change ticket.

A store's certificate generation is determined *only* by matching the
certificate fingerprint of its entries against the change tickets,
never by comparing ``exported_at`` with ``effective_at``.  A backup
exported after a switch may still carry the previous certificate (the
switch had not been applied on that machine yet), and the audit records
such observations as notes instead of drawing conclusions from them.

Sign-off records are evaluated per consumer.  A consumer that has not
signed off a generation is treated as not having accepted it; this is
never inferred from another consumer's sign-off.
"""
from __future__ import print_function

import json
from datetime import datetime

__all__ = [
    "RecoveryAuditError",
    "EntryRecord",
    "StoreListing",
    "ChangeTicket",
    "SignOff",
    "RecoveryPlan",
    "audit_recovery",
    "load_audit_input",
    "manifest_to_json",
]

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class RecoveryAuditError(Exception):
    """Raised when the audit inputs are inconsistent or insufficient."""
    pass


def _parse_time(value):
    return datetime.strptime(value, _TIME_FORMAT)


class EntryRecord(object):
    """One read-only entry of a keystore listing."""

    def __init__(self, alias, cert_fingerprint, cert_type=None):
        self.alias = alias
        self.cert_fingerprint = cert_fingerprint
        self.cert_type = cert_type

    @classmethod
    def from_dict(cls, data):
        return cls(data["alias"], data["cert_fingerprint"],
                   data.get("cert_type"))

    def to_dict(self):
        result = {"alias": self.alias,
                  "cert_fingerprint": self.cert_fingerprint}
        if self.cert_type is not None:
            result["cert_type"] = self.cert_type
        return result


class StoreListing(object):
    """Read-only entry listing exported from one keystore backup."""

    def __init__(self, store_id, exported_at, entries):
        self.store_id = store_id
        self.exported_at = exported_at
        self.entries = list(entries)

    @classmethod
    def from_dict(cls, data):
        return cls(data["store_id"], data["exported_at"],
                   [EntryRecord.from_dict(e) for e in data["entries"]])

    def to_dict(self):
        return {"store_id": self.store_id,
                "exported_at": self.exported_at,
                "entries": [e.to_dict() for e in self.entries]}


class ChangeTicket(object):
    """Change ticket describing one certificate switch for an alias."""

    def __init__(self, ticket_id, scenario, alias, previous_fingerprint,
                 new_fingerprint, effective_at, consumers):
        self.ticket_id = ticket_id
        self.scenario = scenario
        self.alias = alias
        self.previous_fingerprint = previous_fingerprint
        self.new_fingerprint = new_fingerprint
        self.effective_at = effective_at
        self.consumers = list(consumers)

    @classmethod
    def from_dict(cls, data):
        return cls(data["ticket_id"], data["scenario"], data["alias"],
                   data["previous_fingerprint"], data["new_fingerprint"],
                   data["effective_at"], data.get("consumers", []))

    def to_dict(self):
        return {"ticket_id": self.ticket_id,
                "scenario": self.scenario,
                "alias": self.alias,
                "previous_fingerprint": self.previous_fingerprint,
                "new_fingerprint": self.new_fingerprint,
                "effective_at": self.effective_at,
                "consumers": list(self.consumers)}


class SignOff(object):
    """One consumer's sign-off record for a certificate generation."""

    def __init__(self, consumer, ticket_id, fingerprint, signed_at):
        self.consumer = consumer
        self.ticket_id = ticket_id
        self.fingerprint = fingerprint
        self.signed_at = signed_at

    @classmethod
    def from_dict(cls, data):
        return cls(data["consumer"], data["ticket_id"],
                   data["fingerprint"], data["signed_at"])

    def to_dict(self):
        return {"consumer": self.consumer,
                "ticket_id": self.ticket_id,
                "fingerprint": self.fingerprint,
                "signed_at": self.signed_at}


class RecoveryPlan(object):
    """Result of an audit: what to restore and what to retain."""

    def __init__(self, scenario, alias, decision, restore, retain,
                 tickets, notes):
        self.scenario = scenario
        self.alias = alias
        self.decision = decision
        self.restore = restore
        self.retain = retain
        self.tickets = tickets
        self.notes = notes

    def to_manifest(self):
        return {
            "scenario": self.scenario,
            "alias": self.alias,
            "decision": self.decision,
            "restore": self.restore,
            "retain": self.retain,
            "tickets": self.tickets,
            "notes": self.notes,
        }


def load_audit_input(source):
    """Load audit input (listings, tickets, signoffs) from a JSON file
    path, file object, or an already-parsed dict."""
    if isinstance(source, dict):
        data = source
    elif hasattr(source, "read"):
        data = json.load(source)
    else:
        with open(source, "r") as fh:
            data = json.load(fh)
    listings = [StoreListing.from_dict(d) for d in data.get("listings", [])]
    tickets = [ChangeTicket.from_dict(d) for d in data.get("tickets", [])]
    signoffs = [SignOff.from_dict(d) for d in data.get("signoffs", [])]
    return listings, tickets, signoffs


def manifest_to_json(manifest):
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def audit_recovery(listings, tickets, signoffs, scenario):
    """Run the offline recovery audit for one use scenario.

    ``listings``  -- iterable of StoreListing (read-only entry lists)
    ``tickets``   -- iterable of ChangeTicket
    ``signoffs``  -- iterable of SignOff
    ``scenario``  -- the use scenario to audit

    Returns a RecoveryPlan.  Raises RecoveryAuditError if no certificate
    generation is signed off by every consumer of the scenario.
    """
    scenario_tickets = sorted(
        (t for t in tickets if t.scenario == scenario),
        key=lambda t: _parse_time(t.effective_at))
    if not scenario_tickets:
        raise RecoveryAuditError(
            "no change ticket found for scenario %r" % (scenario,))

    aliases = set(t.alias for t in scenario_tickets)
    if len(aliases) != 1:
        raise RecoveryAuditError(
            "scenario %r spans multiple aliases: %s"
            % (scenario, ", ".join(sorted(aliases))))
    alias = aliases.pop()

    # Certificate generations, oldest first.  Generation membership is
    # established purely by fingerprint, via the change tickets.
    generations = [scenario_tickets[0].previous_fingerprint]
    introduced_by = {scenario_tickets[0].previous_fingerprint: None}
    for ticket in scenario_tickets:
        generations.append(ticket.new_fingerprint)
        introduced_by[ticket.new_fingerprint] = ticket.ticket_id
    known_fingerprints = set(generations)

    # Ticket that documents each generation: the introducing ticket, or
    # the earliest ticket naming it as the previous certificate.
    documented_by = {}
    for fingerprint in generations:
        for ticket in scenario_tickets:
            if fingerprint in (ticket.previous_fingerprint,
                               ticket.new_fingerprint):
                documented_by[fingerprint] = ticket.ticket_id
                break

    required_consumers = sorted(
        set(c for t in scenario_tickets for c in t.consumers))

    tickets_by_id = dict((t.ticket_id, t) for t in scenario_tickets)
    notes = []

    # Only sign-offs that reference a ticket of this scenario and a
    # fingerprint actually named by that ticket are considered.
    valid_signoffs = []
    for signoff in signoffs:
        ticket = tickets_by_id.get(signoff.ticket_id)
        if ticket is None:
            continue
        if signoff.fingerprint not in (ticket.previous_fingerprint,
                                       ticket.new_fingerprint):
            notes.append(
                "sign-off of consumer '%s' on ticket %s names fingerprint "
                "%s which the ticket does not cover; record ignored"
                % (signoff.consumer, signoff.ticket_id,
                   signoff.fingerprint))
            continue
        valid_signoffs.append(signoff)

    def signers_of(fingerprint):
        return set(s.consumer for s in valid_signoffs
                   if s.fingerprint == fingerprint)

    # Sign-off completeness is evaluated per consumer; a missing
    # sign-off is never inferred from another consumer's record.
    missing_by_generation = {}
    for fingerprint in generations:
        missing = [c for c in required_consumers
                   if c not in signers_of(fingerprint)]
        missing_by_generation[fingerprint] = missing
        for consumer in missing:
            notes.append(
                "consumer '%s' has no sign-off for certificate %s; "
                "not inferred from other consumers"
                % (consumer, fingerprint))

    fully_signed = [fp for fp in generations
                    if not missing_by_generation[fp]]
    if not fully_signed:
        raise RecoveryAuditError(
            "no certificate generation of scenario %r is signed off by "
            "all consumers %s" % (scenario, ", ".join(required_consumers)))

    target = fully_signed[-1]
    decision = "current" if target == generations[-1] else "rollback"

    # Map each store's entries for this alias onto the generation chain.
    # exported_at is used only to order stores, never to classify them.
    store_entries = []
    for listing in sorted(listings,
                          key=lambda l: (_parse_time(l.exported_at),
                                         l.store_id)):
        matched = [e for e in listing.entries
                   if e.alias == alias
                   and e.cert_fingerprint in known_fingerprints]
        if matched:
            store_entries.append((listing, matched))

    for listing, matched in store_entries:
        exported = _parse_time(listing.exported_at)
        for entry in matched:
            for ticket in scenario_tickets:
                if (entry.cert_fingerprint == ticket.previous_fingerprint
                        and exported > _parse_time(ticket.effective_at)):
                    notes.append(
                        "store %s was exported at %s, after ticket %s "
                        "became effective at %s, yet still carries the "
                        "previous certificate %s; generation determined "
                        "by fingerprint, not by export time"
                        % (listing.store_id, listing.exported_at,
                           ticket.ticket_id, ticket.effective_at,
                           entry.cert_fingerprint))

    source_candidates = [l for l, m in store_entries
                         if any(e.cert_fingerprint == target for e in m)]
    if not source_candidates:
        raise RecoveryAuditError(
            "no keystore backup contains the certificate generation %s "
            "selected for scenario %r" % (target, scenario))
    source_store = source_candidates[-1]

    restore = {
        "alias": alias,
        "cert_fingerprint": target,
        "introduced_by": introduced_by[target],
        "documented_by": documented_by[target],
        "source_store": source_store.store_id,
        "exported_at": source_store.exported_at,
    }

    retain = []
    for listing, matched in store_entries:
        reasons = []
        for entry in matched:
            fingerprint = entry.cert_fingerprint
            if fingerprint == target:
                if listing.store_id == source_store.store_id:
                    reasons.append({
                        "reason": "restore_source",
                        "cert_fingerprint": fingerprint,
                        "ticket_id": documented_by[fingerprint],
                        "consumers": sorted(signers_of(fingerprint)),
                    })
                else:
                    reasons.append({
                        "reason": "backup_copy_of_restore_generation",
                        "cert_fingerprint": fingerprint,
                        "ticket_id": documented_by[fingerprint],
                        "consumers": sorted(signers_of(fingerprint)),
                    })
            generation_signers = sorted(signers_of(fingerprint))
            if generation_signers and fingerprint != target:
                reasons.append({
                    "reason": "generation_still_signed_off",
                    "cert_fingerprint": fingerprint,
                    "ticket_id": documented_by[fingerprint],
                    "consumers": generation_signers,
                })
        if reasons:
            retain.append({
                "store_id": listing.store_id,
                "exported_at": listing.exported_at,
                "entries": [e.to_dict() for e in matched],
                "reasons": reasons,
            })

    ticket_refs = [{
        "ticket_id": t.ticket_id,
        "effective_at": t.effective_at,
        "previous_fingerprint": t.previous_fingerprint,
        "new_fingerprint": t.new_fingerprint,
    } for t in scenario_tickets]

    return RecoveryPlan(scenario, alias, decision, restore, retain,
                        ticket_refs, notes)
