# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Offline queue audit for CVSS-scored tickets.

Keeps the submission-time CVSS version and vector of every ticket, derives a
service priority from configurable, cross-version comparable tiers, and
records an audit trail explaining every queue position change.

The module is fully offline and deterministic: the caller supplies a clock
(any callable returning a datetime), so tests and replays can use a fixed
clock.
"""

from __future__ import unicode_literals

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSError


class QueueAuditError(Exception):
    """
    Raised on invalid queue audit operations.
    """


def detect_version(vector):
    """
    Detects the CVSS version of a vector string.

    Args:
        vector (str): CVSS vector string

    Returns:
        str: "2.0", "3.0", "3.1" or "4.0"
    """
    if vector.startswith("CVSS:4.0"):
        return "4.0"
    if vector.startswith("CVSS:3.1"):
        return "3.1"
    if vector.startswith("CVSS:3.0"):
        return "3.0"
    return "2.0"


def base_score(version, vector):
    """
    Computes the base score of a vector using the existing CVSS scorers.

    Args:
        version (str): CVSS version, one of "2.0", "3.0", "3.1", "4.0"
        vector (str): CVSS vector string

    Returns:
        float: the base score
    """
    if version == "2.0":
        return float(CVSS2(vector).scores()[0])
    if version in ("3.0", "3.1"):
        return float(CVSS3(vector).scores()[0])
    if version == "4.0":
        return float(CVSS4(vector).scores()[0])
    raise QueueAuditError("Unsupported CVSS version: {0}".format(version))


class Tier(object):
    """
    One comparable service-priority band. Tiers are comparable across CVSS
    versions: a ticket lands in a tier when its version is listed in
    'versions' and its base score falls inside [min_score, max_score].
    """

    def __init__(self, name, min_score, max_score, versions):
        self.name = name
        self.min_score = float(min_score)
        self.max_score = float(max_score)
        self.versions = frozenset(versions)

    def matches(self, version, score):
        return version in self.versions and self.min_score <= score <= self.max_score


class Ticket(object):
    """
    A queued ticket. The submission-time version and vector are kept
    untouched; corrections append to the history and replace only the
    current vector.
    """

    def __init__(self, ticket_id, version, vector, submitted_at):
        self.ticket_id = ticket_id
        self.submitted_at = submitted_at
        self.submission_version = version
        self.submission_vector = vector
        self.version = version
        self.vector = vector
        self.score = base_score(version, vector)
        self.history = [(submitted_at, version, vector, self.score)]
        self.pin = None  # (approver, approved_at, expires_at) while pinned

    def correct(self, version, vector, at):
        self.version = version
        self.vector = vector
        self.score = base_score(version, vector)
        self.history.append((at, version, vector, self.score))


class AuditEntry(object):
    """
    One explained movement (or deliberate non-movement) of a ticket.
    """

    def __init__(self, at, event, ticket_id, from_pos, to_pos, reason):
        self.at = at
        self.event = event
        self.ticket_id = ticket_id
        self.from_pos = from_pos
        self.to_pos = to_pos
        self.reason = reason

    def render(self):
        if self.from_pos is None and self.to_pos is None:
            movement = "outside the automatic queue"
        elif self.from_pos == self.to_pos:
            movement = "stays at {0}".format(self.to_pos)
        else:
            movement = "moved {0} -> {1}".format(self.from_pos, self.to_pos)
        return "[{0}] {1}: {2} ({3})".format(
            self.at.isoformat(), self.ticket_id, movement, self.reason
        )


class QueueAudit(object):
    """
    Offline audit of a ticket queue prioritized by CVSS tiers.

    Args:
        tiers (list): tier definitions, highest priority first, each a dict
                      with keys 'name', 'min_score', 'max_score' and
                      'versions' (iterable of CVSS version strings)
        clock (callable): returns the current time as a datetime; supply a
                          fixed clock for deterministic replays
    """

    def __init__(self, tiers, clock):
        self.tiers = [
            Tier(t["name"], t["min_score"], t["max_score"], t["versions"]) for t in tiers
        ]
        self.clock = clock
        self.tickets = {}
        self.manual = []  # ticket ids held for manual handling, arrival order
        self.log = []
        self._order = []

    def _tier_rank(self, ticket):
        for rank, tier in enumerate(self.tiers):
            if tier.matches(ticket.version, ticket.score):
                return rank
        return None

    def _natural_order(self):
        """
        Queue order without pins: tier first, then score descending; equal
        keys keep the existing queue order (stable sort).
        """
        current = list(self._order)
        index = {ticket_id: position for position, ticket_id in enumerate(current)}
        sortable = [t for t in current if self.tickets[t].pin is None]
        sortable.sort(
            key=lambda t: (self._tier_rank(self.tickets[t]), -self.tickets[t].score, index[t])
        )
        return sortable

    def _rebuild(self):
        """
        Recomputes the effective queue: unexpired pins on top (oldest pin
        first), then the natural order of everything else.
        """
        pinned = [t for t in self._order if self.tickets[t].pin is not None]
        self._order = pinned + self._natural_order()

    def _positions(self):
        return {ticket_id: i + 1 for i, ticket_id in enumerate(self._order)}

    def _expire_pins(self, now):
        for ticket_id in list(self._order):
            ticket = self.tickets[ticket_id]
            if ticket.pin is not None and ticket.pin[2] <= now:
                before = self._positions()
                approver, _, expires_at = ticket.pin
                ticket.pin = None
                self._rebuild()
                after = self._positions()
                tier = self.tiers[self._tier_rank(ticket)]
                self.log.append(
                    AuditEntry(
                        now,
                        "pin-expired",
                        ticket_id,
                        before[ticket_id],
                        after[ticket_id],
                        "approved jump by {0} expired at {1}; restored to natural "
                        "position (tier {2}, score {3})".format(
                            approver, expires_at.isoformat(), tier.name, ticket.score
                        ),
                    )
                )
                self._log_displaced(now, "pin-expired", before, after, ticket_id)

    def _log_displaced(self, now, event, before, after, cause_id):
        for ticket_id in self._order:
            if ticket_id == cause_id:
                continue
            if before.get(ticket_id) != after.get(ticket_id):
                self.log.append(
                    AuditEntry(
                        now,
                        event,
                        ticket_id,
                        before.get(ticket_id),
                        after[ticket_id],
                        "shifted by {0}".format(cause_id),
                    )
                )

    def submit(self, ticket_id, vector, version=None):
        """
        Submits a new ticket, keeping its version and vector at submission
        time. Tickets whose version has no configured tier are held in a
        manual-handling slot outside the automatic queue.
        """
        now = self.clock()
        self._expire_pins(now)
        if ticket_id in self.tickets:
            raise QueueAuditError("Duplicate ticket: {0}".format(ticket_id))
        version = version or detect_version(vector)
        try:
            ticket = Ticket(ticket_id, version, vector, now)
        except CVSSError as error:
            raise QueueAuditError(
                "Invalid vector for {0}: {1}".format(ticket_id, error)
            )
        self.tickets[ticket_id] = ticket
        if self._tier_rank(ticket) is None:
            self.manual.append(ticket_id)
            self.log.append(
                AuditEntry(
                    now,
                    "submit",
                    ticket_id,
                    None,
                    None,
                    "held for manual handling: version {0} has no configured tier "
                    "(score {1})".format(version, ticket.score),
                )
            )
            return
        before = self._positions()
        self._order.append(ticket_id)
        self._rebuild()
        after = self._positions()
        tier = self.tiers[self._tier_rank(ticket)]
        self.log.append(
            AuditEntry(
                now,
                "submit",
                ticket_id,
                None,
                after[ticket_id],
                "submitted with {0} vector (kept on record), tier {1}, "
                "score {2}".format(version, tier.name, ticket.score),
            )
        )
        self._log_displaced(now, "submit", before, after, ticket_id)

    def correct(self, ticket_id, vector, version=None):
        """
        Corrects the vector of a ticket. Only corrections that genuinely
        cross a tier boundary reorder the queue; within a tier, equal
        scores keep the existing queue order.
        """
        now = self.clock()
        self._expire_pins(now)
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            raise QueueAuditError("Unknown ticket: {0}".format(ticket_id))
        version = version or detect_version(vector)
        old_rank = self._tier_rank(ticket)
        old_score = ticket.score
        try:
            ticket.correct(version, vector, now)
        except CVSSError as error:
            raise QueueAuditError(
                "Invalid vector for {0}: {1}".format(ticket_id, error)
            )
        new_rank = self._tier_rank(ticket)
        was_manual = ticket_id in self.manual

        if new_rank is None and not was_manual:
            before = self._positions()
            self._order = [t for t in self._order if t != ticket_id]
            self.manual.append(ticket_id)
            self._rebuild()
            after = self._positions()
            self.log.append(
                AuditEntry(
                    now,
                    "correct",
                    ticket_id,
                    before[ticket_id],
                    None,
                    "correction left version {0} without a configured tier; "
                    "moved to manual handling".format(version),
                )
            )
            self._log_displaced(now, "correct", before, after, ticket_id)
            return

        if new_rank is not None and was_manual:
            self.manual.remove(ticket_id)
            self._order.append(ticket_id)
            self._rebuild()
            after = self._positions()
            tier = self.tiers[new_rank]
            self.log.append(
                AuditEntry(
                    now,
                    "correct",
                    ticket_id,
                    None,
                    after[ticket_id],
                    "correction reached configured tier {0} (score {1}); "
                    "left manual handling".format(tier.name, ticket.score),
                )
            )
            return

        if new_rank is None and was_manual:
            self.log.append(
                AuditEntry(
                    now,
                    "correct",
                    ticket_id,
                    None,
                    None,
                    "stays in manual handling: version {0} still has no "
                    "configured tier".format(version),
                )
            )
            return

        before = self._positions()
        self._rebuild()
        after = self._positions()
        old_tier = self.tiers[old_rank].name
        new_tier = self.tiers[new_rank].name
        if old_rank != new_rank:
            reason = (
                "cross-tier correction {0} -> {1} (score {2} -> {3}); "
                "queue reordered".format(old_tier, new_tier, old_score, ticket.score)
            )
        elif old_score != ticket.score:
            reason = "within-tier correction in {0} (score {1} -> {2})".format(
                old_tier, old_score, ticket.score
            )
        else:
            reason = (
                "correction keeps tier {0} and score {1}; existing queue "
                "order kept".format(old_tier, old_score)
            )
        self.log.append(
            AuditEntry(now, "correct", ticket_id, before[ticket_id], after[ticket_id], reason)
        )
        self._log_displaced(now, "correct", before, after, ticket_id)

    def pin(self, ticket_id, approver, expires_at):
        """
        Short-term, independently approved jump to the front of the queue.
        The approval (handler sign-off and expiry) is recorded; when the
        clock passes 'expires_at' the ticket returns to its natural
        position.
        """
        now = self.clock()
        self._expire_pins(now)
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            raise QueueAuditError("Unknown ticket: {0}".format(ticket_id))
        if ticket_id in self.manual:
            raise QueueAuditError(
                "Cannot pin {0}: ticket is held for manual handling".format(ticket_id)
            )
        if expires_at <= now:
            raise QueueAuditError("Pin expiry must be in the future")
        before = self._positions()
        ticket.pin = (approver, now, expires_at)
        self._order = [ticket_id] + [t for t in self._order if t != ticket_id]
        self._rebuild()
        after = self._positions()
        self.log.append(
            AuditEntry(
                now,
                "pin",
                ticket_id,
                before[ticket_id],
                after[ticket_id],
                "short-term jump approved by {0}, expires at {1}".format(
                    approver, expires_at.isoformat()
                ),
            )
        )
        self._log_displaced(now, "pin", before, after, ticket_id)

    def advance(self):
        """
        Applies pending pin expirations at the current clock time.
        """
        self._expire_pins(self.clock())

    def queue(self):
        """
        Returns the current effective queue as a list of ticket ids.
        """
        self._expire_pins(self.clock())
        return list(self._order)

    def manual_queue(self):
        """
        Returns ticket ids held for manual handling, in arrival order.
        """
        return list(self.manual)

    def report(self):
        """
        Renders the audit trail, one explained movement per line.
        """
        return "\n".join(entry.render() for entry in self.log)
