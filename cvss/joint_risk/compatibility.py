"""
Compatibility grid for a joint risk statement.

Two response teams owe their customer one unified risk statement, yet each
team keeps a separately approved internal stop-ship threshold. Given the
limited CVSS vector domain both teams agreed to discuss, this module
recomputes every score with the real CVSS implementation shipped in this
library, compares the two approved policies on each cell, and keeps the
internally approved responsibility labels strictly out of the public view.
"""

from __future__ import unicode_literals

from collections import OrderedDict

from .. import CVSS3, CVSS4
from ..exceptions import CVSSError


class JointRiskError(Exception):
    """General error for joint risk statement building."""


class VectorDomainError(JointRiskError):
    """Raised when the mutually agreed vector domain is empty or invalid."""


class PolicyValidationError(JointRiskError):
    """Raised when an approved stop-ship policy is not well formed."""


def compute_base_score(vector):
    """
    Recomputes the CVSS base score for a vector using the real implementation.

    Args:
        vector (str): a CVSS v3.x or v4.0 vector string

    Returns:
        float: the recomputed base score, rounded by the CVSS specification

    Raises:
        VectorDomainError: if the vector is malformed or not a supported version
    """
    try:
        if vector.startswith("CVSS:4."):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3."):
            return float(CVSS3(vector).base_score)
    except CVSSError as error:
        raise VectorDomainError(
            'Vector "{0}" cannot be scored: {1}'.format(vector, error)
        )
    raise VectorDomainError(
        'Vector "{0}" is not a supported CVSS v3.x or v4.0 vector'.format(vector)
    )


class StopShipPolicy(object):
    """
    A stop-ship threshold approved by exactly one response team.

    A team stops shipping at or above its approved threshold; below it the
    team keeps shipping. The responsibility label is internal evidence and
    must never appear in the customer-facing statement.

    Args:
        team_id (str): stable identifier of the approving team
        threshold (float): approved base-score stop-ship threshold, in 0..10
        responsibility_label (str): internal, non-public liability tag
    """

    def __init__(self, team_id, threshold, responsibility_label):
        team_id = str(team_id).strip()
        if not team_id:
            raise PolicyValidationError("Team identifier must not be empty")
        if not isinstance(responsibility_label, str) or not responsibility_label.strip():
            raise PolicyValidationError(
                'Responsibility label for team "{0}" must not be empty'.format(team_id)
            )
        try:
            threshold = float(threshold)
        except (TypeError, ValueError):
            raise PolicyValidationError(
                'Threshold for team "{0}" must be numeric'.format(team_id)
            )
        if not 0.0 <= threshold <= 10.0:
            raise PolicyValidationError(
                'Threshold for team "{0}" must be between 0.0 and 10.0'.format(team_id)
            )
        self.team_id = team_id
        self.threshold = threshold
        self.responsibility_label = responsibility_label.strip()

    def decide(self, score):
        """
        Applies the approved threshold to a recomputed score.

        Returns:
            str: ``stop_ship`` when the score is at or above the threshold,
            ``keep_shipping`` otherwise
        """
        if score >= self.threshold:
            return "stop_ship"
        return "keep_shipping"

    def __eq__(self, other):
        if not isinstance(other, StopShipPolicy):
            return NotImplemented
        return (
            self.team_id == other.team_id
            and self.threshold == other.threshold
            and self.responsibility_label == other.responsibility_label
        )

    def __repr__(self):
        return "StopShipPolicy(team_id={0!r}, threshold={1})".format(
            self.team_id, self.threshold
        )


class VectorCell(object):
    """
    One cell of the compatibility grid.

    The score is always recomputed from the vector; it is never taken from a
    policy or an external claim.
    """

    def __init__(self, vector, score, decisions, labels):
        self.vector = vector
        self.score = score
        # OrderedDict preserving the policy load order: team_id -> action
        self.decisions = OrderedDict(decisions)
        # Internal responsibility labels, team_id -> label (never public)
        self.labels = OrderedDict(labels)
        distinct = set(decisions.values())
        self.joint = len(distinct) == 1
        self.joint_action = next(iter(distinct)) if self.joint else None

    @property
    def status(self):
        """``joint_commitment`` or ``no_consensus``."""
        return "joint_commitment" if self.joint else "no_consensus"

    def public_view(self):
        """
        Customer-safe view of the cell.

        Team identifiers, per-team actions and responsibility labels are
        withheld. On a disagreement the cell only states that joint evidence
        is missing, without attributing a position to either team.
        """
        view = OrderedDict()
        view["vector"] = self.vector
        view["cvss_base_score"] = self.score
        view["status"] = self.status
        if self.joint:
            view["joint_action"] = self.joint_action
        else:
            view["joint_action"] = None
            view["note"] = "No joint evidence: the approved policies diverge"
        return view

    def internal_view(self):
        """Full cell view, including each team's individually valid scope."""
        view = OrderedDict()
        view["vector"] = self.vector
        view["cvss_base_score"] = self.score
        view["status"] = self.status
        view["team_decisions"] = OrderedDict(self.decisions)
        view["responsibility_labels"] = OrderedDict(self.labels)
        if self.joint:
            view["joint_action"] = self.joint_action
        return view


class JointCompatibility(object):
    """
    Compatibility grid over the limited vector domain both teams agreed on.

    Args:
        policy_a (StopShipPolicy): first team's approved policy
        policy_b (StopShipPolicy): second team's approved policy
        vector_domain (list[str]): finite CVSS vectors both teams agreed to
            discuss; vectors outside this domain are deliberately excluded

    Raises:
        PolicyValidationError: if a policy is invalid or both share an id
        VectorDomainError: if the domain is empty, duplicated, or unscorable
    """

    def __init__(self, policy_a, policy_b, vector_domain):
        if not isinstance(policy_a, StopShipPolicy) or not isinstance(
            policy_b, StopShipPolicy
        ):
            raise PolicyValidationError("Both policies must be StopShipPolicy instances")
        if policy_a.team_id == policy_b.team_id:
            raise PolicyValidationError(
                'Both policies claim team id "{0}"'.format(policy_a.team_id)
            )
        if not vector_domain:
            raise VectorDomainError("The agreed vector domain must not be empty")
        seen = set()
        for vector in vector_domain:
            if not isinstance(vector, str) or not vector.strip():
                raise VectorDomainError("Vector domain entries must be non-empty strings")
            if vector in seen:
                raise VectorDomainError(
                    'Duplicate vector in the agreed domain: "{0}"'.format(vector)
                )
            seen.add(vector)

        self.policies = OrderedDict(
            [(policy_a.team_id, policy_a), (policy_b.team_id, policy_b)]
        )
        self.vector_domain = list(vector_domain)
        self.cells = OrderedDict()
        for vector in self.vector_domain:
            score = compute_base_score(vector)
            decisions = OrderedDict()
            labels = OrderedDict()
            for team_id, policy in self.policies.items():
                decisions[team_id] = policy.decide(score)
                labels[team_id] = policy.responsibility_label
            self.cells[vector] = VectorCell(vector, score, decisions, labels)

    # -- grid summaries ---------------------------------------------------

    def joint_commitments(self):
        """Cells on which both approved policies take the same action."""
        return [cell for cell in self.cells.values() if cell.joint]

    def disagreements(self):
        """Cells where the two approved policies cannot form a joint claim."""
        return [cell for cell in self.cells.values() if not cell.joint]

    def team_scope(self, team_id):
        """
        Individually valid scope of one team across the whole agreed domain.

        Returns:
            OrderedDict: vector -> action, retained even when no consensus
        """
        if team_id not in self.policies:
            raise JointRiskError('Unknown team id "{0}"'.format(team_id))
        return OrderedDict(
            (vector, cell.decisions[team_id]) for vector, cell in self.cells.items()
        )

    # -- statement rendering ---------------------------------------------

    def customer_statement(self):
        """
        Unified, customer-safe risk statement.

        Contains only recomputed scores and joint commitments. Disagreements
        are surfaced as missing joint evidence without team attribution or
        responsibility labels.
        """
        statement = OrderedDict()
        statement["agreed_vector_domain"] = list(self.vector_domain)
        statement["cells"] = [cell.public_view() for cell in self.cells.values()]
        statement["joint_commitment_count"] = len(self.joint_commitments())
        statement["missing_joint_evidence_count"] = len(self.disagreements())
        return statement

    def internal_report(self):
        """Full internal report retaining each team's valid scope and labels."""
        report = OrderedDict()
        report["policies"] = OrderedDict(
            (team_id, OrderedDict([("threshold", policy.threshold)]))
            for team_id, policy in self.policies.items()
        )
        report["cells"] = [cell.internal_view() for cell in self.cells.values()]
        report["team_scopes"] = OrderedDict(
            (team_id, self.team_scope(team_id)) for team_id in self.policies
        )
        return report

    # -- order-independence audit ----------------------------------------

    def signature(self):
        """
        Order-independent content signature of the grid.

        Builds tuples of vector, recomputed score, and the action set paired
        with the policy threshold that produced it, so swapping policy load
        order cannot change the signature.
        """
        signature = []
        for cell in self.cells.values():
            threshold_actions = frozenset(
                (self.policies[team_id].threshold, action)
                for team_id, action in cell.decisions.items()
            )
            signature.append((cell.vector, cell.score, cell.status, threshold_actions))
        return tuple(signature)


def find_recomputable_disagreement(compatibility):
    """
    Finds a disagreement an auditor can recompute from the small vector domain.

    Returns:
        OrderedDict or None: evidence containing the vector, its recomputed
        score, both thresholds, and each team's individually valid action;
        ``None`` when every cell is a joint commitment
    """
    for cell in compatibility.disagreements():
        evidence = OrderedDict()
        evidence["vector"] = cell.vector
        evidence["recomputed_base_score"] = cell.score
        evidence["thresholds"] = OrderedDict(
            (team_id, policy.threshold)
            for team_id, policy in compatibility.policies.items()
        )
        evidence["team_actions"] = OrderedDict(cell.decisions)
        evidence["audit_note"] = (
            "Recompute the base score from the vector with this library and "
            "re-apply each approved threshold to reproduce both actions"
        )
        return evidence
    return None


def verify_reverse_loading(policy_a, policy_b, vector_domain):
    """
    Loads both policy orders and confirms the agreed scope is not widened.

    The reverse-order grid must keep the same vectors, recomputed scores,
    per-cell status, and threshold/action pairs. Responsibility labels are
    intentionally excluded from this comparison because they are internal.

    Returns:
        OrderedDict: audit result with both grid signatures and equality flag

    Raises:
        JointRiskError: if reverse loading changes any cell or the scope
    """
    forward = JointCompatibility(policy_a, policy_b, vector_domain)
    reverse = JointCompatibility(policy_b, policy_a, vector_domain)

    forward_signature = forward.signature()
    reverse_signature = reverse.signature()
    order_independent = forward_signature == reverse_signature

    forward_vectors = frozenset(forward.vector_domain)
    reverse_vectors = frozenset(reverse.vector_domain)
    scope_unchanged = (
        forward_vectors == reverse_vectors
        and len(forward.cells) == len(reverse.cells)
        and len(forward.joint_commitments()) == len(reverse.joint_commitments())
        and len(forward.disagreements()) == len(reverse.disagreements())
    )

    result = OrderedDict()
    result["forward_signature"] = forward_signature
    result["reverse_signature"] = reverse_signature
    result["order_independent"] = order_independent
    result["scope_unchanged"] = scope_unchanged

    if not (order_independent and scope_unchanged):
        raise JointRiskError(
            "Reverse loading widened or altered the jointly agreed scope"
        )
    return result
