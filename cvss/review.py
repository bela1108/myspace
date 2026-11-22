"""
Review backend built on top of the CVSS library.

Accepts a CVSS vector together with per-metric provenance (source trust
levels) and decides, driven by an explicit policy, whether the record can be
published directly and which evidence is still missing. Inherited
environmental metrics can be traced back to the default values that apply to
them. CVSS 3.x and CVSS 4.0 metric sets are reported with their own
version-specific fields.
"""

from __future__ import unicode_literals

from .constants3 import ENVIRONMENTAL_METRICS as ENVIRONMENTAL_METRICS_3
from .constants3 import METRICS_ABBREVIATIONS as NAMES_3
from .constants3 import METRICS_VALUE_NAMES as VALUE_NAMES_3
from .constants3 import TEMPORAL_METRICS as TEMPORAL_METRICS_3
from .constants4 import METRICS_ABBREVIATIONS as NAMES_4
from .constants4 import METRICS_VALUE_NAMES as VALUE_NAMES_4
from .cvss3 import CVSS3
from .cvss4 import CVSS4

try:
    from collections import OrderedDict
except ImportError:
    # noinspection PyUnresolvedReferences
    from ordereddict import OrderedDict

# Source trust levels, ordered from least to most trustworthy. The position
# in this tuple defines the ranking used by ReviewPolicy.
TRUST_UNVERIFIED = "unverified"
TRUST_UPSTREAM_DEFAULT = "upstream_default"
TRUST_CONFIRMED = "confirmed"
TRUST_LEVELS = (TRUST_UNVERIFIED, TRUST_UPSTREAM_DEFAULT, TRUST_CONFIRMED)

# Metric groups per CVSS version. CVSS 3.x splits optional metrics into
# temporal and environmental groups, CVSS 4.0 uses threat, environmental and
# supplemental groups instead.
GROUPS_3 = OrderedDict(
    [
        ("base", ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]),
        ("temporal", list(TEMPORAL_METRICS_3)),
        ("environmental", list(ENVIRONMENTAL_METRICS_3)),
    ]
)

GROUPS_4 = OrderedDict(
    [
        ("base", ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]),
        ("threat", ["E"]),
        (
            "environmental",
            [
                "CR",
                "IR",
                "AR",
                "MAV",
                "MAC",
                "MAT",
                "MPR",
                "MUI",
                "MVC",
                "MVI",
                "MVA",
                "MSC",
                "MSI",
                "MSA",
            ],
        ),
        ("supplemental", ["S", "AU", "R", "V", "RE", "U"]),
    ]
)

# Environmental metrics whose value defaults to the matching base metric
# when not defined ("X" or missing), per CVSS version.
MODIFIED_METRICS_3 = ["MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]
MODIFIED_METRICS_4 = [
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
]


def _trust_rank(level):
    if level not in TRUST_LEVELS:
        raise ValueError(
            'Unknown trust level "{0}", expected one of {1}'.format(level, ", ".join(TRUST_LEVELS))
        )
    return TRUST_LEVELS.index(level)


class ReviewPolicy(object):
    """
    Explicit configuration deciding whether a reviewed record can be
    published directly.

    Args:
        required_trust (dict): mapping of metric group name to the minimum
                               trust level required for direct publication,
                               e.g. {"base": "confirmed", "environmental":
                               "upstream_default"}. Groups not listed fall
                               back to ``fallback_required_trust``.
        fallback_required_trust (str): trust level required for groups not
                                       listed in ``required_trust``.
        default_trust (str): trust level assumed for metrics that carry no
                             provenance information.
    """

    def __init__(
        self,
        required_trust=None,
        fallback_required_trust=TRUST_CONFIRMED,
        default_trust=TRUST_UNVERIFIED,
    ):
        self.required_trust = dict(required_trust or {})
        self.fallback_required_trust = fallback_required_trust
        self.default_trust = default_trust
        for level in list(self.required_trust.values()) + [
            fallback_required_trust,
            default_trust,
        ]:
            _trust_rank(level)

    def required_for(self, group):
        """
        Minimum trust level required for direct publication of the given
        metric group.
        """
        return self.required_trust.get(group, self.fallback_required_trust)


class MetricEvidence(object):
    """
    Review state of a single metric.

    Attributes:
        abbreviation (str): metric abbreviation, e.g. "MAV"
        name (str): full version-specific metric name
        group (str): metric group, e.g. "base" or "environmental"
        value (str): value as found in the vector, "X" when not defined
        value_name (str): textual description of ``value``
        explicit (bool): True when the metric is set to a defined value in
                         the vector
        trust (str): source trust level attached to this metric
        effective (str): value actually used for scoring
        default_note (str): for inherited metrics, which default applies
        reviewed (bool): True when the policy is enforced on this metric;
                         inherited metrics without attached provenance are
                         informational only
        required_trust (str): minimum trust level required by the policy
        sufficient (bool): True when ``trust`` satisfies ``required_trust``
    """

    def __init__(
        self,
        abbreviation,
        name,
        group,
        value,
        value_name,
        explicit,
        trust,
        effective,
        default_note,
        reviewed,
        required_trust,
    ):
        self.abbreviation = abbreviation
        self.name = name
        self.group = group
        self.value = value
        self.value_name = value_name
        self.explicit = explicit
        self.trust = trust
        self.effective = effective
        self.default_note = default_note
        self.reviewed = reviewed
        self.required_trust = required_trust
        self.sufficient = not reviewed or _trust_rank(trust) >= _trust_rank(required_trust)

    def __repr__(self):
        return "MetricEvidence({0}={1}, group={2}, trust={3}, required={4})".format(
            self.abbreviation, self.value, self.group, self.trust, self.required_trust
        )


class ReviewReport(object):
    """
    Outcome of reviewing one vector against a policy.

    Attributes:
        vector (str): the reviewed vector
        cvss (CVSS3 or CVSS4): the parsed and scored object
        version (str): "3.0", "3.1" or "4.0"
        policy (ReviewPolicy): the policy the review ran against
        metrics (list of MetricEvidence): reviewed metrics in canonical order
        missing_evidence (list of MetricEvidence): metrics below the trust
                                                   level required by the policy
        publishable (bool): True when no evidence is missing
    """

    def __init__(self, vector, cvss, version, policy, metrics):
        self.vector = vector
        self.cvss = cvss
        self.version = version
        self.policy = policy
        self.metrics = metrics
        self.missing_evidence = [m for m in metrics if not m.sufficient]
        self.publishable = not self.missing_evidence

    @property
    def decision(self):
        return "publish" if self.publishable else "hold"

    def scores(self):
        return self.cvss.scores()

    def severities(self):
        return self.cvss.severities()

    def explain(self):
        """
        Renders a human-readable review sheet. Metric groups and field names
        are version-specific: CVSS 3.x sheets show temporal metrics such as
        Exploit Code Maturity, CVSS 4.0 sheets show threat metrics such as
        Exploit Maturity and supplemental metrics when present.
        """
        lines = []
        lines.append("CVSS {0} review: {1}".format(self.version, self.vector))
        scores = ", ".join(
            "{0} ({1})".format(score, severity)
            for score, severity in zip(self.scores(), self.severities())
        )
        lines.append("Scores: {0}".format(scores))
        if self.publishable:
            lines.append("Decision: PUBLISH - all metrics satisfy the review policy")
        else:
            lines.append(
                "Decision: HOLD - evidence missing for {0}".format(
                    ", ".join(m.abbreviation for m in self.missing_evidence)
                )
            )
        lines.append("Metrics:")
        for metric in self.metrics:
            origin = "explicit" if metric.explicit else "inherited"
            if not metric.reviewed:
                origin += ", informational"
            line = "  [{0}] {1} {2} = {3} ({4}) - {5}, trust: {6}".format(
                metric.group,
                metric.abbreviation,
                metric.name,
                metric.value,
                metric.value_name,
                origin,
                metric.trust,
            )
            if metric.default_note:
                line += "; default: {0}".format(metric.default_note)
            lines.append(line)
        if self.missing_evidence:
            lines.append("Missing evidence:")
            for metric in self.missing_evidence:
                lines.append(
                    "  - {0} ({1}, {2} group): source trust is "
                    '"{3}", policy requires "{4}" - publication held until '
                    "this metric is confirmed".format(
                        metric.abbreviation,
                        metric.name,
                        metric.group,
                        metric.trust,
                        metric.required_trust,
                    )
                )
        return "\n".join(lines)


def _build_metrics(groups, names, value_names, explicit_metrics, provenance, policy):
    """
    Builds MetricEvidence objects for every reviewed metric.
    """
    metrics = []
    for group, abbreviations in groups.items():
        for abbreviation in abbreviations:
            raw_value = explicit_metrics.get(abbreviation, "X")
            explicit = abbreviation in explicit_metrics and raw_value != "X"
            trust = provenance.get(abbreviation, policy.default_trust)
            _trust_rank(trust)
            # Inherited metrics are only enforced when provenance was
            # explicitly attached to them, otherwise they are informational
            # and only report which default applies.
            reviewed = explicit or abbreviation in provenance
            metrics.append(
                MetricEvidence(
                    abbreviation=abbreviation,
                    name=names[abbreviation],
                    group=group,
                    value=raw_value if explicit else "X",
                    value_name=value_names[abbreviation][raw_value if explicit else "X"],
                    explicit=explicit,
                    trust=trust,
                    effective=None,  # filled in by the version-specific code
                    default_note=None,
                    reviewed=reviewed,
                    required_trust=policy.required_for(group),
                )
            )
    return metrics


def _review_cvss3(vector, provenance, policy):
    cvss = CVSS3(vector)
    metrics = _build_metrics(
        GROUPS_3, NAMES_3, VALUE_NAMES_3, cvss.original_metrics, provenance, policy
    )
    for metric in metrics:
        abbreviation = metric.abbreviation
        if metric.explicit:
            metric.effective = metric.value
        elif abbreviation in MODIFIED_METRICS_3:
            base = abbreviation[1:]
            base_value = cvss.metrics[base]
            metric.effective = base_value
            metric.default_note = "inherits {0} = {1} ({2})".format(
                base, base_value, VALUE_NAMES_3[base][base_value]
            )
        else:
            # Temporal metrics and CR/IR/AR score "X" (Not Defined) as 1.0.
            metric.effective = "X"
            metric.default_note = "not defined - scored with weight 1.0"
    return ReviewReport(vector, cvss, "3.{0}".format(cvss.minor_version), policy, metrics)


def _review_cvss4(vector, provenance, policy):
    cvss = CVSS4(vector)
    metrics = _build_metrics(
        GROUPS_4, NAMES_4, VALUE_NAMES_4, cvss.original_metrics, provenance, policy
    )
    for metric in metrics:
        abbreviation = metric.abbreviation
        if metric.explicit:
            metric.effective = metric.value
        elif abbreviation in MODIFIED_METRICS_4:
            base = abbreviation[1:]
            base_value = cvss.metrics[base]
            metric.effective = base_value
            metric.default_note = "inherits {0} = {1} ({2})".format(
                base, base_value, VALUE_NAMES_4[base][base_value]
            )
        elif abbreviation == "E":
            metric.effective = "A"
            metric.default_note = "not defined - scored as A (Attacked)"
        elif abbreviation in ("CR", "IR", "AR"):
            metric.effective = "H"
            metric.default_note = "not defined - scored as H (High)"
        else:
            # Supplemental metrics carry no scoring weight.
            metric.effective = "X"
            metric.default_note = "not defined - no scoring impact"
    return ReviewReport(vector, cvss, "4.0", policy, metrics)


def review_vector(vector, provenance=None, policy=None):
    """
    Reviews a CVSS vector against per-metric provenance and a policy.

    Args:
        vector (str): CVSS 3.x or CVSS 4.0 vector
        provenance (dict): mapping of metric abbreviation to source trust
                           level, e.g. {"AV": "confirmed", "AC":
                           "upstream_default"}. Metrics not listed get the
                           policy default trust level.
        policy (ReviewPolicy): explicit review configuration; when omitted,
                               every metric group requires "confirmed" trust
                               and unattributed metrics count as "unverified".

    Returns:
        ReviewReport: review outcome including the publish/hold decision,
                      missing evidence and inherited default lookup
    """
    provenance = dict(provenance or {})
    policy = policy or ReviewPolicy()
    if vector.startswith("CVSS:3."):
        return _review_cvss3(vector, provenance, policy)
    elif vector.startswith("CVSS:4.0/"):
        return _review_cvss4(vector, provenance, policy)
    else:
        raise ValueError(
            'Cannot review vector "{0}", expected a CVSS 3.x or CVSS 4.0 vector'.format(vector)
        )
