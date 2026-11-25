"""
Offline consistency checks for rankings based on reviewed CVSS vectors.

The review only returns a verdict. Computed scores and reviewed vectors are kept local to the
check and are not included in the result.
"""

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSError

CONSISTENT = "consistent"
POSSIBLE_TIE = "possible tie"
INSUFFICIENT_EVIDENCE = "insufficient evidence"


def _normalise_ranking(ranking):
    if not isinstance(ranking, (list, tuple)):
        return None

    normalised = []
    seen = set()
    for group in ranking:
        if isinstance(group, str) or not isinstance(group, (list, tuple, set, frozenset)):
            group = (group,)
        group = tuple(group)
        if not group:
            return None
        for risk_id in group:
            if not isinstance(risk_id, str) or not risk_id or risk_id in seen:
                return None
            seen.add(risk_id)
        normalised.append(group)
    return normalised


def _normalise_tie_rules(tie_rules):
    if not isinstance(tie_rules, dict):
        return None

    normalised = {}
    for version, rule in tie_rules.items():
        if not isinstance(version, str) or not isinstance(rule, dict):
            return None
        allow_ties = rule.get("allow_ties")
        score_index = rule.get("score_index", 0)
        tolerance = rule.get("tolerance", 0.0)
        if not isinstance(allow_ties, bool):
            return None
        if not isinstance(score_index, int) or score_index < 0:
            return None
        if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)) or tolerance < 0:
            return None
        normalised[version] = {
            "allow_ties": allow_ties,
            "score_index": score_index,
            "tolerance": float(tolerance),
        }
    return normalised


def _cvss_for_vector(vector):
    if not isinstance(vector, str):
        return None
    try:
        if vector.startswith("CVSS:4."):
            return CVSS4(vector)
        if vector.startswith("CVSS:3."):
            return CVSS3(vector)
        return CVSS2(vector)
    except (CVSSError, KeyError, ValueError):
        return None


def _vector_version(cvss):
    if isinstance(cvss, CVSS4):
        return "4.0"
    if isinstance(cvss, CVSS3):
        prefix = cvss.clean_vector(output_prefix=False)
        return getattr(cvss, "version", None) or ("3.1" if prefix.startswith("CVSS:3.1") else "3.0")
    return "2.0"


def _score_for(cvss, rule):
    scores = cvss.scores()
    if rule["score_index"] >= len(scores):
        return None
    score = scores[rule["score_index"]]
    if score is None:
        return None
    return float(score)


def _reviewed_scores(reviewed_vectors, tie_rules):
    scores = {}
    for risk_id, vector in reviewed_vectors.items():
        cvss = _cvss_for_vector(vector)
        if cvss is None:
            return None
        version = _vector_version(cvss)
        rule = tie_rules.get(version)
        if rule is None:
            return None
        score = _score_for(cvss, rule)
        if score is None:
            return None
        scores[risk_id] = score
    return scores


def _positions(ranking):
    return {
        risk_id: position
        for position, group in enumerate(ranking)
        for risk_id in group
    }


def _check_ranking(ranking, scores, tie_rules, reviewed_vectors):
    position = _positions(ranking)
    for earlier_group, later_group in zip(ranking, ranking[1:]):
        for earlier_id in earlier_group:
            for later_id in later_group:
                earlier_score = scores[earlier_id]
                later_score = scores[later_id]
                if earlier_score < later_score:
                    return INSUFFICIENT_EVIDENCE
                if abs(earlier_score - later_score) <= max(
                    tie_rules[_vector_version(_cvss_for_vector(reviewed_vectors[earlier_id]))][
                        "tolerance"
                    ],
                    tie_rules[_vector_version(_cvss_for_vector(reviewed_vectors[later_id]))][
                        "tolerance"
                    ],
                ):
                    return POSSIBLE_TIE

    for group in ranking:
        if len(group) < 2:
            continue
        first_id = group[0]
        first_version = _vector_version(_cvss_for_vector(reviewed_vectors[first_id]))
        first_rule = tie_rules[first_version]
        for risk_id in group[1:]:
            version = _vector_version(_cvss_for_vector(reviewed_vectors[risk_id]))
            if not first_rule["allow_ties"] or not tie_rules[version]["allow_ties"]:
                return INSUFFICIENT_EVIDENCE
            if abs(scores[first_id] - scores[risk_id]) > max(
                first_rule["tolerance"],
                tie_rules[version]["tolerance"],
            ):
                return INSUFFICIENT_EVIDENCE

    for earlier_id, earlier_score in scores.items():
        for later_id, later_score in scores.items():
            if position[earlier_id] >= position[later_id]:
                continue
            earlier_version = _vector_version(_cvss_for_vector(reviewed_vectors[earlier_id]))
            later_version = _vector_version(_cvss_for_vector(reviewed_vectors[later_id]))
            tolerance = max(
                tie_rules[earlier_version]["tolerance"],
                tie_rules[later_version]["tolerance"],
            )
            if abs(earlier_score - later_score) <= tolerance and (
                not tie_rules[earlier_version]["allow_ties"]
                or not tie_rules[later_version]["allow_ties"]
            ):
                return INSUFFICIENT_EVIDENCE
    return CONSISTENT


def check_ranking_consistency(disclosed_rankings, reviewed_vectors, tie_rules):
    """
    Checks whether disclosed rankings are supported by reviewed CVSS vectors.

    Args:
        disclosed_rankings (dict): Role name to ranking. A ranking is an ordered sequence; each
            item may be one risk ID or a sequence of explicitly tied risk IDs.
        reviewed_vectors (dict): Risk ID to a reviewed CVSS v2, v3, or v4 vector.
        tie_rules (dict): CVSS version to a rule with ``allow_ties``, an optional ``score_index``,
            and an optional numeric ``tolerance``.

    Returns:
        (str): One of ``consistent``, ``possible tie``, or ``insufficient evidence``.
    """
    if not isinstance(disclosed_rankings, dict) or not disclosed_rankings:
        return INSUFFICIENT_EVIDENCE
    if not isinstance(reviewed_vectors, dict) or not reviewed_vectors:
        return INSUFFICIENT_EVIDENCE

    normalised_tie_rules = _normalise_tie_rules(tie_rules)
    if normalised_tie_rules is None:
        return INSUFFICIENT_EVIDENCE

    normalised_rankings = {}
    expected_ids = set(reviewed_vectors)
    for role, ranking in disclosed_rankings.items():
        if not isinstance(role, str) or not role:
            return INSUFFICIENT_EVIDENCE
        normalised = _normalise_ranking(ranking)
        if normalised is None or set(_positions(normalised)) != expected_ids:
            return INSUFFICIENT_EVIDENCE
        normalised_rankings[role] = normalised

    scores = _reviewed_scores(reviewed_vectors, normalised_tie_rules)
    if scores is None:
        return INSUFFICIENT_EVIDENCE

    verdicts = {
        _check_ranking(ranking, scores, normalised_tie_rules, reviewed_vectors)
        for ranking in normalised_rankings.values()
    }
    if INSUFFICIENT_EVIDENCE in verdicts:
        return INSUFFICIENT_EVIDENCE
    if POSSIBLE_TIE in verdicts:
        return POSSIBLE_TIE
    return CONSISTENT
