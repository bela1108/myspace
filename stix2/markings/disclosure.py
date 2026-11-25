"""Fixed-length marking summaries and observable differentials."""

from stix2.disclosure import *  # noqa: F401,F403
import stix2.disclosure as _core


def marking_summary(graph=None, identity=None, markings=None, **kwargs):
    """Return a stable marking summary for an object, graph or ref list."""
    if markings is None and _is_marking_ref_list(graph):
        markings = graph
        graph = None
    return _core.summarize_markings(
        graph=graph,
        identity=identity,
        markings=markings,
        **kwargs,
    )


def stable_marking_output(graph=None, identity=None, **kwargs):
    summary = marking_summary(graph, identity, **kwargs)
    canonical = _core.canonical_json(summary)
    return _core.StableOutput(canonical, summary)


def observable_difference(*args, **kwargs):
    """Compare marking summaries while equalizing externally visible lengths."""
    left = kwargs.pop("left", None)
    right = kwargs.pop("right", None)
    left_identity = kwargs.pop("left_identity", kwargs.pop("identity_a", None))
    right_identity = kwargs.pop("right_identity", kwargs.pop("identity_b", None))
    identity = kwargs.pop("identity", None)

    values = [value for value in (left,) + tuple(args) + (right,) if value is not None]
    subjects = []
    identities = []
    for value in values:
        if _core._is_identity_like(value) and not _is_marking_ref_list(value):
            identities.append(value)
        else:
            subjects.append(value)

    if len(subjects) >= 2:
        left_subject, right_subject = subjects[0], subjects[1]
    elif len(subjects) == 1:
        left_subject = right_subject = subjects[0]
    else:
        raise TypeError("marking observable_difference requires two marking subjects")

    if left_identity is not None:
        lid = left_identity
    elif identities:
        lid = identities[0]
    else:
        lid = identity
    if right_identity is not None:
        rid = right_identity
    elif len(identities) >= 2:
        rid = identities[1]
    elif identities:
        rid = identities[0]
    else:
        rid = identity

    left_summary = _as_summary(left_subject, lid, **kwargs)
    right_summary = _as_summary(right_subject, rid, **kwargs)
    return _core.compare_observations(left_summary, right_summary, **kwargs)


def _is_marking_ref_list(value):
    return (
        isinstance(value, (list, tuple, set, frozenset))
        and len(value) > 0
        and all(isinstance(item, str) for item in value)
    )


def _as_summary(value, identity, **kwargs):
    if isinstance(value, _core.Observation):
        return value
    if isinstance(value, _core.StableOutput):
        return value
    if isinstance(value, dict) and value.get("kind") == "stix2.disclosure.marking-summary/v1":
        return value
    if _is_marking_ref_list(value):
        return marking_summary(markings=value, identity=identity, **kwargs)
    return marking_summary(value, identity=identity, **kwargs)


observable_diff = observable_difference
external_observable_difference = observable_difference
externally_observable_difference = observable_difference
stable_summary = stable_marking_output
fixed_length_summary = _core.fixed_summary
summary_digest = _core.fixed_digest

__all__ = getattr(_core, "__all__", []) + [
    "marking_summary", "stable_marking_output", "observable_difference",
    "observable_diff", "external_observable_difference",
    "externally_observable_difference", "stable_summary",
    "fixed_length_summary", "summary_digest",
]
