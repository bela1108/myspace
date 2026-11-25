"""Disclosure-safe datastore views and observable differentials."""

from stix2.disclosure import *  # noqa: F401,F403
import stix2.disclosure as _core


def query_page(store, query=None, identity=None, **kwargs):
    """Query a datastore and return a stable, count-controlled output."""
    if query is None:
        try:
            objects = store.query()
        except TypeError:
            objects = store.query([])
    else:
        objects = store.query(query)
    return _core.stable_equivalent_output(objects, identity=identity, **kwargs)


def observable_difference(*args, **kwargs):
    """Compare datastores/pages without exposing hidden-object existence."""
    query = kwargs.pop("query", None)
    left_query = kwargs.pop("left_query", query)
    right_query = kwargs.pop("right_query", query)

    args = list(args)
    if len(args) >= 2 and _looks_like_store(args[0]) and _looks_like_store(args[1]):
        left = _run_query(args.pop(0), left_query)
        right = _run_query(args.pop(0), right_query)
        args = [left, right] + args
    elif args and _looks_like_store(args[0]):
        args[0] = _run_query(args[0], left_query)

    return _core.observable_difference(*args, **kwargs)


def _looks_like_store(value):
    return value is not None and (
        hasattr(value, "query") and callable(getattr(value, "query"))
    )


def _run_query(store, query):
    if query is None:
        try:
            return store.query()
        except TypeError:
            return store.query([])
    return store.query(query)


observable_diff = observable_difference
external_observable_difference = observable_difference
externally_observable_difference = observable_difference

__all__ = getattr(_core, "__all__", []) + [
    "query_page", "observable_difference", "observable_diff",
    "external_observable_difference", "externally_observable_difference",
]
