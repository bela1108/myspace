# Placeholder values only; this file contains no real credentials.
import hmac


def direct_short_circuit(secret, candidate, ready):
    # B616: equality hidden inside a short-circuit expression.
    if ready and secret == candidate:
        return True
    return False


def local_unpacking(secret, candidate, ready):
    # B616: both names inherit the source through tuple unpacking.
    left, right = secret, candidate
    if ready and left == right:
        return True
    return False


def chained_comparison(secret, candidate, limit):
    # B616: the equality pair in a chained comparison is checked.
    if secret == candidate == "placeholder-value":
        return True
    return False


def branch_order(secret, candidate, ready):
    # Reversing these two branches must not change the Compare nodes seen.
    if ready:
        if secret == candidate:
            return True
    else:
        if candidate == secret:
            return False
    return False


def constant_time_helper(secret, candidate):
    # Safe: the configured comparison helper owns the actual comparison.
    return hmac.compare_digest(secret, candidate)
