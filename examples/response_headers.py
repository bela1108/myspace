import functools


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def inner_headers(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        response = fn(*args, **kwargs)
        response["headers"] = SECURITY_HEADERS
        return response

    return wrapper


def audit_outer(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        response = fn(*args, **kwargs)
        if kwargs.get("as_json"):
            return response
        return {
            "status": 200,
            "body": response.get("body", []),
        }

    return wrapper


@audit_outer
@inner_headers
def employee_report(employee_id):
    if employee_id is None:
        return {"status": 400, "body": "missing employee id"}
    return {"status": 200, "body": [employee_id]}
