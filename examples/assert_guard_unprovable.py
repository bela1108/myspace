# SPDX-License-Identifier: Apache-2.0
"""Gateway fixture: rejection happens in a conditional helper path."""

import json
import sys


class Request:
    def __init__(self, path, role, enforce=False):
        self.path = path
        self.role = role
        self.enforce = enforce


REACHED = []


def validate_request(request):
    return request.role == "admin" and ".." not in request.path


def write_audit(request):
    REACHED.append(request.path)


def _reject_if_invalid(request):
    if not validate_request(request):
        raise PermissionError("invalid request")


def handle(request):
    assert validate_request(request), "invalid request"
    if request.enforce:
        _reject_if_invalid(request)
    write_audit(request)
    return "accepted"


def main():
    enforce = "--enforce" in sys.argv[1:]
    request = Request("../etc/passwd", "guest", enforce=enforce)
    try:
        outcome = handle(request)
    except AssertionError:
        outcome = "assertion-rejected"
    except PermissionError:
        outcome = "helper-rejected"
    print(json.dumps({"outcome": outcome, "reached": bool(REACHED)}))


if __name__ == "__main__":
    main()
