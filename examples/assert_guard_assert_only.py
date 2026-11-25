# SPDX-License-Identifier: Apache-2.0
"""Gateway fixture: the assertion is the only validation check."""

import json


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


def handle(request):
    assert validate_request(request), "invalid request"
    write_audit(request)
    return "accepted"


def main():
    request = Request("../etc/passwd", "guest")
    try:
        outcome = handle(request)
    except AssertionError:
        outcome = "assertion-rejected"
    print(json.dumps({"outcome": outcome, "reached": bool(REACHED)}))


if __name__ == "__main__":
    main()
