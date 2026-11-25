# SPDX-License-Identifier: Apache-2.0
"""Gateway fixture: an explicit rejection backs up the assertion."""

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
    if not validate_request(request):
        return "rejected"
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
