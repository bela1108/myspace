import textwrap
import unittest

from bandit.plugins import response_headers


REQUIRED = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
]


def analyze(source, wrappers=None, required=None):
    config = {
        "required_headers": REQUIRED if required is None else required,
        "wrappers": wrappers or {},
    }
    source = textwrap.dedent(source).lstrip("\n")
    return source, response_headers.analyze_source(source, config)


def line_of(source, marker):
    for number, line in enumerate(source.splitlines(), 1):
        if marker in line:
            return number
    raise AssertionError(f"marker not found: {marker}")


class ResponseHeaderContractTests(unittest.TestCase):
    def test_two_wrapper_layers_report_only_new_response_exit(self):
        source, findings = analyze(
            """
            import functools

            FULL = {
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }

            def inner_headers(fn):
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    response = fn(*args, **kwargs)
                    response["headers"] = FULL
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
                    return {"status": 400, "body": "missing"}
                return {"status": 200, "body": [employee_id]}
            """,
            wrappers={"inner_headers": "all"},
        )

        self.assertEqual(1, len(findings), findings)
        finding = findings[0]
        rewrite_line = line_of(source, "return {")
        self.assertEqual(tuple(REQUIRED), finding.missing)
        self.assertEqual(rewrite_line, finding.line)
        self.assertEqual(rewrite_line, finding.return_line)
        self.assertIn(f"line {rewrite_line}", finding.message)
        self.assertIn("new response object", finding.message)

    def test_response_aliases_and_early_returns_are_tracked(self):
        _, findings = analyze(
            """
            def secure(fn):
                def wrapper(*args, **kwargs):
                    response = fn(*args, **kwargs)
                    alias = response
                    return alias
                return wrapper

            @secure
            def employee_report(employee_id):
                if employee_id is None:
                    missing = {"status": 404}
                    early = missing
                    return early
                payload = {"status": 200}
                alias = payload
                return alias
            """,
            wrappers={"secure": "all"},
        )

        self.assertEqual([], findings)

    def test_header_mapping_overwrite_is_reported_at_rewrite(self):
        source, findings = analyze(
            """
            def inner_headers(fn):
                def wrapper():
                    response = fn()
                    response["headers"] = {
                        "Content-Security-Policy": "default-src 'self'",
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                    }
                    return response
                return wrapper

            def rewrite_headers(fn):
                def wrapper():
                    response = fn()
                    response["headers"] = {"Content-Type": "text/plain"}
                    return response
                return wrapper

            @rewrite_headers
            @inner_headers
            def employee_report():
                return {"status": 200, "body": []}
            """,
            wrappers={"inner_headers": "all"},
        )

        self.assertEqual(1, len(findings), findings)
        finding = findings[0]
        rewrite_line = line_of(
            source,
            'response["headers"] = {"Content-Type"',
        )
        self.assertEqual(rewrite_line, finding.line)
        self.assertEqual("headers rewritten", finding.origin_kind)
        self.assertIn("rewritten at line", finding.message)

    def test_partial_decorator_reports_each_early_return(self):
        source, findings = analyze(
            """
            @partial_headers
            def employee_report(employee_id):
                if employee_id is None:
                    return {"status": 404}
                return {"status": 200}
            """,
            wrappers={
                "partial_headers": ["X-Content-Type-Options"],
            },
        )

        self.assertEqual(2, len(findings), findings)
        self.assertEqual(
            {
                line_of(source, 'return {"status": 404'),
                line_of(source, 'return {"status": 200'),
            },
            {finding.return_line for finding in findings},
        )
        for finding in findings:
            self.assertNotIn("X-Content-Type-Options", finding.missing)
            self.assertIn("Content-Security-Policy", finding.missing)

    def test_loop_keeps_header_state_unknown(self):
        _, findings = analyze(
            """
            def outer(fn):
                def wrapper():
                    response = fn()
                    for name in ["one", "two"]:
                        response["headers"] = {name: "value"}
                    return response
                return wrapper

            @outer
            def employee_report():
                return {"status": 200}
            """,
        )

        self.assertEqual([], findings)

    def test_external_response_keeps_header_state_unknown(self):
        _, findings = analyze(
            """
            def outer(fn):
                def wrapper():
                    response = fn()
                    return response
                return wrapper

            @outer
            def employee_report():
                return make_response("report")
            """,
        )

        self.assertEqual([], findings)

    def test_config_accepts_wrapper_mapping_with_headers(self):
        contract = response_headers.normalise_config(
            {
                "required_headers": REQUIRED,
                "wrappers": {
                    "secure": {
                        "headers": ["Content-Security-Policy"],
                        "complete": False,
                    }
                },
            }
        )

        self.assertEqual(tuple(REQUIRED), contract.required)
        self.assertEqual(
            frozenset({"Content-Security-Policy"}),
            contract.wrappers["secure"].headers,
        )


if __name__ == "__main__":
    unittest.main()
