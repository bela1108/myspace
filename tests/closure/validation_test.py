from datetime import timedelta

from detect_secrets.closure.validation import Check
from detect_secrets.closure.validation import validate_environment
from detect_secrets.closure.validation import validate_receipt
from detect_secrets.closure.validation import validate_revocation_scope
from detect_secrets.closure.validation import validate_window
from tests.closure.conftest import AS_OF
from tests.closure.conftest import make_receipt
from tests.closure.conftest import make_scope
from tests.closure.conftest import make_window


class TestWindow:
    def test_passes_inside_window(self):
        result = validate_window(make_receipt(), AS_OF)
        assert result.check is Check.WINDOW
        assert result.passed
        assert result.reasons == ()

    def test_fails_outside_window_and_says_why(self):
        receipt = make_receipt(window=make_window(
            opens_at=AS_OF - timedelta(days=30),
            closes_at=AS_OF - timedelta(days=1),
        ))
        result = validate_window(receipt, AS_OF)
        assert not result.passed
        assert 'RT-1' in result.reasons[0]


class TestEnvironment:
    def test_passes_on_match(self):
        assert validate_environment(make_receipt(), 'prod').passed

    def test_fails_on_mismatch(self):
        result = validate_environment(make_receipt(environment='staging'), 'prod')
        assert not result.passed
        assert "'staging'" in result.reasons[0]


class TestRevocationScope:
    def test_passes_when_subset_of_frozen_scope(self):
        assert validate_revocation_scope(make_receipt(), make_scope()).passed

    def test_fails_when_empty(self):
        receipt = make_receipt(revocation_scope=frozenset())
        assert not validate_revocation_scope(receipt, make_scope()).passed

    def test_fails_when_naming_branches_outside_frozen_scope(self):
        receipt = make_receipt(revocation_scope=frozenset({'main', 'feature/x'}))
        result = validate_revocation_scope(receipt, make_scope())
        assert not result.passed
        assert 'feature/x' in result.reasons[0]


def test_validate_receipt_runs_each_check_separately():
    receipt = make_receipt(environment='staging')
    results = validate_receipt(receipt, as_of=AS_OF, environment='prod', scope=make_scope())

    assert [result.check for result in results] == [
        Check.WINDOW,
        Check.ENVIRONMENT,
        Check.REVOCATION_SCOPE,
    ]
    # only the environment check failed; the others are judged independently
    assert [result.passed for result in results] == [True, False, True]
