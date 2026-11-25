"""Tests for time-aware responsibility resolution."""
import pytest

from detect_secrets.incident.models import OwnershipRule
from detect_secrets.incident.ownership import OwnershipBook


def _rule(record_id, prefix, team, start, end=None):
    return OwnershipRule(
        record_id=record_id,
        path_prefix=prefix,
        team=team,
        effective_from=start,
        effective_to=end,
        source="CODEOWNERS",
    )


@pytest.fixture
def book():
    return OwnershipBook(
        [
            _rule("OWN-1", "src/payments", "payments-team", "2026-01-01T00:00:00",
                  "2026-06-01T00:00:00"),
            _rule("OWN-2", "src/payments", "payments-guild", "2026-06-01T00:00:00"),
            _rule("OWN-3", "src/platform", "platform-team", "2026-01-01T00:00:00"),
        ],
    )


def test_resolves_owner_from_matching_record(book):
    resolution = book.resolve("src/payments/charges.py", "2026-02-01T00:00:00")
    assert resolution.team == "payments-team"
    assert resolution.record_id == "OWN-1"
    assert resolution.source == "ownership_table"


def test_owner_changes_when_ownership_record_expires(book):
    before = book.resolve("src/payments/x.py", "2026-05-31T23:59:00")
    after = book.resolve("src/payments/x.py", "2026-06-01T00:00:00")
    assert (before.team, before.record_id) == ("payments-team", "OWN-1")
    assert (after.team, after.record_id) == ("payments-guild", "OWN-2")


def test_longest_prefix_wins(book):
    resolution = book.resolve("src/platform/billing/deep/key.py", "2026-03-01T00:00:00")
    assert resolution.record_id == "OWN-3"


def test_fallback_owner_is_labelled_as_code_move(book):
    resolution = book.resolve(
        "docs/misc/secret.txt",
        "2026-03-01T00:00:00",
        fallback_team="payments-team",
        fallback_record_id="OWN-1",
    )
    assert resolution.team == "payments-team"
    assert resolution.source == "code_move"


def test_missing_owner_without_fallback_raises(book):
    with pytest.raises(LookupError):
        book.resolve("docs/misc/secret.txt", "2026-03-01T00:00:00")


def test_duplicate_record_id_rejected():
    with pytest.raises(ValueError):
        OwnershipBook(
            [
                _rule("DUP", "src/a", "a", "2026-01-01T00:00:00"),
                _rule("DUP", "src/b", "b", "2026-01-01T00:00:00"),
            ],
        )
