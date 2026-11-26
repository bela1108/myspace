# SPDX-License-Identifier: Apache-2.0
import textwrap
from unittest import mock

from bandit.core import config as bandit_config
from bandit.core import manager as bandit_manager
from bandit.plugins import lease_lifecycle as lease


PROJECT_CONFIG = {
    "lease_lifecycle": {
        "acquisition_functions": [
            "lease_project.acquire_elevated_client"
        ],
        "managed_borrow_functions": ["lease_project.elevated_client"],
        "handoff_functions": ["lease_project.handoff"],
        "deregistration_functions": ["lease_project.deregister"],
        "renewal_functions": ["lease_project.renew"],
        "sink_functions": [
            "long_lived_queue.put",
            "long_lived_queue.put_nowait",
        ],
    }
}


POST_BORROW_SOURCE = textwrap.dedent(
    '''
    from lease_project import elevated_client


    async def batch():
        async with elevated_client() as client:
            client.allowed()
        client.call_after_borrow()
    '''
)


NEVER_CALLED_CLOSURE_SOURCE = textwrap.dedent(
    '''
    from lease_project import elevated_client


    async def batch():
        async with elevated_client() as client:
            def deferred():
                return client.closed_over()
    '''
)


QUEUE_LEAK_SOURCE = textwrap.dedent(
    '''
    from lease_project import acquire_elevated_client


    async def batch(long_lived_queue):
        client = await acquire_elevated_client()
        await long_lived_queue.put(client)
    '''
)


CLEANUP_RERAISE_SOURCE = textwrap.dedent(
    '''
    from lease_project import acquire_elevated_client, deregister


    async def batch():
        client = await acquire_elevated_client()
        try:
            await client.work()
        except Exception:
            raise
        await deregister(client)
    '''
)


FINALLY_CLEANUP_SOURCE = textwrap.dedent(
    '''
    from lease_project import acquire_elevated_client, deregister


    async def batch():
        client = await acquire_elevated_client()
        try:
            await client.work()
        finally:
            await deregister(client)
    '''
)


CLOSURE_SINK_SOURCE = textwrap.dedent(
    '''
    from lease_project import elevated_client


    async def batch(long_lived_queue):
        async with elevated_client() as client:
            await long_lived_queue.put(lambda: client.use())
    '''
)


HANDOFF_SOURCE = textwrap.dedent(
    '''
    from lease_project import elevated_client, handoff


    async def batch():
        async with elevated_client() as client:
            handoff(client, destination="unknown-worker")
    '''
)


CLOSURE_AFTER_BORROW_SOURCE = textwrap.dedent(
    '''
    from lease_project import elevated_client


    async def batch():
        async with elevated_client() as client:
            def deferred():
                return client.closed_over()
        deferred()
    '''
)


CLOSURE_AND_RERAISE_SOURCE = textwrap.dedent(
    '''
    from lease_project import elevated_client


    async def batch():
        async with elevated_client() as client:
            def deferred():
                return client.closed_over()
            try:
                await client.work()
            except Exception:
                raise
    '''
)


RENEWAL_SOURCE = textwrap.dedent(
    '''
    from lease_project import acquire_elevated_client, deregister, renew


    async def batch():
        client = await acquire_elevated_client()
        try:
            await renew(client, ttl=300)
        finally:
            await deregister(client)
    '''
)


class MockElevatedClient:
    def allowed(self):
        return "allowed"

    def call_after_borrow(self):
        return "after-borrow"

    def closed_over(self):
        return "closed-over"


def test_configuration_accepts_project_aliases():
    config = lease.normalize_config(
        {
            "lease": {
                "acquire": ["acquire_lease"],
                "borrow": ["borrow_client"],
                "transfer": ["transfer_client"],
                "cleanup": ["release_lease"],
                "trusted_renewal": ["heartbeat"],
                "long_lived_sinks": ["queue.put"],
            }
        }
    )

    assert "acquire_lease" in config["acquisition_functions"]
    assert "borrow_client" in config["managed_borrow_functions"]
    assert "transfer_client" in config["handoff_functions"]
    assert "release_lease" in config["deregistration_functions"]
    assert "heartbeat" in config["renewal_functions"]
    assert "queue.put" in config["sink_functions"]


def test_mock_client_distinguishes_post_borrow_call_from_dead_closure():
    mock_client = mock.Mock(spec=MockElevatedClient)

    mock_client.call_after_borrow()
    deferred_closure = lambda: mock_client.closed_over()
    assert callable(deferred_closure)

    post_borrow = lease.analyze_source(POST_BORROW_SOURCE, PROJECT_CONFIG)
    never_called = lease.analyze_source(
        NEVER_CALLED_CLOSURE_SOURCE, PROJECT_CONFIG
    )

    post_findings = post_borrow.by_verdict(lease.LEASE_LEAKED)
    closure_findings = never_called.by_verdict(
        lease.NEEDS_MANUAL_REVIEW
    )

    assert len(post_findings) == 1
    assert post_findings[0].reason == "call_after_borrow"
    assert not post_borrow.has_verdict(lease.NEEDS_MANUAL_REVIEW)

    assert len(closure_findings) == 1
    assert closure_findings[0].reason == "uncalled_closure_capture"
    assert not never_called.has_verdict(lease.LEASE_LEAKED)

    mock_client.call_after_borrow.assert_called_once_with()
    mock_client.closed_over.assert_not_called()


def test_closure_invoked_after_borrow_is_leak():
    report = lease.analyze_source(
        CLOSURE_AFTER_BORROW_SOURCE, PROJECT_CONFIG
    )

    findings = report.by_verdict(lease.LEASE_LEAKED)
    assert len(findings) == 1
    assert findings[0].reason == "closure_invoked_after_borrow"
    assert not report.has_verdict(lease.NEEDS_MANUAL_REVIEW)


def test_uncalled_closure_and_rethrow_are_considered_together():
    report = lease.analyze_source(
        CLOSURE_AND_RERAISE_SOURCE, PROJECT_CONFIG
    )

    findings = report.by_verdict(lease.NEEDS_MANUAL_REVIEW)
    assert len(findings) == 1
    assert findings[0].reason == "uncalled_closure_capture"
    assert findings[0].details["exception_rethrow"] is True
    assert findings[0].details["rethrow_lines"]
    assert not report.has_verdict(lease.CLEANUP_NOT_GUARANTEED)


def test_queue_storage_is_definite_lease_leak():
    report = lease.analyze_source(QUEUE_LEAK_SOURCE, PROJECT_CONFIG)

    findings = report.by_verdict(lease.LEASE_LEAKED)
    assert len(findings) == 1
    assert findings[0].reason == "long_lived_sink"
    expected_line = next(
        index
        for index, line in enumerate(QUEUE_LEAK_SOURCE.splitlines(), 1)
        if "long_lived_queue.put(client)" in line
    )
    assert findings[0].line == expected_line


def test_exception_rethrow_makes_cleanup_not_guaranteed():
    report = lease.analyze_source(CLEANUP_RERAISE_SOURCE, PROJECT_CONFIG)

    findings = report.by_verdict(lease.CLEANUP_NOT_GUARANTEED)
    assert len(findings) == 1
    assert findings[0].details["rethrow_lines"]
    expected_line = next(
        index
        for index, line in enumerate(
            CLEANUP_RERAISE_SOURCE.splitlines(), 1
        )
        if "deregister(client)" in line
    )
    assert findings[0].details["cleanup_lines"] == [expected_line]


def test_finally_deregistration_is_guaranteed():
    report = lease.analyze_source(FINALLY_CLEANUP_SOURCE, PROJECT_CONFIG)

    assert not report.has_verdict(lease.CLEANUP_NOT_GUARANTEED)
    assert not report.has_verdict(lease.LEASE_LEAKED)


def test_closure_sink_is_leaked_not_manual_review():
    report = lease.analyze_source(CLOSURE_SINK_SOURCE, PROJECT_CONFIG)

    leaked = report.by_verdict(lease.LEASE_LEAKED)
    assert len(leaked) == 1
    assert leaked[0].reason == "closure_escape_to_sink"
    assert not report.has_verdict(lease.NEEDS_MANUAL_REVIEW)


def test_configured_handoff_requires_manual_review():
    report = lease.analyze_source(HANDOFF_SOURCE, PROJECT_CONFIG)

    findings = report.by_verdict(lease.NEEDS_MANUAL_REVIEW)
    assert len(findings) == 1
    assert findings[0].reason == "handoff_boundary"


def test_trusted_renewal_has_independent_verdict():
    report = lease.analyze_source(RENEWAL_SOURCE, PROJECT_CONFIG)

    renewals = report.by_verdict(lease.TRUSTED_RENEWAL)
    assert len(renewals) == 1
    assert renewals[0].rule_id == "B904"
    assert not report.has_verdict(lease.LEASE_LEAKED)
    assert not report.has_verdict(lease.CLEANUP_NOT_GUARANTEED)


def _run_bandit(tmp_path, source):
    sample = tmp_path / "lease_sample.py"
    sample.write_text(textwrap.dedent(source), encoding="utf-8")

    config = bandit_config.BanditConfig()
    config._config["lease_lifecycle"] = PROJECT_CONFIG["lease_lifecycle"]
    manager = bandit_manager.BanditManager(
        config,
        "file",
        profile={
            "include": ["B901", "B902", "B903", "B904"],
        },
    )
    manager.discover_files([str(sample)], True)
    manager.run_tests()
    assert not manager.skipped
    return manager


def test_bandit_json_report_separates_verdicts(tmp_path):
    post_manager = _run_bandit(tmp_path, POST_BORROW_SOURCE)
    closure_manager = _run_bandit(tmp_path, NEVER_CALLED_CLOSURE_SOURCE)

    post_issues = post_manager.get_issue_list()
    closure_issues = closure_manager.get_issue_list()

    assert [issue.test_id for issue in post_issues] == ["B901"]
    assert post_issues[0].lease_verdict == lease.LEASE_LEAKED
    post_dict = post_issues[0].as_dict()
    assert post_dict["lease_verdict"] == "leaked_lease"

    assert [issue.test_id for issue in closure_issues] == ["B903"]
    assert closure_issues[0].lease_verdict == lease.NEEDS_MANUAL_REVIEW
    closure_dict = closure_issues[0].as_dict()
    assert closure_dict["lease_verdict"] == "needs_manual_review"


def test_bandit_reports_all_four_rule_ids(tmp_path):
    sources = (
        QUEUE_LEAK_SOURCE,
        CLEANUP_RERAISE_SOURCE,
        HANDOFF_SOURCE,
        RENEWAL_SOURCE,
    )
    ids = set()
    for source in sources:
        manager = _run_bandit(tmp_path, source)
        ids.update(issue.test_id for issue in manager.get_issue_list())

    assert ids == {"B901", "B902", "B903", "B904"}
