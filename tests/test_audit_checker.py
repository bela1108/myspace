from audit_checker import check_c_code
from audit_checker.demo import CONTRACTS as DEMO_CONTRACTS
from audit_checker.checker import audit_file


CONTRACTS = {
    "protected_write": {"role": "change", "resource_arg": 0, "success": 0},
    "withdraw_resource": {"role": "withdraw", "resource_arg": 0},
    "commit_credential": {"role": "credential", "resource_arg": 0},
}


def _statuses(report):
    return [exit_report["status"] for exit_report in report["exits"]]


def test_missing_credential_on_early_return_and_shared_cleanup():
    source = r'''
    int protected_write(const char *r);
    int commit_credential(const char *r);

    int configure(const char *r, int early)
    {
        int rc = protected_write(r);
        if (rc != 0)
            goto cleanup;

        if (early > 0)
            return 21;
        if (early < 0)
            goto cleanup;

        commit_credential(r);

    cleanup:
        return rc;
    }
    '''

    report = check_c_code(source, CONTRACTS, "configure")

    assert report["verdict"] == "missing_credential"
    missing = [exit_report for exit_report in report["exits"] if exit_report["status"] == "missing_credential"]
    assert len(missing) >= 2
    assert {exit_report["exit_line"] for exit_report in missing}
    for exit_report in missing:
        path = exit_report["path_text"]
        assert "protected_write" in path
        assert "inferred succeeded" in path
        assert "configure" in path
        assert exit_report["path"][-1]["kind"] == "return"

    clean = [exit_report for exit_report in report["exits"] if exit_report["status"] == "clean"]
    assert clean


def test_duplicate_credential_through_one_local_helper():
    source = r'''
    int protected_write(const char *r);
    int commit_credential(const char *r);

    static int audit_helper(const char *r)
    {
        return commit_credential(r);
    }

    int configure(const char *r)
    {
        int rc;
        rc = protected_write(r);
        if (rc != 0)
            goto cleanup;

        commit_credential(r);
        rc = audit_helper(r);

        return 0;

    cleanup:
        return rc;
    }
    '''

    report = check_c_code(source, CONTRACTS, "configure")

    assert report["verdict"] == "duplicate_credential"
    duplicate = next(exit_report for exit_report in report["exits"] if exit_report["status"] == "duplicate_credential")
    assert duplicate["problems"][0]["actual_credentials"] == 2
    path = duplicate["path_text"]
    assert "commit_credential" in path
    assert "audit_helper" in path
    assert "inline local helper layer 1" in path


def test_rollback_path_is_clean():
    source = r'''
    int protected_write(const char *r);
    int withdraw_resource(const char *r);
    int commit_credential(const char *r);

    int configure(const char *r, int abort)
    {
        int rc = protected_write(r);
        if (rc != 0)
            goto cleanup;

        if (abort != 0) {
            withdraw_resource(r);
            goto cleanup;
        }

        commit_credential(r);

    cleanup:
        return rc;
    }
    '''

    report = check_c_code(source, CONTRACTS, "configure")

    assert report["verdict"] == "rollback_clean"
    assert report["findings"] == []
    assert set(_statuses(report)) <= {"clean", "rollback_clean"}
    rolled_back = next(exit_report for exit_report in report["exits"] if exit_report["status"] == "rollback_clean")
    assert "withdraw_resource" in rolled_back["path_text"]
    assert "jump to label cleanup" in rolled_back["path_text"]
    assert rolled_back["ledger"][0]["effective_changes"] == 0
    assert rolled_back["ledger"][0]["credentials"] == 0
    assert rolled_back["ledger"][0]["withdrawn_changes"] == 1


def test_missing_external_contract_is_proof_boundary():
    source = r'''
    int protected_write(const char *r);
    int commit_credential(const char *r);
    int unknown_policy(const char *r);

    int configure(const char *r)
    {
        int rc = protected_write(r);
        if (rc != 0)
            goto cleanup;

        if (unknown_policy(r) > 0)
            commit_credential(r);

        return 0;

    cleanup:
        return rc;
    }
    '''

    report = check_c_code(source, CONTRACTS, "configure")

    assert report["verdict"] == "undecidable"
    unknown = next(exit_report for exit_report in report["exits"] if exit_report["status"] == "undecidable")
    assert unknown["boundaries"][0]["callee"] == "unknown_policy"
    assert "no effect/audit contract" in unknown["boundaries"][0]["reason"]
    assert "unknown_policy" in unknown["path_text"]
    assert any(exit_report["status"] == "clean" for exit_report in report["exits"])


def test_loop_zero_and_two_iterations_expose_missing_and_duplicate():
    source = r'''
    int protected_write(const char *r);
    int commit_credential(const char *r);

    int configure(const char *r, int count)
    {
        int i;
        int rc = protected_write(r);
        if (rc != 0)
            goto cleanup;

        for (i = 0; i < count; ++i)
            commit_credential(r);

    cleanup:
        return rc;
    }
    '''

    report = check_c_code(source, CONTRACTS, "configure")
    statuses = _statuses(report)

    assert "missing_credential" in statuses
    assert "duplicate_credential" in statuses
    zero_path = next(e["path_text"] for e in report["exits"] if e["status"] == "missing_credential")
    many_path = next(e["path_text"] for e in report["exits"] if e["status"] == "duplicate_credential")
    assert "0 body iteration" in zero_path or "after 0 iteration(s)" in zero_path
    assert "after 2 iteration(s)" in many_path


def test_fixed_two_iteration_balanced_loop_is_clean():
    source = r'''
    int protected_write(const char *r);
    int commit_credential(const char *r);

    int configure(const char *r)
    {
        int i;
        int rc = 0;

        for (i = 0; i < 2; ++i) {
            rc = protected_write(r);
            if (rc != 0)
                goto cleanup;
            commit_credential(r);
        }

        return 0;

    cleanup:
        return rc;
    }
    '''

    report = check_c_code(source, CONTRACTS, "configure")

    assert report["verdict"] == "clean"
    assert report["findings"] == []
    success_exit = next(e for e in report["exits"] if e["exit_kind"] == "return" and e["exit_line"] is not None)
    assert success_exit["ledger"][0]["effective_changes"] == 2
    assert success_exit["ledger"][0]["credentials"] == 2


def test_fixed_zero_iteration_loop_is_clean():
    source = r'''
    int protected_write(const char *r);
    int commit_credential(const char *r);

    int configure(const char *r)
    {
        int i;
        for (i = 0; i < 0; ++i) {
            protected_write(r);
            commit_credential(r);
        }
        return 0;
    }
    '''

    report = check_c_code(source, CONTRACTS, "configure")

    assert report["verdict"] == "clean"
    assert report["exits"][0]["ledger"] == []
