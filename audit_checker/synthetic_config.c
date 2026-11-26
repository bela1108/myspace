/* Synthetic device configuration for audit-credential checking. */

int hal_protected_write(const char *resource, int slot);
int cfg_withdraw(const char *resource);
int audit_commit(const char *resource);
int external_policy(const char *resource);

static int audit_via_helper(const char *resource)
{
    return audit_commit(resource);
}

int demo_missing(const char *resource, int early)
{
    int rc;

    rc = hal_protected_write(resource, 1);
    if (rc != 0) {
        goto cleanup;
    }

    if (early > 0) {
        return 21;
    }
    if (early < 0) {
        goto cleanup;
    }

    audit_commit(resource);

cleanup:
    return rc;
}

int demo_duplicate(const char *resource)
{
    int rc;

    rc = hal_protected_write(resource, 2);
    if (rc != 0) {
        goto cleanup;
    }

    audit_commit(resource);
    rc = audit_via_helper(resource);
    if (rc != 0) {
        goto cleanup;
    }

    return 0;

cleanup:
    return rc;
}

int demo_rollback_clean(const char *resource, int attempts, int abort_after_write)
{
    int rc = -1;
    int attempt;

    for (attempt = 0; attempt < attempts; ++attempt) {
        rc = hal_protected_write(resource, attempt);
        if (rc == 0) {
            break;
        }
    }

    if (rc != 0) {
        goto cleanup;
    }

    if (abort_after_write != 0) {
        cfg_withdraw(resource);
        goto cleanup;
    }

    audit_commit(resource);

cleanup:
    return rc;
}

int demo_undecidable(const char *resource)
{
    int rc;

    rc = hal_protected_write(resource, 3);
    if (rc != 0) {
        goto cleanup;
    }

    if (external_policy(resource) > 0) {
        audit_commit(resource);
    }

    return 0;

cleanup:
    return rc;
}
