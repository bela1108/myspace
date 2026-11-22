# The closed input domain is configured under match_export_authorization:
# subjects: department, action
# departments: dept_a, dept_b
# actions: view, export, bulk_export
# restricted calls: export_customer_pii, bulk_export_customer_pii
# authorization predicates: is_admin, has_export_grant


def shadowed_authorization(department, action, user):
    # bad: the earlier unguarded case wins for this witness and performs a
    # restricted export, shadowing the guarded authorization case below.
    match (department, action):
        case ("dept_a", "export"):
            export_customer_pii()
        case ("dept_a", "export") if is_admin(user):
            log_attempt()


def widened_or_pattern(department, action):
    # bad: the or pattern admits bulk_export as well, neither is authorized.
    match (department, action):
        case ("dept_a", "export" | "bulk_export"):
            export_customer_pii()
        case _:
            deny()


def capture_binding(department, action):
    # bad: a capture pattern binds every department, so both dept_a and
    # dept_b reach the restricted export without an authorization check.
    match (department, action):
        case (dept, "export"):
            export_customer_pii()
        case _:
            deny()


def authorized_guard(department, action):
    # good: the authorization predicate uses the capture-bound department.
    match (department, action):
        case (dept, "export") if has_export_grant(dept):
            export_customer_pii()
        case _:
            deny()


def unreadable_guard(department, action, user):
    # analysis gap: the predicate is outside the configured authorization
    # vocabulary, so authorization coverage cannot be decided here.
    match (department, action):
        case ("dept_a", "export") if runtime_policy(user):
            export_customer_pii()
        case _:
            deny()


def legacy_dispatch(department, action):
    # old syntax keeps using the pre-existing code path; no match node is
    # present so B114 stays silent.
    if department == "dept_a" and action == "export":
        export_customer_pii()
