#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import collections


# Verdict states for a resolved audit-write call.
#   UNSAFE  - the write is reachable while a transaction may still be
#             rolled back, so a confirmed audit entry can outlive the
#             underlying security action.
#   UNKNOWN - binding is dynamic or a wrapper cannot be resolved
#             statically, so no confident ordering can be established.
#   SAFE    - the write only runs after the transaction has committed
#             (or outside of any tracked transaction).
#   PENDING - the write has no transaction boundary in its own scope; the
#             caller transaction state at the folded call site decides.
AuditVerdict = collections.namedtuple(
    'AuditVerdict',
    ['state', 'reason', 'call']
)

UNSAFE = 'unsafe'
UNKNOWN = 'unknown'
SAFE = 'safe'
PENDING = 'pending'
DYNAMIC = 'dynamic'


class AuditTransactionConfig(collections.namedtuple(
    'AuditTransactionConfig',
    [
        'audit_write_functions',
        'post_commit_callbacks',
        'outside_transaction_adapters',
        'commit_functions',
        'rollback_functions',
    ]
)):
    """Explicit project configuration for audit/transaction ordering.

    Every entry is a dotted call name, e.g. ``audit.log_security_event`` or
    the bare name ``log_security_event``. A configured name matches both the
    bare call (``log_security_event(...)``) and the fully qualified call
    (``audit.log_security_event(...)``).

    audit_write_functions:
        Functions that append a confirmed security-action record to the
        audit stream. These are the calls whose ordering relative to the
        transaction boundary is being checked.
    post_commit_callbacks:
        Registrars that only invoke their callable argument after the
        transaction has committed, e.g. ``transaction.on_commit``.
    outside_transaction_adapters:
        Adapters that are only valid outside of a transaction. Reaching one
        of these while a transaction is still open is reported, since the
        adapter bypasses the rollback boundary.
    commit_functions / rollback_functions:
        Transaction boundary calls that close the current transaction
        scope, respectively making pending writes safe or unsafe.
    """

    @classmethod
    def default(cls):
        return cls(
            audit_write_functions=(
                'audit.log_security_event',
                'log_security_event',
            ),
            post_commit_callbacks=(
                'transaction.on_commit',
                'on_commit',
            ),
            outside_transaction_adapters=(
                'audit_sink.emit',
                'emit_audit_event',
            ),
            commit_functions=(
                'transaction.commit',
                'commit',
            ),
            rollback_functions=(
                'transaction.rollback',
                'rollback',
            ),
        )

    @classmethod
    def from_mapping(cls, mapping):
        """Build a config from an explicit project mapping, falling back to
        the default entries for any category the project leaves unset.
        """
        default = cls.default()._asdict()

        for key, value in mapping.items():
            if key in default and value:
                default[key] = tuple(value)

        return cls(**default)
