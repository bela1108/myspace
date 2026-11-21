#!/usr/bin/env python
"""
Allocatable processing budgets for oletools backends.

Office parsing is not a single operation.  A document is first opened as a
container, then its macro streams may be extracted, and finally embedded
attachments may be decoded.  Callers such as an attachment gateway usually
have a limited amount of work they are willing to spend on a batch of files.
Charging all of that work to one shared pool makes a large document able to
starve every following document.

This module provides the accounting primitives used by
:mod:`oletools.scan_backend`:

* :class:`ScanBudget` owns the quotas and charges.
* :class:`BudgetAccount` is a per-object ledger.
* :data:`CONTAINER`, :data:`MACRO` and :data:`ATTACHMENT` are independent
  accounting categories.
* :class:`BudgetExhausted` reports the exact category and object that ran out
  of quota.

Quotas are expressed in caller-defined work units.  A backend using byte
counts, parser operations or a weighted estimate can use the same ledger.

Example::

    budget = ScanBudget(container=100, macro=50, attachment=200)
    budget.allocate('large.docx', container=80, macro=40, attachment=150)
    budget.top_up('small.doc', macro=10)
"""

from __future__ import print_function

import copy


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

class BudgetCategoryValue(str):
    """String category that also exposes an enum-like ``.value``."""

    @property
    def value(self):
        return str(self)

    @property
    def name(self):
        return str(self).upper()


CONTAINER = BudgetCategoryValue('container')
MACRO = BudgetCategoryValue('macro')
ATTACHMENT = BudgetCategoryValue('attachment')

CATEGORIES = (CONTAINER, MACRO, ATTACHMENT)
CONTAINER_PARSE = CONTAINER
MACRO_EXTRACTION = MACRO
ATTACHMENT_DECODING = ATTACHMENT

#: Alternative names accepted at API boundaries.
CATEGORY_ALIASES = {
    'container': CONTAINER,
    'containers': CONTAINER,
    'container_parse': CONTAINER,
    'parse_container': CONTAINER,
    'ole': CONTAINER,
    'ooxml': CONTAINER,
    'zip': CONTAINER,
    'macro': MACRO,
    'macros': MACRO,
    'macro_extract': MACRO,
    'macro_extraction': MACRO,
    'extract_macro': MACRO,
    'extract_macros': MACRO,
    'vba': MACRO,
    'xlm': MACRO,
    'attachment': ATTACHMENT,
    'attachments': ATTACHMENT,
    'attachment_decode': ATTACHMENT,
    'attachment_decoding': ATTACHMENT,
    'decode_attachment': ATTACHMENT,
    'decode_attachments': ATTACHMENT,
    'decode': ATTACHMENT,
    'ole10native': ATTACHMENT,
    'package': ATTACHMENT,
}


class BudgetCategory(object):
    """String constants and aliases for the three accounting categories."""

    CONTAINER = CONTAINER
    MACRO = MACRO
    ATTACHMENT = ATTACHMENT
    MACRO_EXTRACTION = MACRO
    ATTACHMENT_DECODING = ATTACHMENT
    ALL = CATEGORIES


def normalize_category(category):
    """
    Return the canonical category name for *category*.

    ``None`` is kept as ``None`` so helpers can mean "the stage that paused".
    """
    if category is None:
        return None
    if hasattr(category, 'value'):
        category = category.value
    if not isinstance(category, str):
        raise TypeError('budget category must be a string, not {0!r}'
                        .format(type(category).__name__))
    key = category.strip().lower().replace('-', '_').replace(' ', '_')
    try:
        return CATEGORY_ALIASES[key]
    except KeyError:
        raise ValueError('unknown budget category {0!r}; expected one of {1}'
                         .format(category, ', '.join(CATEGORIES)))


def normalize_categories(categories):
    """Normalize an iterable of categories, preserving order and uniqueness."""
    result = []
    for category in categories:
        category = normalize_category(category)
        if category not in result:
            result.append(category)
    return tuple(result)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class BudgetError(Exception):
    """Base class for processing-budget errors."""


class BudgetExhausted(BudgetError):
    """
    Raised when an object cannot pay for the next unit of work.

    ``needed`` is the shortfall for the pending stage while ``available`` is
    what the account had left.  ``consumed`` can be set by a stage processor
    that performed some work before discovering that the next chunk did not
    fit; the scanner uses it to keep the ledger exact.
    """

    def __init__(self, category=None, object_id=None, needed=None,
                 available=None, message=None, consumed=None, findings=None):
        self.category = normalize_category(category)
        self.object_id = object_id
        self.needed = needed
        self.required = needed
        self.shortfall = needed
        self.available = available
        self.consumed = consumed
        self.findings = findings
        if message is None:
            message = 'processing budget exhausted'
            if self.object_id is not None:
                message += ' for object {0!r}'.format(self.object_id)
            if self.category is not None:
                message += ' in category {0!r}'.format(self.category)
            if needed is not None:
                message += ' (needed {0}, available {1})'.format(
                    needed, available)
        self.message = message
        super(BudgetExhausted, self).__init__(message)

    def to_dict(self):
        return {
            'object_id': self.object_id,
            'category': self.category,
            'needed': self.needed,
            'available': self.available,
            'consumed': self.consumed,
            'findings': self.findings,
            'message': self.message,
        }


# Sentinel  used to distinguish "argument not supplied" from an explicit
# ``None`` (which means unlimited).
_UNSET = object()


def _new_limits(value):
    return dict((category, value) for category in CATEGORIES)


def _limits_from_kwargs(container=_UNSET, macro=_UNSET, attachment=_UNSET,
                        total=_UNSET, default=_UNSET):
    """
    Build a limits mapping from either per-category values or a total.

    If nothing was supplied, all categories are unlimited.  If anything was
    supplied, categories not mentioned default to ``default`` (0 unless the
    caller explicitly asked for another default).
    """
    supplied = [value is not _UNSET
                for value in (container, macro, attachment, total)]
    if not any(supplied):
        if default is _UNSET:
            return _new_limits(None)
        return _new_limits(default)
    if default is _UNSET:
        default = 0
    limits = _new_limits(default)
    if total is not _UNSET:
        if total is None:
            limits = _new_limits(None)
        else:
            limits = _new_limits(total)
    values = {
        CONTAINER: container,
        MACRO: macro,
        ATTACHMENT: attachment,
    }
    for category, value in values.items():
        if value is not _UNSET:
            limits[category] = value
    for category, value in limits.items():
        if value is not None and value < 0:
            raise ValueError('budget for {0} cannot be negative'
                             .format(category))
    return limits


def _coerce_amount(amount, category=None):
    if amount is None:
        raise TypeError('budget amount must not be None')
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise TypeError('budget amount for {0} must be a number, not {1!r}'
                        .format(category, amount))
    if amount < 0:
        raise ValueError('budget amount for {0} cannot be negative'
                         .format(category))
    return amount


class BudgetAccount(object):
    """Usage ledger for one object (or for a shared root pool)."""

    def __init__(self, object_id=None, container=_UNSET, macro=_UNSET,
                 attachment=_UNSET, total=_UNSET, limits=None,
                 default=_UNSET):
        self.object_id = object_id
        if limits is None:
            limits = _limits_from_kwargs(container, macro, attachment,
                                         total, default)
        self.limits = dict(limits)
        self.used = dict((category, 0) for category in CATEGORIES)
        self.events = []

    @property
    def id(self):
        return self.object_id

    def limit(self, category):
        """Return the quota for *category* (``None`` means unlimited)."""
        return self.limits[normalize_category(category)]

    def remaining(self, category):
        """Return the remaining quota for *category* (``None`` unlimited)."""
        category = normalize_category(category)
        limit = self.limits[category]
        if limit is None:
            return None
        return max(0, limit - self.used[category])

    def can_afford(self, category, amount):
        """Return True if *amount* still fits in *category*."""
        category = normalize_category(category)
        amount = _coerce_amount(amount, category)
        remaining = self.remaining(category)
        return remaining is None or amount <= remaining

    def require(self, category, amount):
        """Like :meth:`can_afford`, but raise :class:`BudgetExhausted`."""
        category = normalize_category(category)
        amount = _coerce_amount(amount, category)
        remaining = self.remaining(category)
        if remaining is not None and amount > remaining:
            raise BudgetExhausted(
                category=category,
                object_id=self.object_id,
                needed=amount - remaining,
                available=remaining,
            )
        return amount

    def charge(self, category, amount=None):
        """
        Charge *amount* units to *category*.

        For convenience the two arguments may also be supplied in the reverse
        order, i.e. ``charge(100, MACRO)``.
        """
        if amount is None:
            raise TypeError('charge() requires an amount')
        if isinstance(category, (int, float)) and isinstance(amount, str):
            category, amount = amount, category
        category = normalize_category(category)
        self.require(category, amount)
        self.used[category] += amount
        self.events.append((category, amount))
        return self.used[category]

    spend = charge
    consume = charge
    use = charge
    available = remaining
    can_pay = can_afford

    def refund(self, category, amount):
        """Undo a charge, used when a stage stops before doing its work."""
        category = normalize_category(category)
        amount = _coerce_amount(amount, category)
        if amount > self.used[category]:
            raise ValueError('cannot refund more than was charged')
        self.used[category] -= amount
        self.events.append((category, -amount))
        return self.used[category]

    def top_up(self, category, amount):
        """Increase the quota for one category."""
        category = normalize_category(category)
        amount = _coerce_amount(amount, category)
        if self.limits[category] is None:
            return None
        self.limits[category] += amount
        return self.limits[category]

    def snapshot(self):
        """Return a JSON-friendly view of this ledger."""
        return {
            'object_id': self.object_id,
            'limits': dict(self.limits),
            'used': dict(self.used),
            'remaining': dict((category, self.remaining(category))
                              for category in CATEGORIES),
        }

    to_dict = snapshot

    def clone(self):
        return copy.deepcopy(self)

    def __repr__(self):
        return 'BudgetAccount(object_id={0!r}, limits={1!r}, used={2!r})'\
            .format(self.object_id, self.limits, self.used)


#: Backwards/alternative name used by some callers.
ObjectBudget = BudgetAccount
ObjectProcessingBudget = BudgetAccount
BudgetKind = BudgetCategory
BudgetExceeded = BudgetExhausted
InsufficientBudget = BudgetExhausted


class ScanBudget(object):
    """
    A collection of processing quotas shared by a batch of Office objects.

    The constructor accepts either:

    * no limits, meaning "unlimited" (useful when a gateway only wants usage
      telemetry), or
    * per-category limits, e.g. ``ScanBudget(container=1000, macro=500,
      attachment=2000)``.  Categories omitted in that form default to zero,
      which makes accidental cross-category spending visible.

    Limits are shared by objects until the caller reserves an account with
    :meth:`allocate` or tops up a specific object with :meth:`top_up`.
    Explicit object accounts are independent, so a large object cannot spend
    the quota reserved for its smaller siblings.

    ``objects``/``object_quotas`` may be used to allocate a mapping of object
    id to per-category quota at construction time.
    """

    def __init__(self, container=_UNSET, macro=_UNSET, attachment=_UNSET,
                 total=_UNSET, objects=None, object_quotas=None,
                 default=_UNSET):
        if hasattr(container, "items") and not isinstance(container, str):
            limits = container
            if macro is _UNSET:
                macro = limits.get("macro", limits.get("macro_extraction",
                                                         _UNSET))
            if attachment is _UNSET:
                attachment = limits.get("attachment", limits.get(
                    "attachment_decoding", _UNSET))
            if total is _UNSET:
                total = limits.get("total", _UNSET)
            if objects is None and object_quotas is None:
                objects = limits.get("objects", limits.get("object_quotas"))
            container = limits.get("container", limits.get("container_parse",
                                                         _UNSET))
        self.limits = _limits_from_kwargs(container, macro, attachment,
                                          total, default)
        self.root = BudgetAccount(limits=self.limits)
        self.accounts = {}
        quotas = object_quotas if object_quotas is not None else objects
        if quotas:
            for object_id, quota in quotas.items():
                if isinstance(quota, dict):
                    self.allocate(object_id, **quota)
                elif isinstance(quota, (int, float)):
                    self.allocate(object_id, total=quota)
                else:
                    raise TypeError('quota for {0!r} must be a number or a '
                                    'mapping'.format(object_id))

    @property
    def used(self):
        """Total usage, including explicitly allocated object accounts."""
        result = dict((category, self.root.used[category])
                      for category in CATEGORIES)
        for account in self.accounts.values():
            for category in CATEGORIES:
                result[category] += account.used[category]
        return result

    @property
    def remaining(self):
        """Remaining shared root quota (``None`` means unlimited)."""
        return dict((category, self.root.remaining(category))
                    for category in CATEGORIES)

    def account_for(self, object_id):
        """
        Return the ledger that should be charged for *object_id*.

        An explicitly allocated account wins.  Otherwise the shared root pool
        is used.  This makes ``ScanBudget(container=...)`` behave as a shared
        batch budget and ``allocate`` as a per-object reservation.
        """
        return self.accounts.get(object_id, self.root)

    account = account_for
    get_account = account_for
    for_object = account_for
    object = account_for

    def allocate(self, object_id, container=_UNSET, macro=_UNSET,
                 attachment=_UNSET, total=_UNSET, replace=False,
                 default=_UNSET):
        """
        Reserve a per-object account.

        Repeated calls merge additional quota into the existing account.
        Pass ``replace=True`` to start from zero instead.
        """
        if object_id is None:
            raise ValueError('object_id must not be None')
        if default is _UNSET:
            default = 0
        if object_id in self.accounts and not replace:
            account = self.accounts[object_id]
            additions = _limits_from_kwargs(container, macro, attachment,
                                            total, default=0)
            for category in CATEGORIES:
                if additions[category]:
                    account.top_up(category, additions[category])
            return account
        account = BudgetAccount(
            object_id=object_id,
            container=container,
            macro=macro,
            attachment=attachment,
            total=total,
            default=default,
        )
        self.accounts[object_id] = account
        return account

    grant = allocate
    reserve = allocate
    allocate_for = allocate
    reserve_for = allocate

    def allocate_evenly(self, object_ids, container=_UNSET, macro=_UNSET,
                        attachment=_UNSET, total=_UNSET):
        """
        Split a total quota evenly across *object_ids*.

        Any remainder is assigned to the first objects, keeping the sum exact.
        This is a convenient way for a gateway to give every file a fair slice
        instead of letting the first large file consume the batch budget.
        """
        object_ids = list(object_ids)
        if not object_ids:
            return {}
        values = {}
        if total is not _UNSET:
            values = dict((category, total) for category in CATEGORIES)
        if container is not _UNSET:
            values[CONTAINER] = container
        if macro is not _UNSET:
            values[MACRO] = macro
        if attachment is not _UNSET:
            values[ATTACHMENT] = attachment
        if not values:
            raise TypeError('allocate_evenly() requires a quota')

        count = len(object_ids)
        shares = dict((category, [value // count for _ in object_ids])
                      for category, value in values.items())
        for category, value in values.items():
            remainder = value % count
            for index in range(remainder):
                shares[category][index] += 1

        result = {}
        for index, object_id in enumerate(object_ids):
            quota = dict((category, shares[category][index])
                         for category in values)
            result[object_id] = self.allocate(object_id, **quota)
        return result

    def top_up(self, object_id=None, category=None, amount=None,
               container=_UNSET, macro=_UNSET, attachment=_UNSET):
        """
        Add quota to a specific object, or to the shared pool.

        Examples::

            budget.top_up('report.docx', macro=100)
            budget.top_up('report.docx', MACRO, 100)
            budget.top_up(container=50)       # shared pool
        """
        if amount is None and isinstance(category, (int, float)) and \
                not isinstance(category, bool):
            amount = category
            category = None
        if amount is not None:
            if isinstance(category, (int, float)) and \
                    isinstance(amount, str):
                category, amount = amount, category
            if object_id is None:
                account = self.root
            elif object_id in self.accounts:
                account = self.accounts[object_id]
            else:
                account = self.allocate(object_id)
            if category is None:
                for category_name in CATEGORIES:
                    account.top_up(category_name, amount)
            else:
                account.top_up(normalize_category(category), amount)
            return account

        additions = _limits_from_kwargs(container, macro, attachment,
                                        default=0)
        if object_id is None:
            account = self.root
        elif object_id in self.accounts:
            account = self.accounts[object_id]
        else:
            account = self.allocate(object_id)
        for category in CATEGORIES:
            if additions[category]:
                account.top_up(category, additions[category])
        return account

    # Common alternative spellings.
    topup = top_up
    add_quota = top_up
    add_budget = top_up
    refill = top_up
    grant_more = top_up

    def charge(self, object_id, category, amount):
        """Charge *amount* to *object_id* (``None`` means the shared pool)."""
        if object_id is None:
            account = self.root
        else:
            account = self.accounts.get(object_id, self.root)
        return account.charge(category, amount)

    spend = charge
    consume = charge

    def can_afford(self, object_id, category, amount):
        return self.account_for(object_id).can_afford(category, amount)

    def remaining_for(self, object_id, category=None):
        account = self.account_for(object_id)
        if category is None:
            return dict((name, account.remaining(name))
                        for name in CATEGORIES)
        return account.remaining(category)

    @property
    def usage(self):
        return self.used

    def snapshot(self):
        """Return a JSON-friendly snapshot of shared and per-object usage."""
        return {
            'limits': dict(self.limits),
            'used': self.used,
            'remaining': self.remaining,
            'objects': dict((object_id, account.snapshot())
                            for object_id, account in self.accounts.items()),
        }

    to_dict = snapshot

    def clone(self):
        """Return an independent copy, useful to compare or replay a scan."""
        return copy.deepcopy(self)

    def __repr__(self):
        return 'ScanBudget(limits={0!r}, objects={1!r})'\
            .format(self.limits, sorted(self.accounts))


#: Alternative name for callers that think in terms of a batch.
BatchBudget = ScanBudget
ProcessingBudget = ScanBudget
ObjectScanBudget = ScanBudget
Budget = ScanBudget


__all__ = [
    'ATTACHMENT',
    'ATTACHMENT_DECODING',
    'BatchBudget',
    'Budget',
    'BudgetAccount',
    'BudgetCategory',
    'BudgetError',
    'BudgetExhausted',
    'BudgetExceeded',
    'BudgetKind',
    'BudgetCategoryValue',
    'CATEGORIES',
    'CATEGORY_ALIASES',
    'CONTAINER',
    'CONTAINER_PARSE',
    'InsufficientBudget',
    'MACRO',
    'MACRO_EXTRACTION',
    'ObjectBudget',
    'ObjectProcessingBudget',
    'ObjectScanBudget',
    'ProcessingBudget',
    'ScanBudget',
    'normalize_categories',
    'normalize_category',
]
