from plyara.core import Plyara
from plyara.acceptance import (
    AcceptancePlan,
    AcceptancePlanner,
    AcceptanceSelector,
    CompliancePlanner,
    Evidence,
    OfflineAcceptancePlanner,
    Obligation,
    build_acceptance_plan,
    create_acceptance_plan,
    minimum_acceptance_plan,
    minimum_compliant_combination,
    offline_acceptance_plan,
    plan_acceptance,
    plan_offline_acceptance,
    select_acceptance_plan,
    select_minimum_acceptance,
    solve_acceptance,
)

__all__ = [
    'Plyara',
    'AcceptancePlan',
    'AcceptancePlanner',
    'AcceptanceSelector',
    'CompliancePlanner',
    'Evidence',
    'Obligation',
    'OfflineAcceptancePlanner',
    'build_acceptance_plan',
    'create_acceptance_plan',
    'minimum_acceptance_plan',
    'minimum_compliant_combination',
    'offline_acceptance_plan',
    'plan_acceptance',
    'plan_offline_acceptance',
    'select_acceptance_plan',
    'select_minimum_acceptance',
    'solve_acceptance',
]


def __getattr__(name):
    """Resolve additional acceptance-planning aliases lazily."""
    from plyara import acceptance

    if hasattr(acceptance, name):
        return getattr(acceptance, name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
