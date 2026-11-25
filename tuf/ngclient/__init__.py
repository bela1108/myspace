# Copyright 2021-2025, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client public API."""

from tuf.api.metadata import TargetFile
from tuf.ngclient.combination import (
    ClientDownloadState,
    CombinationConflict,
    CombinationConflictError,
    CombinationError,
    CombinationPlan,
    CombinationPreflight,
    CombinationResult,
    Dependency,
    DependencyEdge,
    DependencyRequirement,
    InterfaceDeclaration,
    ModuleDeclaration,
    Requirement,
    TargetCandidate,
    TargetIdentity,
    VersionConstraint,
    check_combination,
    check_target_combination,
    combination_preflight,
    plan_target_combination,
    preflight_combination,
    preflight_target_combination,
    preflight_targets,
    resolve_combination,
    resolve_target_closure,
    resolve_target_combination,
)
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface
from tuf.ngclient.updater import Updater
from tuf.ngclient.urllib3_fetcher import Urllib3Fetcher

__all__ = [  # noqa: PLE0604
    ClientDownloadState.__name__,
    CombinationConflict.__name__,
    CombinationConflictError.__name__,
    CombinationError.__name__,
    CombinationPlan.__name__,
    CombinationPreflight.__name__,
    CombinationResult.__name__,
    Dependency.__name__,
    DependencyEdge.__name__,
    DependencyRequirement.__name__,
    FetcherInterface.__name__,
    InterfaceDeclaration.__name__,
    ModuleDeclaration.__name__,
    Requirement.__name__,
    TargetCandidate.__name__,
    TargetFile.__name__,
    TargetIdentity.__name__,
    Updater.__name__,
    UpdaterConfig.__name__,
    Urllib3Fetcher.__name__,
    VersionConstraint.__name__,
    check_combination.__name__,
    check_target_combination.__name__,
    combination_preflight.__name__,
    plan_target_combination.__name__,
    preflight_combination.__name__,
    preflight_target_combination.__name__,
    preflight_targets.__name__,
    resolve_combination.__name__,
    resolve_target_combination.__name__,
    resolve_target_closure.__name__,
]
