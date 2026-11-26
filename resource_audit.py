#!/usr/bin/env python3
"""Compatibility naming for the resource range audit entry point."""

from pefile import (
    RESOURCE_RANGE_CANDIDATE,
    RESOURCE_RANGE_OUT_OF_RANGE,
    RESOURCE_RANGE_VERIFIED,
    ResourceRangeAuditor,
    ResourceRangeAuditReport,
    audit_exported_resource_ranges,
    audit_resource_copy_ranges,
    audit_resource_range,
    audit_resource_ranges,
    audit_resource_transfers,
    audit_resources,
    review_resource_ranges,
)
from resource_range_audit import (
    build_benign_resource_pair,
    build_tiny_resource_pe,
    main,
)

__all__ = [
    "RESOURCE_RANGE_CANDIDATE",
    "RESOURCE_RANGE_OUT_OF_RANGE",
    "RESOURCE_RANGE_VERIFIED",
    "ResourceRangeAuditReport",
    "ResourceRangeAuditor",
    "audit_exported_resource_ranges",
    "audit_resource_copy_ranges",
    "audit_resource_range",
    "audit_resource_ranges",
    "audit_resource_transfers",
    "audit_resources",
    "build_benign_resource_pair",
    "build_tiny_resource_pe",
    "main",
    "review_resource_ranges",
]
