# SPDX-License-Identifier: Apache-2.0

"""Short compatibility alias for :mod:`in_toto.reviewlib`."""

from in_toto.reviewlib import *  # noqa: F403
from in_toto.reviewlib import (
    ApprovalManifest,
    CredentialReviewer,
    ReviewFinding,
    ReviewReport,
    load_approval_manifest,
    review_layout,
    review_link,
    review_links,
    review_summary_link,
)
