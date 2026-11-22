"""
Reference-only comparison of probe samples against a historical baseline.

A probe manifest may not have existed when an older baseline was produced, so the
baseline has no probe annotations to trust. We can still *look up* each sample in
the baseline by its stable identity (sample file + content hash) and display which
plugins flagged it back then. This never feeds the release verdict: only a freshly
verified probe run can do that.
"""
from typing import Any
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

from ..audit.common import get_baseline_from_file
from ..core.potential_secret import PotentialSecret
from .manifest import TestSample


def compare_against_baseline(
    samples: List[TestSample],
    baseline_filename: str,
) -> Dict[str, Any]:
    collection = get_baseline_from_file(baseline_filename)
    indexed = _index_baseline_secrets(collection)

    results = []
    for sample in samples:
        key = (sample.filename, PotentialSecret.hash_secret(sample.content))
        observed_types = sorted(indexed.get(key, set()))
        results.append(
            {
                'id': sample.id,
                'filename': sample.filename,
                'expected-plugins': sorted(sample.expected_plugins),
                'baseline-plugins': observed_types,
                'found-in-baseline': bool(observed_types),
            },
        )

    return {
        'baseline': baseline_filename,
        'reference-only': True,
        'samples': results,
    }


def _index_baseline_secrets(collection: Any) -> Dict[Tuple[str, str], Set[str]]:
    indexed: Dict[Tuple[str, str], Set[str]] = {}
    for filename in collection.files:
        for secret in collection.data[filename]:
            indexed.setdefault(
                (filename, secret.secret_hash),
                set(),
            ).add(secret.type)

    return indexed
