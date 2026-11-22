"""
A probe manifest declares the *expected* contribution of a fixed set of test
samples. Every sample carries a stable identity so that fresh probe runs can be
compared against historical baselines, and names the plugins that are supposed
to (and not supposed to) flag it.

Manifest schema (JSON)::

    {
      "samples": [
        {
          "id": "alpha-only-marker",
          "value": "alpha-marker-value",
          "expected_plugins": ["AlphaTestDetector"]
        }
      ]
    }

expected_plugins is the authoritative per-plugin accounting: a plugin named
there must detect the sample (its own positive, or a shared positive when more
than one plugin is named), while every other enabled plugin must ignore it (a
negative it is expected to leave alone).
"""
import json
from typing import Any
from typing import Dict
from typing import List

from ..exceptions import InvalidFile


class TestSample:
    __test__ = False

    def __init__(
        self,
        id: str,
        value: str,
        expected_plugins: List[str],
        filename: str = None,
    ) -> None:
        self.id = id
        self.value = value
        self.expected_plugins = set(expected_plugins)
        self.filename = filename or f'probe-samples/{id}'

    @property
    def content(self) -> str:
        return self.value

    @classmethod
    def load_from_dict(cls, data: Dict[str, Any]) -> 'TestSample':
        try:
            expected_plugins = data['expected_plugins']
            if isinstance(expected_plugins, str):
                expected_plugins = [expected_plugins]

            sample = cls(
                id=str(data['id']),
                value=str(data['value']),
                expected_plugins=[str(name) for name in expected_plugins],
                filename=str(data['filename']) if data.get('filename') else None,
            )
        except (KeyError, TypeError) as exc:
            raise InvalidFile(f'Invalid probe sample: {data}') from exc

        if not sample.id or not sample.expected_plugins:
            raise InvalidFile(f'Invalid probe sample: {data}')

        return sample

    def is_negative_for(self, plugin_name: str) -> bool:
        return plugin_name not in self.expected_plugins

    def json(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'filename': self.filename,
            'value': self.value,
            'expected_plugins': sorted(self.expected_plugins),
        }


class ProbeManifest:
    def __init__(self, samples: List[TestSample] = None) -> None:
        self.samples: List[TestSample] = samples or []

    @classmethod
    def load_from_file(cls, filename: str) -> 'ProbeManifest':
        try:
            with open(filename) as file_handle:
                payload = json.load(file_handle)
        except (IOError, OSError, json.decoder.JSONDecodeError) as exc:
            raise InvalidFile(
                f'Unable to read probe manifest: {filename}',
            ) from exc

        if not isinstance(payload, dict) or 'samples' not in payload:
            raise InvalidFile(f'Invalid probe manifest: {filename}')

        samples = [
            TestSample.load_from_dict(sample)
            for sample in payload['samples']
        ]
        ids = [sample.id for sample in samples]
        if len(ids) != len(set(ids)):
            raise InvalidFile(
                f'Duplicate sample ids in probe manifest: {filename}',
            )

        return cls(samples)

    def get_sample(self, sample_id: str) -> TestSample:
        for sample in self.samples:
            if sample.id == sample_id:
                return sample

        raise KeyError(sample_id)

    def json(self) -> Dict[str, Any]:
        return {
            'samples': [sample.json() for sample in self.samples],
        }
