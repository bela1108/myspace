from pathlib import Path

import pytest

from pip_audit._remediation.depgraph import BASE_GROUP, DependencyGraph
from pip_audit._remediation.lockplan import load_lock_plan

ASSETS = Path(__file__).parent.parent / "assets" / "remediation"


@pytest.fixture()
def before_graph():
    return DependencyGraph(load_lock_plan(ASSETS / "pylock.before.toml"))


class TestDependencyGraph:
    def test_base_roots_exclude_group_members(self, before_graph):
        roots = before_graph.group_roots(BASE_GROUP)
        assert "appcore" in roots
        assert "plugintool" not in roots

    def test_group_roots(self, before_graph):
        assert before_graph.group_roots("plugins") == frozenset({"plugintool"})

    def test_reachable_from_base(self, before_graph):
        reachable = before_graph.reachable_from(before_graph.group_roots(BASE_GROUP))
        assert {"appcore", "vulnchain", "troublemaker", "markerlib"} <= reachable
        assert "plugintool" not in reachable

    def test_enumerates_two_chains_for_multi_path_package(self, before_graph):
        chains = before_graph.chains_to(before_graph.group_roots(BASE_GROUP), "legacylib")
        paths = [chain.packages for chain in chains]
        assert ("appcore", "basesettings", "legacylib") in paths
        assert ("appcore", "sharedutils", "legacylib") in paths
        assert all(not chain.marker_gated for chain in chains)

    def test_marker_gated_chain_is_flagged(self, before_graph):
        chains = before_graph.chains_to(before_graph.group_roots(BASE_GROUP), "markerlib")
        assert len(chains) == 1
        assert chains[0].marker_gated is True

    def test_unknown_target_returns_no_chains(self, before_graph):
        assert before_graph.chains_to(before_graph.group_roots(BASE_GROUP), "does-not-exist") == []

    def test_group_isolated_from_base(self, before_graph):
        chains = before_graph.chains_to(before_graph.group_roots("plugins"), "vulnchain")
        assert [chain.packages for chain in chains] == [("plugintool", "vulnchain")]

    def test_groups_include_base_first(self, before_graph):
        groups = before_graph.groups()
        assert groups[0] == BASE_GROUP
        assert "plugins" in groups
