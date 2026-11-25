"""Version-bound finite proof trees for small case files."""

from enum import Enum


class ReviewStatus(str, Enum):
    REEXAMINE_REQUIRED = "must_reexamine"
    INDEPENDENTLY_SUPPORTED = "independently_supported"
    UNKNOWN_SOURCE = "unknown_source"


class EdgeType(str, Enum):
    SUPPORTS = "supports"
    COPIED_FROM = "copied_from"


def build_versioned_proof_tree(case_file):
    """Build a finite proof tree and classify every version-bound claim.

    A ``supports`` edge contributes proof. A ``copied_from`` edge only records
    provenance; copied material is never treated as independent support.
    """
    nodes, versioned_nodes = _index_nodes(case_file.get("nodes", []))
    edges = case_file.get("edges", [])
    outgoing_support = {node_id: [] for node_id in nodes}
    outgoing_copies = {node_id: [] for node_id in nodes}

    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        _require_node(source, nodes)
        _require_node(target, nodes)
        edge_type = EdgeType(edge.get("type", EdgeType.SUPPORTS))
        if edge_type == EdgeType.SUPPORTS:
            outgoing_support[target].append(source)
        else:
            outgoing_copies[target].append(source)

    classifications = {}
    for node_id, node in nodes.items():
        classifications[node_id] = _classify(
            node_id,
            nodes,
            outgoing_support,
            outgoing_copies,
            set(),
        )

    return {
        "nodes": [
            _node_view(node, classifications[node["id"]], outgoing_copies)
            for node in case_file.get("nodes", [])
        ],
        "edges": list(edges),
        "paths": _build_paths(
            case_file,
            nodes,
            versioned_nodes,
            outgoing_support,
            outgoing_copies,
            classifications,
        ),
    }


def _index_nodes(raw_nodes):
    nodes = {}
    for raw_node in raw_nodes:
        node = dict(raw_node)
        node_id = node["id"]
        if node_id in nodes:
            raise ValueError("Duplicate node id: {0}".format(node_id))
        nodes[node_id] = node
    return nodes


def _require_node(node_id, nodes):
    if node_id not in nodes:
        raise ValueError("Unknown node id: {0}".format(node_id))


def _classify(node_id, nodes, support_edges, copy_edges, active):
    if node_id in active:
        raise ValueError("Proof trees cannot contain cycles: {0}".format(node_id))

    node = nodes[node_id]
    if node.get("kind") == "evidence":
        if node.get("status") == "corrected":
            return ReviewStatus.REEXAMINE_REQUIRED
        if node.get("status") == "independent":
            return ReviewStatus.INDEPENDENTLY_SUPPORTED
        return ReviewStatus.UNKNOWN_SOURCE

    supports = support_edges.get(node_id, [])
    if not supports:
        return ReviewStatus.UNKNOWN_SOURCE

    next_active = active | {node_id}
    child_statuses = [
        _classify(support_id, nodes, support_edges, copy_edges, next_active)
        for support_id in supports
    ]

    if ReviewStatus.INDEPENDENTLY_SUPPORTED in child_statuses:
        return ReviewStatus.INDEPENDENTLY_SUPPORTED
    if ReviewStatus.REEXAMINE_REQUIRED in child_statuses:
        return ReviewStatus.REEXAMINE_REQUIRED
    return ReviewStatus.UNKNOWN_SOURCE


def _node_view(node, status, copy_edges):
    view = dict(node)
    view["version"] = node["version"]
    view["review_status"] = status.value
    view["copied_from"] = list(copy_edges.get(node["id"], []))
    return view


def _build_paths(case_file, nodes, support_edges, copy_edges, classifications):
    paths = {}
    for path in case_file.get("paths", []):
        claim_id = path["claim_id"]
        before_version = path["before_version"]
        after_version = path["after_version"]
        _require_node(claim_id, nodes)
        paths[claim_id] = {
            "before_correction": _path_view(
                claim_id,
                before_version,
                nodes,
                support_edges,
                copy_edges,
                classifications,
            ),
            "after_correction": _path_view(
                claim_id,
                after_version,
                nodes,
                support_edges,
                copy_edges,
                classifications,
            ),
        }
    return paths


def _path_view(claim_id, version, nodes, support_edges, copy_edges, classifications):
    versioned_claim_id = _versioned_id(claim_id, version, nodes)
    return {
        "node_id": versioned_claim_id,
        "version": version,
        "review_status": classifications[versioned_claim_id].value,
        "support_path": _support_path(
            versioned_claim_id,
            nodes,
            support_edges,
            set(),
        ),
        "copy_chain": _copy_chain(versioned_claim_id, copy_edges, nodes),
    }


def _versioned_id(claim_id, version, nodes):
    versioned_id = "{0}@{1}".format(claim_id, version)
    if versioned_id in nodes:
        return versioned_id
    if claim_id not in nodes:
        raise ValueError("Unknown node id: {0}".format(claim_id))
    return claim_id


def _support_path(node_id, nodes, support_edges, active):
    if node_id in active:
        raise ValueError("Proof trees cannot contain cycles: {0}".format(node_id))
    supports = support_edges.get(node_id, [])
    if not supports:
        return [node_id]
    next_active = active | {node_id}
    return [
        node_id,
        _support_path(supports[0], nodes, support_edges, next_active),
    ]


def _copy_chain(node_id, copy_edges, nodes):
    chain = []
    current = node_id
    seen = set()
    while copy_edges.get(current):
        if current in seen:
            raise ValueError("Copy chains cannot contain cycles: {0}".format(current))
        seen.add(current)
        current = copy_edges[current][0]
        _require_node(current, nodes)
        chain.append(current)
    return chain
