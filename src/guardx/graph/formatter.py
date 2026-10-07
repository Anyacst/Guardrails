"""Graph Formatter & Exporter for CLI Inspection and GUI Contract.

Guarantees:
- Formats Execution Provenance DAG into human-readable ASCII trees.
- Serializes ExecutionGraph into standard JSON matching frontend GUI contract.
"""

from collections import defaultdict
import json
from typing import Dict, List, Set
from guardx.graph.models import ExecutionGraph, GraphEdge, GraphNode


class GraphFormatter:
    """Formats ExecutionGraph into ASCII tree or JSON."""

    @staticmethod
    def to_json(graph: ExecutionGraph, indent: int = 2) -> str:
        """Serializes graph to JSON for frontend/backend contract."""
        return json.dumps(graph.to_dict(), indent=indent)

    @staticmethod
    def to_tree(graph: ExecutionGraph) -> str:
        """Renders an ASCII execution provenance tree."""
        lines = [f"SESSION: {graph.session_id}", ""]
        if not graph.nodes:
            lines.append("  (Empty Graph)")
            return "\n".join(lines)

        # Build adjacency maps
        outgoing: Dict[str, List[GraphEdge]] = defaultdict(list)
        incoming_count: Dict[str, int] = defaultdict(int)

        for edge in graph.edges:
            # Exclude BELONGS_TO_SCOPE from primary hierarchy tree for clean readability
            if edge.edge_type.value == "BELONGS_TO_SCOPE":
                continue
            outgoing[edge.source_id].append(edge)
            incoming_count[edge.target_id] += 1

        node_map = {n.node_id: n for n in graph.nodes}

        # Root nodes have 0 incoming execution edges (excluding scopes)
        roots = [
            nid for nid in node_map
            if incoming_count[nid] == 0 and not nid.startswith("scope:")
        ]
        if not roots:
            roots = [n.node_id for n in graph.nodes if not n.node_id.startswith("scope:")]

        visited: Set[str] = set()

        def render_subtree(nid: str, prefix: str = "", is_last: bool = True):
            node = node_map.get(nid)
            label = node.label if node else nid
            node_type = node.node_type.value if node else "NODE"
            branch = "└── " if is_last else "├── "
            lines.append(f"{prefix}{branch}{label} [{node_type}]")

            child_prefix = prefix + ("    " if is_last else "│   ")
            edges = outgoing.get(nid, [])

            for idx, edge in enumerate(edges):
                edge_is_last = (idx == len(edges) - 1)
                edge_branch = "└── " if edge_is_last else "├── "
                target_node = node_map.get(edge.target_id)
                target_name = target_node.label if target_node else edge.target_id
                lines.append(f"{child_prefix}{edge_branch}[{edge.edge_type.value}] → {target_name}")

                # Recurse into children of target if target has outgoing edges and not visited
                next_prefix = child_prefix + ("    " if edge_is_last else "│   ")
                sub_edges = outgoing.get(edge.target_id, [])
                for s_idx, s_edge in enumerate(sub_edges):
                    s_is_last = (s_idx == len(sub_edges) - 1)
                    s_branch = "└── " if s_is_last else "├── "
                    s_target = node_map.get(s_edge.target_id)
                    s_name = s_target.label if s_target else s_edge.target_id
                    lines.append(f"{next_prefix}{s_branch}[{s_edge.edge_type.value}] → {s_name}")

        for root_id in roots:
            if root_id in visited:
                continue
            root_node = node_map.get(root_id)
            root_label = root_node.label if root_node else root_id
            lines.append(f"● {root_label} [{root_node.node_type.value if root_node else 'NODE'}]")

            edges = outgoing.get(root_id, [])
            for idx, edge in enumerate(edges):
                is_last = (idx == len(edges) - 1)
                branch = "└── " if is_last else "├── "
                target_node = node_map.get(edge.target_id)
                target_name = target_node.label if target_node else edge.target_id
                lines.append(f"  {branch}{edge.edge_type.value} → {target_name}")

                sub_prefix = "      " if is_last else "  │   "
                sub_edges = outgoing.get(edge.target_id, [])
                for s_idx, s_edge in enumerate(sub_edges):
                    s_last = (s_idx == len(sub_edges) - 1)
                    s_branch = "└── " if s_last else "├── "
                    s_target = node_map.get(s_edge.target_id)
                    s_name = s_target.label if s_target else s_edge.target_id
                    lines.append(f"{sub_prefix}{s_branch}{s_edge.edge_type.value} → {s_name}")

                    # Render third level (e.g. read_file -> READ_FROM -> .env)
                    third_prefix = sub_prefix + ("      " if s_last else "  │   ")
                    third_edges = outgoing.get(s_edge.target_id, [])
                    for t_idx, t_edge in enumerate(third_edges):
                        t_last = (t_idx == len(third_edges) - 1)
                        t_branch = "└── " if t_last else "├── "
                        t_target = node_map.get(t_edge.target_id)
                        t_name = t_target.label if t_target else t_edge.target_id
                        lines.append(f"{third_prefix}{t_branch}{t_edge.edge_type.value} → {t_name}")

            visited.add(root_id)

        return "\n".join(lines)
