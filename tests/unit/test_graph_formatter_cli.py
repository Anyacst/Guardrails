"""Unit tests for GraphFormatter and CLI inspection utilities."""

import json
from guardx.cli.inspect import inspect_session
from guardx.graph.formatter import GraphFormatter
from guardx.graph.models import EdgeType, ExecutionGraph, GraphEdge, GraphNode, NodeType


def test_graph_formatter_tree_and_json():
    n1 = GraphNode(node_id="agent:opencode", node_type=NodeType.AGENT, label="OpenCode", session_id="s1")
    n2 = GraphNode(node_id="tool:read_file", node_type=NodeType.TOOL, label="read_file", session_id="s1")
    n3 = GraphNode(node_id="file:.env", node_type=NodeType.FILE, label=".env", session_id="s1")

    e1 = GraphEdge(edge_id="e1", source_id="agent:opencode", target_id="tool:read_file", edge_type=EdgeType.INVOKED, event_id="evt_1")
    e2 = GraphEdge(edge_id="e2", source_id="tool:read_file", target_id="file:.env", edge_type=EdgeType.READ_FROM, event_id="evt_2")

    graph = ExecutionGraph(session_id="s1", nodes=[n1, n2, n3], edges=[e1, e2])

    # 1. ASCII Tree formatting
    tree_output = GraphFormatter.to_tree(graph)
    assert "SESSION: s1" in tree_output
    assert "OpenCode" in tree_output
    assert "INVOKED → read_file" in tree_output
    assert "READ_FROM → .env" in tree_output

    # 2. JSON Export
    json_output = GraphFormatter.to_json(graph)
    parsed = json.loads(json_output)
    assert parsed["session_id"] == "s1"
    assert len(parsed["nodes"]) == 3
    assert len(parsed["edges"]) == 2
