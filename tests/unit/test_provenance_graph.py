"""Unit tests for GraphStore and ProvenanceEngine."""

from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import RawObservation
from guardx.graph.engine import ProvenanceEngine
from guardx.graph.models import EdgeType, GraphEdge, GraphNode, NodeType
from guardx.graph.store import InMemoryGraphStore


def test_in_memory_graph_store_operations():
    store = InMemoryGraphStore()

    n1 = GraphNode(node_id="agent:opencode", node_type=NodeType.AGENT, label="OpenCode", session_id="s1")
    n2 = GraphNode(node_id="tool:read_file", node_type=NodeType.TOOL, label="read_file", session_id="s1")
    n3 = GraphNode(node_id="file:.env", node_type=NodeType.FILE, label="file:.env", session_id="s1")

    store.add_node(n1)
    store.add_node(n2)
    store.add_node(n3)

    # Duplicate node addition (idempotent merge)
    n1_dup = GraphNode(node_id="agent:opencode", node_type=NodeType.AGENT, label="OpenCode", session_id="s1", properties={"version": "1.0"})
    store.add_node(n1_dup)

    assert len(store.get_nodes()) == 3
    assert store.get_node("agent:opencode").properties.get("version") == "1.0"

    e1 = GraphEdge(
        edge_id="e1",
        source_id="agent:opencode",
        target_id="tool:read_file",
        edge_type=EdgeType.INVOKED,
        event_id="evt_1",
        provenance_quality=ProvenanceQuality.OBSERVED,
    )
    e2 = GraphEdge(
        edge_id="e2",
        source_id="tool:read_file",
        target_id="file:.env",
        edge_type=EdgeType.READ_FROM,
        event_id="evt_2",
        provenance_quality=ProvenanceQuality.OBSERVED,
    )

    store.add_edge(e1)
    store.add_edge(e2)

    # Verify query by source / target
    assert len(store.get_edges(source_id="agent:opencode")) == 1
    assert len(store.get_edges(target_id="file:.env")) == 1

    # Verify ancestors and descendants
    ancestors = store.get_ancestors("file:.env")
    assert ancestors == {"agent:opencode", "tool:read_file"}

    descendants = store.get_descendants("agent:opencode")
    assert descendants == {"tool:read_file", "file:.env"}

    # Path finding
    path = store.find_path("agent:opencode", "file:.env")
    assert path == ["agent:opencode", "tool:read_file", "file:.env"]


def test_provenance_engine_event_projection(recorder, event_bus):
    store = InMemoryGraphStore()
    engine = ProvenanceEngine(store=store)
    event_bus.subscribe(engine)

    # 1. Open a tool call observation
    tool_evt = recorder.record(RawObservation(
        event_type=EventType.TOOL_CALL,
        raw_payload={"tool_name": "read_file"},
        actor_id="agent:opencode",
    ))

    # 2. File read observation
    file_evt = recorder.record(RawObservation(
        event_type=EventType.FILE_READ,
        raw_payload={"path": ".env"},
        actor_id="tool:read_file",
        source_raw=".env",
        causal_event_id=tool_evt.event_id,
    ))

    # Provenance engine should have automatically created nodes and edges
    agent_node = store.get_node("agent:opencode")
    tool_node = store.get_node("tool:read_file")
    file_node = store.get_node("file:.env")

    assert agent_node is not None
    assert tool_node is not None
    assert file_node is not None

    edges = store.get_edges()
    edge_types = [e.edge_type for e in edges]
    assert EdgeType.INVOKED in edge_types
    assert EdgeType.READ_FROM in edge_types
    assert EdgeType.CAUSED_BY in edge_types
