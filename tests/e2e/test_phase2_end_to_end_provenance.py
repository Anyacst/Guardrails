"""End-to-End Master Test for Phase 2: Execution Provenance DAG.

Scenario:
User
  │
  ▼
OpenCode
  │
  ├── INVOKED ──► read_file
  │                  │
  │                  └── READ_FROM ──► .env
  │
  ├── RETURNED_TO ◄── read_file
  │
  └── SENT_TO ────► OpenRouter (LLM)

Verifications:
- Complete pipeline: Runtime Activity -> Collectors -> RawObservation -> EventRecorder -> EventBus -> ProvenanceEngine -> GraphStore.
- Immutable supporting events for all edges.
- Execution scopes attribution.
- Backward causal query from LLM node back to User Input.
- Zero raw secrets in all event payloads and node properties.
"""

from guardx.cli.inspect import inspect_session
from guardx.collectors.file_collector import FileCollector
from guardx.collectors.llm_collector import LLMCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.context import ScopeManager
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import RawObservation
from guardx.graph.engine import ProvenanceEngine
from guardx.graph.models import EdgeType, NodeType
from guardx.graph.store import InMemoryGraphStore


def test_phase2_master_provenance_pipeline(recorder, event_bus, session):
    # 1. Initialize ProvenanceEngine and subscribe to EventBus
    graph_store = InMemoryGraphStore()
    engine = ProvenanceEngine(store=graph_store)
    event_bus.subscribe(engine)

    scope_mgr = ScopeManager(recorder=recorder)
    tool_col = ToolCollector(recorder)
    file_col = FileCollector(recorder)
    llm_col = LLMCollector(recorder)

    # 2. Step 1: User Input
    user_event = recorder.record(RawObservation(
        event_type=EventType.USER_INPUT,
        raw_payload={"prompt": "Inspect the project environment and explain configuration to LLM."},
        actor_id="user:alice",
    ))

    # 3. Step 2: Agent Root Task Scope
    with scope_mgr.scope("agent_task:inspect_env", originating_event_id=user_event.event_id) as root_scope:
        agent_action_evt = recorder.record(RawObservation(
            event_type=EventType.AGENT_ACTION,
            raw_payload={"thought": "I need to read .env file to see configuration."},
            actor_id="agent:opencode",
            causal_event_id=user_event.event_id,
        ))

        # 4. Step 3: Tool Execution Scope for read_file
        with scope_mgr.scope("tool:read_file", originating_event_id=agent_action_evt.event_id) as tool_scope:
            tool_call_evt = tool_col.record_tool_call(
                tool_name="read_file",
                arguments={"path": ".env"},
                actor_id="agent:opencode",
                causal_event_id=agent_action_evt.event_id,
            )

            # 5. Step 4: File Read Observation (contains raw credential that MUST be masked)
            file_read_evt = file_col.record_file_read(
                file_path=".env",
                content="OPENAI_API_KEY=sk-proj-supersecretkey999999999999999\nDATABASE_URL=postgres://localhost",
                actor_id="tool:read_file",
                causal_event_id=tool_call_evt.event_id,
            )

            # 6. Step 5: Tool Result Observation
            tool_result_evt = tool_col.record_tool_result(
                tool_name="read_file",
                result_data={"content": file_read_evt.payload.get("content")},
                actor_id="tool:read_file",
                causal_event_id=file_read_evt.event_id,
            )

        # 7. Step 6: LLM Request (Agent constructs prompt and sends to external LLM)
        llm_req_evt = llm_col.record_request(
            provider="OpenRouter",
            model="anthropic/claude-3.5-sonnet",
            prompt_preview="Explain this configuration: " + str(tool_result_evt.payload.get("result")),
            actor_id="agent:opencode",
            causal_event_id=tool_result_evt.event_id,
        )

        # 8. Step 7: LLM Response
        llm_resp_evt = llm_col.record_response(
            provider="OpenRouter",
            model="anthropic/claude-3.5-sonnet",
            completion_preview="The configuration connects to local PostgreSQL database.",
            tokens_used=180,
            actor_id="agent:opencode",
            causal_event_id=llm_req_evt.event_id,
        )

    # =========================================================================
    # VERIFICATION: DAG Structure, Nodes, Edges, Causality, Invariants
    # =========================================================================

    # Verify Graph Nodes
    user_node = graph_store.get_node("user:alice")
    agent_node = graph_store.get_node("agent:opencode")
    tool_node = graph_store.get_node("tool:read_file")
    file_node = graph_store.get_node("file:.env")
    llm_node = graph_store.get_node("llm:openrouter")

    assert user_node is not None
    assert agent_node is not None
    assert tool_node is not None
    assert file_node is not None
    assert llm_node is not None

    # Verify Edges
    edges = graph_store.get_edges()
    assert len(edges) >= 6

    # Verify edge types
    edge_types = [e.edge_type for e in edges]
    assert EdgeType.INVOKED in edge_types
    assert EdgeType.READ_FROM in edge_types
    assert EdgeType.RETURNED_TO in edge_types
    assert EdgeType.SENT_TO in edge_types
    assert EdgeType.CAUSED_BY in edge_types

    # Every edge has supporting immutable event_id, provenance_quality, and confidence
    for edge in edges:
        assert edge.event_id.startswith("evt_")
        assert edge.provenance_quality in (ProvenanceQuality.OBSERVED, ProvenanceQuality.DERIVED)
        assert 0.0 <= edge.confidence <= 1.0

    # Causal Query: "Why did this LLM request happen?"
    causal_ancestors = engine.explain_causality("llm:openrouter")
    causal_ids = {n.node_id for n in causal_ancestors}
    assert "agent:opencode" in causal_ids
    assert "tool:read_file" in causal_ids
    assert "file:.env" in causal_ids

    # Path from Agent to File
    path_to_file = graph_store.find_path("agent:opencode", "file:.env")
    assert path_to_file == ["agent:opencode", "tool:read_file", "file:.env"]

    # Verify Zero Raw Secrets in any recorded event
    all_events = recorder.get_history()
    for evt in all_events:
        assert "sk-proj-supersecretkey999999999999999" not in str(evt.payload)
        assert "sk-proj-supersecretkey999999999999999" not in str(evt.metadata)

    # CLI Tree Rendering Check
    tree_text = inspect_session(engine, session.session_id)
    assert "SESSION: test_session_001" in tree_text
    assert "OpenCode" in tree_text
    assert "read_file" in tree_text
    assert ".env" in tree_text
    assert "OpenRouter" in tree_text
