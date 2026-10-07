"""End-to-End Test for Milestone 2 Live Investigation Console.

Validates the complete execution provenance pipeline:
OpenCode action → RawObservation → EventRecorder → EventBus → ProvenanceEngine → WebSocket stream

Also enforces the critical semantic invariant:
OpenCode reading .env followed by calling OpenRouter must NOT create a .env -> OpenRouter edge.
Execution relationship != Data Flow.
"""

import pytest
from fastapi.testclient import TestClient

from guardx.adapters.opencode_adapter import OpenCodeGuardXAdapter
from guardx.collectors.file_collector import FileCollector
from guardx.collectors.llm_collector import LLMCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import RawObservation
from guardx.server.app import create_app
from guardx.server.session_registry import global_session_registry


@pytest.fixture
def client():
    global_session_registry.clear()
    app = create_app()
    return TestClient(app)


def test_e2e_opencode_live_investigation_stream_and_graph(client):
    """End-to-End test of the complete pipeline from agent execution to WebSocket delivery and graph verification."""
    session_id = "opencode_live_session"
    ctx = global_session_registry.get_session(session_id)
    assert ctx is not None

    recorder = ctx.recorder
    scope_mgr = ctx.scope_manager
    tool_col = ToolCollector(recorder)
    file_col = FileCollector(recorder)
    llm_col = LLMCollector(recorder)

    received_messages = []

    with client.websocket_connect(f"/ws/sessions/{session_id}") as ws:
        # 1. Receive initial snapshot
        snapshot = ws.receive_json()
        assert snapshot["type"] == "session.snapshot"
        assert snapshot["session_id"] == session_id

        # 2. OpenCode Step 1: User prompt
        user_evt = recorder.record(RawObservation(
            event_type=EventType.USER_INPUT,
            raw_payload={"prompt": "Inspect the repository .env and prepare summary for remote LLM."},
            actor_id="user:alice",
        ))

        # 3. OpenCode Step 2: Tool execution in task scope
        with scope_mgr.scope("agent_task:inspect_env", originating_event_id=user_evt.event_id) as task_scope:
            action_evt = recorder.record(RawObservation(
                event_type=EventType.AGENT_ACTION,
                raw_payload={"thought": "Calling agentguard_read on .env configuration"},
                actor_id="agent:opencode",
                causal_event_id=user_evt.event_id,
            ))

            with scope_mgr.scope("tool:agentguard_read", originating_event_id=action_evt.event_id) as tool_scope:
                tool_call = tool_col.record_tool_call(
                    tool_name="agentguard_read",
                    arguments={"path": ".env"},
                    actor_id="agent:opencode",
                    causal_event_id=action_evt.event_id,
                )
                file_read = file_col.record_file_read(
                    file_path=".env",
                    content="OPENAI_API_KEY=sk-proj-999999999999999999999999\nDEBUG=true\n",
                    actor_id="tool:agentguard_read",
                    causal_event_id=tool_call.event_id,
                )
                tool_result = tool_col.record_tool_result(
                    tool_name="agentguard_read",
                    result_data={"content": file_read.payload.get("content")},
                    actor_id="tool:agentguard_read",
                    causal_event_id=file_read.event_id,
                )

        # 4. OpenCode Step 3: Call remote LLM
        llm_req = llm_col.record_request(
            provider="OpenRouter",
            model="anthropic/claude-3.5-sonnet",
            prompt_preview="Explain configuration: [MASKED_OPENAI_KEY_001_8a041e4b] with DEBUG=true",
            actor_id="agent:opencode",
            causal_event_id=tool_result.event_id,
        )
        llm_resp = llm_col.record_response(
            provider="OpenRouter",
            model="anthropic/claude-3.5-sonnet",
            completion_preview="The configuration enables debugging and defines OpenAI API connectivity.",
            tokens_used=145,
            actor_id="agent:opencode",
            causal_event_id=llm_req.event_id,
        )

        # 5. Drain WebSocket messages
        # Read available messages until LLM response is received
        found_llm_event = False
        while not found_llm_event:
            msg = ws.receive_json()
            received_messages.append(msg)
            if msg["type"] == "event.created" and msg["data"]["event_id"] == llm_resp.event_id:
                found_llm_event = True

    # 6. Verify WebSocket message types and sequence
    event_messages = [m for m in received_messages if m["type"] == "event.created"]
    node_messages = [m for m in received_messages if m["type"] == "node.created"]
    edge_messages = [m for m in received_messages if m["type"] == "edge.created"]

    assert len(event_messages) >= 8
    assert len(node_messages) >= 4
    assert len(edge_messages) >= 4

    # Verify monotonic sequence ordering across all received events
    sequences = [m["data"]["sequence_number"] for m in event_messages]
    assert sequences == sorted(sequences)

    # 7. Query Session Graph via REST endpoint
    graph_res = client.get(f"/api/sessions/{session_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()

    nodes = {n["node_id"]: n for n in graph_data["nodes"]}
    edges = graph_data["edges"]

    # Verify essential nodes exist
    assert "agent:opencode" in nodes
    assert "tool:agentguard_read" in nodes
    assert "file:.env" in nodes
    assert "llm:openrouter" in nodes

    # Verify execution edges
    edge_pairs = {(e["source_id"], e["target_id"], e["edge_type"]) for e in edges}

    # OpenCode -> agentguard_read (INVOKED)
    assert ("agent:opencode", "tool:agentguard_read", "INVOKED") in edge_pairs

    # agentguard_read -> .env (READ_FROM)
    assert ("tool:agentguard_read", "file:.env", "READ_FROM") in edge_pairs

    # agentguard_read -> OpenCode (RETURNED_TO)
    assert ("tool:agentguard_read", "agent:opencode", "RETURNED_TO") in edge_pairs

    # OpenCode -> OpenRouter (SENT_TO)
    assert ("agent:opencode", "llm:openrouter", "SENT_TO") in edge_pairs

    # 8. CRITICAL SEMANTIC DISTINCTION:
    # Must NOT contain a direct data flow edge from file:.env to llm:openrouter
    for edge in edges:
        assert not (edge["source_id"] == "file:.env" and edge["target_id"] == "llm:openrouter"), (
            "CRITICAL VIOLATION: Execution DAG must not claim data flow from .env to OpenRouter!"
        )

    # 9. Verify Evidence Invariants
    for edge in edges:
        assert edge["event_id"] is not None
        assert edge["provenance_quality"] in ["OBSERVED", "DERIVED", "INFERRED"]
        assert 0.0 <= edge["confidence"] <= 1.0

    # 10. Verify Zero Raw Secrets in Graph and Events
    raw_graph_str = graph_res.text
    assert "sk-proj-999999999999999999999999" not in raw_graph_str

    events_res = client.get(f"/api/sessions/{session_id}/events")
    raw_events_str = events_res.text
    assert "sk-proj-999999999999999999999999" not in raw_events_str
    assert "[MASKED_OPENAI_KEY_" in raw_events_str
