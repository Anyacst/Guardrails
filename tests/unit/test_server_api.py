"""Unit tests for GuardX FastAPI REST Endpoints.

Tests:
- GET /api/sessions
- GET /api/sessions/{session_id}
- GET /api/sessions/{session_id}/events
- GET /api/sessions/{session_id}/graph
- GET /api/sessions/{session_id}/scopes
- GET /api/events/{event_id}
- GET /api/nodes/{node_id}
- Graph and Event serialization contracts
- Session isolation
- Safe payload guarantees (no raw secrets exposed in REST)
"""

import pytest
from fastapi.testclient import TestClient

from guardx.collectors.file_collector import FileCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.enums import EventType
from guardx.core.models import RawObservation
from guardx.server.app import create_app
from guardx.server.session_registry import global_session_registry


@pytest.fixture
def client():
    """Provides a TestClient with a fresh session registry."""
    global_session_registry.clear()
    app = create_app()
    return TestClient(app)


def test_list_sessions_endpoint(client):
    """Verifies GET /api/sessions returns active sessions with correct stats."""
    response = client.get("/api/sessions")
    assert response.status_code == 200
    sessions = response.json()
    assert isinstance(sessions, list)
    assert len(sessions) >= 1

    # Default session check
    default_session = next((s for s in sessions if s["session_id"] == "opencode_live_session"), None)
    assert default_session is not None
    assert default_session["agent_name"] == "OpenCode"
    assert "event_count" in default_session
    assert "node_count" in default_session


def test_get_session_details_endpoint(client):
    """Verifies GET /api/sessions/{session_id} returns detailed metadata and stats."""
    response = client.get("/api/sessions/opencode_live_session")
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == "opencode_live_session"
    assert data["agent_name"] == "OpenCode"
    assert "stats" in data
    assert data["stats"]["total_events"] == 0

    # Non-existent session 404
    err_resp = client.get("/api/sessions/non_existent_session_id")
    assert err_resp.status_code == 404


def test_get_session_events_and_serialization(client):
    """Verifies GET /api/sessions/{session_id}/events returns ordered serialized GuardXEvents."""
    ctx = global_session_registry.get_session("opencode_live_session")
    recorder = ctx.recorder

    evt1 = recorder.record(RawObservation(
        event_type=EventType.USER_INPUT,
        raw_payload={"query": "List files in directory"},
        actor_id="user:alice",
    ))
    evt2 = recorder.record(RawObservation(
        event_type=EventType.AGENT_ACTION,
        raw_payload={"thought": "Executing list tool"},
        actor_id="agent:opencode",
        causal_event_id=evt1.event_id,
    ))

    response = client.get("/api/sessions/opencode_live_session/events")
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 2

    # Verify chronological sequence_number ordering
    assert events[0]["sequence_number"] == 1
    assert events[0]["event_id"] == evt1.event_id
    assert events[0]["event_type"] == "USER_INPUT"
    assert events[0]["actor_id"] == "user:alice"
    assert events[0]["provenance_quality"] == "OBSERVED"
    assert events[0]["confidence"] == 1.0

    assert events[1]["sequence_number"] == 2
    assert events[1]["event_id"] == evt2.event_id
    assert events[1]["causal_event_id"] == evt1.event_id


def test_get_session_graph_serialization_contract(client):
    """Verifies GET /api/sessions/{session_id}/graph preserves all node and edge contract fields."""
    ctx = global_session_registry.get_session("opencode_live_session")
    tool_col = ToolCollector(ctx.recorder)
    tool_col.record_tool_call(
        tool_name="read_file",
        arguments={"path": "main.py"},
        actor_id="agent:opencode",
    )

    response = client.get("/api/sessions/opencode_live_session/graph")
    assert response.status_code == 200
    graph = response.json()

    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) >= 2
    assert len(graph["edges"]) >= 1

    # Node contract validation
    agent_node = next((n for n in graph["nodes"] if n["node_type"] == "AGENT"), None)
    assert agent_node is not None
    assert agent_node["node_id"] == "agent:opencode"
    assert agent_node["label"] == "OpenCode"
    assert agent_node["session_id"] == "opencode_live_session"
    assert isinstance(agent_node["properties"], dict)

    # Edge contract validation
    invoked_edge = next((e for e in graph["edges"] if e["edge_type"] == "INVOKED"), None)
    assert invoked_edge is not None
    assert invoked_edge["source_id"] == "agent:opencode"
    assert invoked_edge["target_id"] == "tool:read_file"
    assert "event_id" in invoked_edge
    assert invoked_edge["provenance_quality"] == "OBSERVED"
    assert invoked_edge["confidence"] == 1.0


def test_get_session_scopes_endpoint(client):
    """Verifies GET /api/sessions/{session_id}/scopes returns hierarchical ExecutionScopes."""
    ctx = global_session_registry.get_session("opencode_live_session")
    with ctx.scope_manager.scope("parent_task") as parent_scope:
        with ctx.scope_manager.scope("child_tool") as child_scope:
            pass

    response = client.get("/api/sessions/opencode_live_session/scopes")
    assert response.status_code == 200
    scopes = response.json()
    assert len(scopes) == 2

    assert scopes[0]["scope_name"] == "parent_task"
    assert scopes[0]["parent_scope_id"] is None
    assert scopes[1]["scope_name"] == "child_tool"
    assert scopes[1]["parent_scope_id"] == scopes[0]["scope_id"]


def test_get_single_event_and_node_endpoints(client):
    """Verifies GET /api/events/{event_id} and GET /api/nodes/{node_id}."""
    ctx = global_session_registry.get_session("opencode_live_session")
    tool_col = ToolCollector(ctx.recorder)
    tool_evt = tool_col.record_tool_call(
        tool_name="grep_code",
        arguments={"query": "TODO"},
        actor_id="agent:opencode",
    )

    # Single Event endpoint
    evt_resp = client.get(f"/api/events/{tool_evt.event_id}")
    assert evt_resp.status_code == 200
    evt_data = evt_resp.json()
    assert evt_data["event_id"] == tool_evt.event_id
    assert evt_data["event_type"] == "TOOL_CALL"

    # Single Node endpoint
    node_resp = client.get("/api/nodes/tool:grep_code")
    assert node_resp.status_code == 200
    node_data = node_resp.json()
    assert node_data["node"]["node_id"] == "tool:grep_code"
    assert node_data["node"]["node_type"] == "TOOL"
    assert len(node_data["incoming_edges"]) >= 1
    assert node_data["incoming_edges"][0]["edge_type"] == "INVOKED"

    # Non-existent node returns 404
    missing_resp = client.get("/api/nodes/non_existent_node_id")
    assert missing_resp.status_code == 404


def test_session_isolation(client):
    """Verifies strict isolation: events and nodes in session A never leak into session B."""
    session_a = global_session_registry.create_session("session_alpha", agent_name="AgentA")
    session_b = global_session_registry.create_session("session_beta", agent_name="AgentB")

    session_a.recorder.record(RawObservation(
        event_type=EventType.USER_INPUT,
        raw_payload={"prompt": "Secret alpha mission"},
        actor_id="user:alice",
    ))

    session_b.recorder.record(RawObservation(
        event_type=EventType.USER_INPUT,
        raw_payload={"prompt": "Public beta task"},
        actor_id="user:bob",
    ))

    # Check session A
    resp_a = client.get("/api/sessions/session_alpha/events")
    events_a = resp_a.json()
    assert len(events_a) == 1
    assert events_a[0]["payload"]["prompt"] == "Secret alpha mission"

    # Check session B
    resp_b = client.get("/api/sessions/session_beta/events")
    events_b = resp_b.json()
    assert len(events_b) == 1
    assert events_b[0]["payload"]["prompt"] == "Public beta task"
    assert events_b[0]["payload"]["prompt"] != "Secret alpha mission"

    # Graph isolation
    graph_a = client.get("/api/sessions/session_alpha/graph").json()
    graph_b = client.get("/api/sessions/session_beta/graph").json()
    node_ids_a = {n["node_id"] for n in graph_a["nodes"]}
    node_ids_b = {n["node_id"] for n in graph_b["nodes"]}
    assert "user:alice" in node_ids_a
    assert "user:alice" not in node_ids_b
    assert "user:bob" in node_ids_b


def test_safe_payload_guarantee_no_raw_secrets_in_rest(client):
    """Verifies INV-001 enforcement: API responses never expose unmasked secrets."""
    ctx = global_session_registry.get_session("opencode_live_session")
    file_col = FileCollector(ctx.recorder)

    # Ingest a file read containing an OpenAI key and token
    raw_secret_str = "sk-proj-abc123456789defghijklmnop"
    file_col.record_file_read(
        file_path=".env",
        content=f"OPENAI_API_KEY={raw_secret_str}\nPASSWORD=supersecretpassword\n",
        actor_id="agent:opencode",
    )

    # Retrieve via REST
    events_resp = client.get("/api/sessions/opencode_live_session/events")
    assert events_resp.status_code == 200
    events = events_resp.json()

    # Assert raw secret string is nowhere in the serialized JSON text
    raw_json_text = events_resp.text
    assert raw_secret_str not in raw_json_text
    assert "supersecretpassword" not in raw_json_text

    # Verify HMAC fingerprint masking is present in sanitized content
    payload = events[0]["payload"]
    assert "[MASKED_OPENAI_KEY_" in payload["content"]
    assert "[MASKED_GENERIC_SECRET_KV_" in payload["content"]
    assert payload["file_path"] == ".env"
