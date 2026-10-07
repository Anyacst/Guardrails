"""Unit tests for GuardX WebSocket Live Streaming.

Tests:
- WebSocket connection and session.snapshot payload
- Live incremental event.created broadcasting
- Live node.created and edge.created generation
- Scope lifecycle events (scope.started, scope.ended)
- Ping-pong keepalive
- Disconnect handling and cleanup
- Zero raw secrets over WebSocket frames
"""

import pytest
from fastapi.testclient import TestClient

from guardx.collectors.file_collector import FileCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.enums import EventType
from guardx.core.models import RawObservation
from guardx.server.app import create_app
from guardx.server.broadcaster import get_or_create_broadcaster
from guardx.server.session_registry import global_session_registry


@pytest.fixture
def client():
    """Provides a TestClient with a fresh session registry."""
    global_session_registry.clear()
    app = create_app()
    return TestClient(app)


def test_websocket_snapshot_on_connect(client):
    """Verifies that connecting to /ws/sessions/{id} immediately delivers a session.snapshot."""
    ctx = global_session_registry.get_session("opencode_live_session")
    # Pre-populate an event
    ctx.recorder.record(RawObservation(
        event_type=EventType.USER_INPUT,
        raw_payload={"prompt": "Initial prompt"},
        actor_id="user:alice",
    ))

    with client.websocket_connect("/ws/sessions/opencode_live_session") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "session.snapshot"
        assert msg["session_id"] == "opencode_live_session"
        assert "data" in msg
        assert "events" in msg["data"]
        assert len(msg["data"]["events"]) == 1
        assert msg["data"]["events"][0]["event_type"] == "USER_INPUT"
        assert "nodes" in msg["data"]
        assert "edges" in msg["data"]


def test_websocket_incremental_event_broadcast(client):
    """Verifies that new events recorded via EventRecorder push incremental event.created messages."""
    ctx = global_session_registry.get_session("opencode_live_session")

    with client.websocket_connect("/ws/sessions/opencode_live_session") as ws:
        # Consume initial snapshot
        snapshot = ws.receive_json()
        assert snapshot["type"] == "session.snapshot"

        # Record new event
        ctx.recorder.record(RawObservation(
            event_type=EventType.AGENT_ACTION,
            raw_payload={"thought": "Processing request"},
            actor_id="agent:opencode",
        ))

        # Expect incremental event.created
        inc_msg = ws.receive_json()
        assert inc_msg["type"] == "event.created"
        assert inc_msg["session_id"] == "opencode_live_session"
        assert inc_msg["data"]["event_type"] == "AGENT_ACTION"
        assert inc_msg["data"]["actor_id"] == "agent:opencode"
        assert inc_msg["data"]["sequence_number"] == 1


def test_websocket_incremental_node_and_edge_broadcast(client):
    """Verifies that tool invocation pushes event.created, node.created, and edge.created."""
    ctx = global_session_registry.get_session("opencode_live_session")
    tool_col = ToolCollector(ctx.recorder)

    with client.websocket_connect("/ws/sessions/opencode_live_session") as ws:
        snapshot = ws.receive_json()
        assert snapshot["type"] == "session.snapshot"

        # Record a tool call
        tool_col.record_tool_call(
            tool_name="read_file",
            arguments={"path": "config.json"},
            actor_id="agent:opencode",
        )

        # Collect broadcast messages for this action
        received_types = []
        for _ in range(5):
            msg = ws.receive_json()
            received_types.append(msg["type"])
            if "edge.created" in received_types:
                break

        assert "event.created" in received_types
        assert "node.created" in received_types
        assert "edge.created" in received_types


def test_websocket_scope_lifecycle_broadcast(client):
    """Verifies that scope start and exit broadcast scope.started and scope.ended."""
    ctx = global_session_registry.get_session("opencode_live_session")

    with client.websocket_connect("/ws/sessions/opencode_live_session") as ws:
        snapshot = ws.receive_json()
        assert snapshot["type"] == "session.snapshot"

        with ctx.scope_manager.scope("investigation_task") as scope:
            # First message should be event.created for SCOPE_START
            msg1 = ws.receive_json()
            assert msg1["type"] == "event.created"
            assert msg1["data"]["event_type"] == "SCOPE_START"

            # Second message should be scope.started
            msg2 = ws.receive_json()
            assert msg2["type"] == "scope.started"
            assert msg2["data"]["scope_name"] == "investigation_task"

            # Collect node.created messages emitted for agent and scope
            created_nodes = []
            for _ in range(2):
                m = ws.receive_json()
                if m["type"] == "node.created":
                    created_nodes.append(m["data"]["node_type"])

            assert "EXECUTION_SCOPE" in created_nodes

        # Exiting scope produces event.created (SCOPE_END) and scope.ended
        msg3 = ws.receive_json()
        assert msg3["type"] == "event.created"
        assert msg3["data"]["event_type"] == "SCOPE_END"

        msg4 = ws.receive_json()
        assert msg4["type"] == "scope.ended"
        assert msg4["data"]["scope_name"] == "investigation_task"


def test_websocket_ping_pong_keepalive(client):
    """Verifies ping/pong keepalive works on the WebSocket connection."""
    with client.websocket_connect("/ws/sessions/opencode_live_session") as ws:
        snapshot = ws.receive_json()
        assert snapshot["type"] == "session.snapshot"

        ws.send_text("ping")
        pong = ws.receive_text()
        assert pong == "pong"


def test_websocket_safe_payload_guarantee(client):
    """Verifies INV-001: WebSocket frames NEVER contain unmasked secrets."""
    ctx = global_session_registry.get_session("opencode_live_session")
    file_col = FileCollector(ctx.recorder)

    with client.websocket_connect("/ws/sessions/opencode_live_session") as ws:
        snapshot = ws.receive_json()

        secret_token = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        file_col.record_file_read(
            file_path=".git/config",
            content=f"token={secret_token}\n",
            actor_id="agent:opencode",
        )

        msg = ws.receive_json()
        assert msg["type"] == "event.created"

        # Verify secret_token is NOT anywhere in the message payload or text
        msg_str = str(msg)
        assert secret_token not in msg_str
        assert "[MASKED_GITHUB_TOKEN_" in msg["data"]["payload"]["content"]


def test_websocket_client_disconnect_cleanup(client):
    """Verifies that disconnecting cleanups broadcaster socket set without crashing subsequent events."""
    ctx = global_session_registry.get_session("opencode_live_session")
    broadcaster = get_or_create_broadcaster(ctx)

    with client.websocket_connect("/ws/sessions/opencode_live_session") as ws:
        ws.receive_json()  # snapshot
        assert broadcaster.client_count >= 1

    # After context manager exits, socket is disconnected
    # Emitting an event must not raise exceptions
    ctx.recorder.record(RawObservation(
        event_type=EventType.USER_INPUT,
        raw_payload={"msg": "After disconnect"},
        actor_id="user:alice",
    ))
