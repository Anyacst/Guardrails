"""Unit tests for GuardX Groq Demo Agent and Workspace Sandbox.

Covers:
1. Workspace path confinement
2. ../ traversal rejection
3. Absolute-path rejection
4. Symlink escape rejection
5. read_file instrumentation
6. write_file instrumentation
7. tool-call instrumentation
8. LLM request/response instrumentation
9. Execution scope nesting
10. Maximum tool rounds limit
11. Zero GROQ_API_KEY leakage guarantee
"""

from pathlib import Path
import tempfile
from unittest.mock import MagicMock
import pytest

from examples.groq_agent.agent import GroqAgent, MAX_TOOL_ROUNDS
from examples.groq_agent.sandbox import SandboxSecurityError, WorkspaceSandbox
from examples.groq_agent.tools import AgentToolExecutor
from guardx.collectors.file_collector import FileCollector
from guardx.collectors.llm_collector import LLMCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.server.session_registry import SessionRegistry


@pytest.fixture
def test_sandbox_dir(tmp_path):
    """Provides a temporary sandboxed workspace with test files."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / ".env").write_text("DEMO_API_KEY=guardx-demo-not-real\nDEBUG=false\n")
    (ws / "config.py").write_text("def get_config(): return {'debug': False}\n")
    (ws / "notes.txt").write_text("Test notes\n")
    return ws


@pytest.fixture
def session_ctx():
    """Provides an isolated session context."""
    registry = SessionRegistry()
    return registry.create_session("test_groq_session", agent_name="GroqAgent")


# -----------------------------------------------------------------------------
# 1. Sandbox Path Confinement & Traversal Rejection Tests
# -----------------------------------------------------------------------------

def test_sandbox_confinement_normal_paths(test_sandbox_dir):
    sandbox = WorkspaceSandbox(test_sandbox_dir)
    safe_config = sandbox.resolve_safe_path("config.py")
    assert safe_config.exists()
    assert safe_config == (test_sandbox_dir / "config.py").resolve()
    assert sandbox.relative_display_path(safe_config) == "config.py"


def test_sandbox_rejects_dot_dot_traversal(test_sandbox_dir):
    sandbox = WorkspaceSandbox(test_sandbox_dir)
    with pytest.raises(SandboxSecurityError, match="Path traversal detected"):
        sandbox.resolve_safe_path("../outside.txt")

    with pytest.raises(SandboxSecurityError, match="Path traversal detected"):
        sandbox.resolve_safe_path("subdir/../../secret.txt")


def test_sandbox_rejects_absolute_path_outside_workspace(test_sandbox_dir, tmp_path):
    outside_file = tmp_path / "outside_secret.env"
    outside_file.write_text("OUTSIDE=1")

    sandbox = WorkspaceSandbox(test_sandbox_dir)
    with pytest.raises(SandboxSecurityError, match="Sandbox violation"):
        sandbox.resolve_safe_path(str(outside_file.resolve()))


def test_sandbox_rejects_symlink_escape(test_sandbox_dir, tmp_path):
    outside_target = tmp_path / "outside_target.txt"
    outside_target.write_text("SECRET")

    symlink_path = test_sandbox_dir / "escape_link.txt"
    try:
        symlink_path.symlink_to(outside_target)
    except OSError:
        pytest.skip("Symlink creation not supported on this environment")

    sandbox = WorkspaceSandbox(test_sandbox_dir)
    with pytest.raises(SandboxSecurityError):
        sandbox.resolve_safe_path("escape_link.txt")


# -----------------------------------------------------------------------------
# 2. Tool & File Observation Instrumentation Tests
# -----------------------------------------------------------------------------

def test_read_file_instrumentation(test_sandbox_dir, session_ctx):
    sandbox = WorkspaceSandbox(test_sandbox_dir)
    tool_col = ToolCollector(session_ctx.recorder)
    file_col = FileCollector(session_ctx.recorder)

    executor = AgentToolExecutor(
        sandbox=sandbox,
        tool_collector=tool_col,
        file_collector=file_col,
        scope_manager=session_ctx.scope_manager,
    )

    res = executor.execute_tool("read_file", {"path": ".env"})
    assert "content" in res
    assert "DEMO_API_KEY" in res["content"]

    history = session_ctx.recorder.get_history()
    event_types = [e.event_type for e in history]

    # Verify event sequence
    assert EventType.TOOL_CALL in event_types
    assert EventType.FILE_READ in event_types
    assert EventType.TOOL_RESULT in event_types

    file_read_evt = next(e for e in history if e.event_type == EventType.FILE_READ)
    assert file_read_evt.provenance_quality == ProvenanceQuality.OBSERVED
    assert file_read_evt.actor.actor_id == "tool:read_file"
    assert file_read_evt.source.resource_id == "file:.env"


def test_write_file_instrumentation(test_sandbox_dir, session_ctx):
    sandbox = WorkspaceSandbox(test_sandbox_dir)
    tool_col = ToolCollector(session_ctx.recorder)
    file_col = FileCollector(session_ctx.recorder)

    executor = AgentToolExecutor(
        sandbox=sandbox,
        tool_collector=tool_col,
        file_collector=file_col,
        scope_manager=session_ctx.scope_manager,
    )

    res = executor.execute_tool(
        "write_file",
        {"path": "summary.txt", "content": "Configuration summary: DEBUG=false"},
    )
    assert res["status"] == "written"
    assert (test_sandbox_dir / "summary.txt").exists()

    history = session_ctx.recorder.get_history()
    write_evt = next(e for e in history if e.event_type == EventType.FILE_WRITE)
    assert write_evt.provenance_quality == ProvenanceQuality.OBSERVED
    assert write_evt.actor.actor_id == "tool:write_file"
    assert write_evt.destination.resource_id == "file:summary.txt"

    # Verify WROTE_TO edge in DAG
    edges = session_ctx.graph_store.get_edges(source_id="tool:write_file", target_id="file:summary.txt")
    assert len(edges) >= 1
    assert edges[0].edge_type.value == "WROTE_TO"


def test_tool_call_list_files_instrumentation(test_sandbox_dir, session_ctx):
    sandbox = WorkspaceSandbox(test_sandbox_dir)
    tool_col = ToolCollector(session_ctx.recorder)
    file_col = FileCollector(session_ctx.recorder)

    executor = AgentToolExecutor(
        sandbox=sandbox,
        tool_collector=tool_col,
        file_collector=file_col,
        scope_manager=session_ctx.scope_manager,
    )

    res = executor.execute_tool("list_files", {"path": "."})
    assert "items" in res
    filenames = [item["name"] for item in res["items"]]
    assert "config.py" in filenames
    assert ".env" in filenames


# -----------------------------------------------------------------------------
# 3. LLM Request/Response & Scope Nesting Tests
# -----------------------------------------------------------------------------

def test_llm_request_response_instrumentation(test_sandbox_dir, session_ctx):
    # Mock Groq client returning final answer
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "The workspace is configured with DEBUG=false."
    mock_choice.message.tool_calls = None
    mock_response = MagicMock(choices=[mock_choice], usage={"total_tokens": 85})
    mock_client.chat.completions.create.return_value = mock_response

    agent = GroqAgent(
        session_context=session_ctx,
        workspace_dir=test_sandbox_dir,
        groq_client=mock_client,
    )

    res = agent.run("Summarize the workspace")
    assert res["status"] == "completed"
    assert "DEBUG=false" in res["final_answer"]

    history = session_ctx.recorder.get_history()
    event_types = [e.event_type for e in history]
    assert EventType.USER_INPUT in event_types
    assert EventType.LLM_REQUEST in event_types
    assert EventType.LLM_RESPONSE in event_types


def test_execution_scope_nesting(test_sandbox_dir, session_ctx):
    # Mock Groq client calling list_files then completing
    mock_client = MagicMock()

    # Round 1: Model requests list_files
    tc_mock = MagicMock()
    tc_mock.id = "tc_1"
    tc_mock.function.name = "list_files"
    tc_mock.function.arguments = '{"path": "."}'

    resp1_msg = MagicMock(content=None, tool_calls=[tc_mock])
    resp1 = MagicMock(choices=[MagicMock(message=resp1_msg)], usage={"total_tokens": 50})

    # Round 2: Model gives final answer
    resp2_msg = MagicMock(content="Workspace files listed successfully.", tool_calls=None)
    resp2 = MagicMock(choices=[MagicMock(message=resp2_msg)], usage={"total_tokens": 40})

    mock_client.chat.completions.create.side_effect = [resp1, resp2]

    agent = GroqAgent(
        session_context=session_ctx,
        workspace_dir=test_sandbox_dir,
        groq_client=mock_client,
    )

    agent.run("List files")

    # Inspect scope events
    scope_events = [e for e in session_ctx.recorder.get_history() if e.event_type == EventType.SCOPE_START]
    scope_names = [e.payload.get("scope_name") for e in scope_events]

    assert "agent_task" in scope_names
    assert "llm_round_1" in scope_names
    assert "tool:list_files" in scope_names
    assert "llm_round_2" in scope_names


def test_maximum_tool_rounds_limit(test_sandbox_dir, session_ctx):
    # Mock Groq client endlessly calling list_files
    mock_client = MagicMock()
    tc_mock = MagicMock()
    tc_mock.id = "tc_loop"
    tc_mock.function.name = "list_files"
    tc_mock.function.arguments = '{"path": "."}'

    loop_resp = MagicMock(
        choices=[MagicMock(message=MagicMock(content=None, tool_calls=[tc_mock]))],
        usage={"total_tokens": 20},
    )
    mock_client.chat.completions.create.return_value = loop_resp

    agent = GroqAgent(
        session_context=session_ctx,
        workspace_dir=test_sandbox_dir,
        groq_client=mock_client,
    )

    result = agent.run("Infinite loop test")
    assert result["rounds"] == MAX_TOOL_ROUNDS


# -----------------------------------------------------------------------------
# 4. Zero GROQ_API_KEY Leakage Invariant Test
# -----------------------------------------------------------------------------

def test_zero_groq_api_key_leakage(test_sandbox_dir, session_ctx):
    canary_key = "gsk_testcanarykey999999999999999999999999"

    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Normal output without secret"
    mock_choice.message.tool_calls = None
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[mock_choice], usage={"total_tokens": 30}
    )

    agent = GroqAgent(
        session_context=session_ctx,
        workspace_dir=test_sandbox_dir,
        groq_client=mock_client,
        api_key=canary_key,
    )

    agent.run("Check config")

    # Invariant: canary key MUST NEVER be present in history or graph
    for evt in session_ctx.recorder.get_history():
        evt_str = str(evt)
        assert canary_key not in evt_str, f"Canary API key leaked into event: {evt.event_id}"
        assert canary_key not in str(evt.payload)
        assert canary_key not in str(evt.metadata)

    graph = session_ctx.graph_store.get_session_graph(session_ctx.session.session_id)
    graph_str = str(graph.to_dict())
    assert canary_key not in graph_str, "Canary API key leaked into Graph JSON representation"
