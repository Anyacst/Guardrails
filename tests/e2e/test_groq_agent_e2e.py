"""End-to-End Provenance Test for GuardX Groq Demo Agent.

Validates:
1. End-to-end execution of Groq Agent with multi-tool calling
2. Complete provenance capture: LLM requests/responses, tool calls, file reads, and file writes
3. Full Execution Provenance DAG construction:
   - agent:groq_agent -> tool:list_files (INVOKED)
   - agent:groq_agent -> tool:read_file (INVOKED)
   - tool:read_file -> file:config.py (READ_FROM)
   - tool:read_file -> file:.env (READ_FROM)
   - agent:groq_agent -> tool:write_file (INVOKED)
   - tool:write_file -> file:summary.txt (WROTE_TO)
   - agent:groq_agent -> llm:groq (SENT_TO)
4. Critical Semantic Invariant: NO file:.env -> llm:groq edge
5. Optional manual live test when real GROQ_API_KEY is configured
"""

import os
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from examples.groq_agent.agent import GroqAgent, load_project_groq_api_key
from guardx.core.enums import EventType
from guardx.server.session_registry import SessionRegistry


def create_multi_round_mock_groq():
    """Builds a mock Groq client that simulates a realistic multi-step agent investigation."""
    mock_client = MagicMock()

    # Step 1: Model calls list_files
    tc_list = MagicMock()
    tc_list.id = "tc_list_01"
    tc_list.function.name = "list_files"
    tc_list.function.arguments = '{"path": "."}'
    resp1 = MagicMock(
        choices=[MagicMock(message=MagicMock(content="I will first list the files.", tool_calls=[tc_list]))],
        usage={"total_tokens": 45},
    )

    # Step 2: Model calls read_file for config.py
    tc_read_cfg = MagicMock()
    tc_read_cfg.id = "tc_read_cfg_02"
    tc_read_cfg.function.name = "read_file"
    tc_read_cfg.function.arguments = '{"path": "config.py"}'
    resp2 = MagicMock(
        choices=[MagicMock(message=MagicMock(content="Reading config.py", tool_calls=[tc_read_cfg]))],
        usage={"total_tokens": 60},
    )

    # Step 3: Model calls read_file for .env
    tc_read_env = MagicMock()
    tc_read_env.id = "tc_read_env_03"
    tc_read_env.function.name = "read_file"
    tc_read_env.function.arguments = '{"path": ".env"}'
    resp3 = MagicMock(
        choices=[MagicMock(message=MagicMock(content="Reading .env", tool_calls=[tc_read_env]))],
        usage={"total_tokens": 75},
    )

    # Step 4: Model calls write_file for summary.txt
    tc_write = MagicMock()
    tc_write.id = "tc_write_04"
    tc_write.function.name = "write_file"
    tc_write.function.arguments = '{"path": "summary.txt", "content": "Configuration summary: DEBUG=false, API key loaded."}'
    resp4 = MagicMock(
        choices=[MagicMock(message=MagicMock(content="Writing summary.txt", tool_calls=[tc_write]))],
        usage={"total_tokens": 90},
    )

    # Step 5: Final completion answer
    resp5 = MagicMock(
        choices=[MagicMock(message=MagicMock(
            content="Investigation complete. The application configures DEBUG=false and loads credentials from .env. Summary written to summary.txt.",
            tool_calls=None,
        ))],
        usage={"total_tokens": 110},
    )

    mock_client.chat.completions.create.side_effect = [resp1, resp2, resp3, resp4, resp5]
    return mock_client


def test_groq_agent_end_to_end_read_and_write_provenance(tmp_path):
    """Verifies end-to-end execution of Groq agent and resulting Execution Provenance DAG."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "config.py").write_text("def get_config(): return {'debug': False}\n")
    (workspace / ".env").write_text("DEMO_API_KEY=guardx-demo-not-real\nDATABASE_PASSWORD=testpass\n")

    registry = SessionRegistry()
    session_ctx = registry.create_session("groq_e2e_session", agent_name="GroqAgent", workspace_root=str(workspace))

    mock_groq = create_multi_round_mock_groq()
    agent = GroqAgent(
        session_context=session_ctx,
        workspace_dir=workspace,
        groq_client=mock_groq,
    )

    prompt = "Inspect this workspace. Determine how the application is configured. Read files as necessary and create summary.txt."
    result = agent.run(prompt)

    assert result["status"] == "completed"
    assert result["rounds"] == 5
    assert (workspace / "summary.txt").exists()
    assert "DEBUG=false" in (workspace / "summary.txt").read_text()

    # 1. Event verification
    history = session_ctx.recorder.get_history()
    event_types = [e.event_type for e in history]
    assert EventType.USER_INPUT in event_types
    assert EventType.LLM_REQUEST in event_types
    assert EventType.LLM_RESPONSE in event_types
    assert EventType.TOOL_CALL in event_types
    assert EventType.FILE_READ in event_types
    assert EventType.FILE_WRITE in event_types
    assert EventType.TOOL_RESULT in event_types

    # Sequence numbers strictly monotonic
    seqs = [e.sequence_number for e in history]
    assert seqs == list(range(1, len(history) + 1))

    # 2. Graph DAG verification
    graph = session_ctx.graph_store.get_session_graph(session_ctx.session.session_id)
    graph_dict = graph.to_dict()

    node_ids = {n["node_id"] for n in graph_dict["nodes"]}
    assert "agent:groq_agent" in node_ids
    assert "tool:list_files" in node_ids
    assert "tool:read_file" in node_ids
    assert "tool:write_file" in node_ids
    assert "file:config.py" in node_ids
    assert "file:.env" in node_ids
    assert "file:summary.txt" in node_ids
    assert "llm:groq" in node_ids

    # 3. Directed Edge verification
    edge_triplets = {(e["source_id"], e["target_id"], e["edge_type"]) for e in graph_dict["edges"]}

    assert ("agent:groq_agent", "tool:list_files", "INVOKED") in edge_triplets
    assert ("agent:groq_agent", "tool:read_file", "INVOKED") in edge_triplets
    assert ("agent:groq_agent", "tool:write_file", "INVOKED") in edge_triplets
    assert ("tool:read_file", "file:config.py", "READ_FROM") in edge_triplets
    assert ("tool:read_file", "file:.env", "READ_FROM") in edge_triplets
    assert ("tool:write_file", "file:summary.txt", "WROTE_TO") in edge_triplets
    assert ("agent:groq_agent", "llm:groq", "SENT_TO") in edge_triplets

    # 4. CRITICAL SEMANTIC INVARIANT:
    # Must NOT draw data-flow edges from resources to LLM
    for e in graph_dict["edges"]:
        assert not (e["source_id"] in ["file:.env", "file:config.py"] and e["target_id"] == "llm:groq"), (
            "CRITICAL VIOLATION: Execution DAG must not claim data flow from files to LLM!"
        )


@pytest.mark.skipif(
    not load_project_groq_api_key(),
    reason="Live Groq test requires GROQ_API_KEY configured in .env",
)
def test_manual_live_groq_agent_execution():
    """Optional manual live test that executes against the real Groq API when GROQ_API_KEY is present."""
    api_key = load_project_groq_api_key()
    assert api_key is not None

    registry = SessionRegistry()
    session_ctx = registry.create_session("live_groq_manual_session", agent_name="GroqAgent")

    agent = GroqAgent(session_context=session_ctx, api_key=api_key)
    result = agent.run("Inspect the workspace and summarize findings in notes.txt.")

    assert result["status"] == "completed"
    assert result["rounds"] >= 1
    assert len(session_ctx.recorder.get_history()) > 0
