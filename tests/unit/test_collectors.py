"""Unit tests for GuardX Runtime Collectors."""

from guardx.collectors.file_collector import FileCollector
from guardx.collectors.llm_collector import LLMCollector
from guardx.collectors.network_collector import NetworkCollector
from guardx.collectors.process_collector import ProcessCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.enums import EventType, ProvenanceQuality


def test_tool_collector(recorder):
    collector = ToolCollector(recorder)
    assert collector.collector_name == "tool_collector"

    # Test observe_call context manager
    with collector.observe_call(
        tool_name="read_file",
        arguments={"path": "config.py"},
        actor_id="agent:opencode",
    ) as call_evt:
        assert call_evt.event_type == EventType.TOOL_CALL
        assert call_evt.provenance_quality == ProvenanceQuality.OBSERVED
        assert call_evt.payload["tool_name"] == "read_file"
        assert call_evt.destination.resource_id == "tool:read_file"

    history = recorder.get_history()
    assert len(history) == 2
    assert history[0].event_type == EventType.TOOL_CALL
    assert history[1].event_type == EventType.TOOL_RESULT


def test_file_collector_read_and_write(recorder):
    collector = FileCollector(recorder)
    assert collector.collector_name == "file_collector"

    # Read observation
    read_evt = collector.record_file_read(
        file_path="src/app.py",
        content="print('hello')",
        actor_id="tool:read_file",
    )
    assert read_evt.event_type == EventType.FILE_READ
    assert read_evt.provenance_quality == ProvenanceQuality.OBSERVED
    assert read_evt.source.resource_id == "file:src/app.py"

    # Write observation
    write_evt = collector.record_file_write(
        file_path="src/app.py",
        content="print('updated')",
        actor_id="tool:write_file",
        causal_event_id=read_evt.event_id,
    )
    assert write_evt.event_type == EventType.FILE_WRITE
    assert write_evt.destination.resource_id == "file:src/app.py"
    assert write_evt.causal_event_id == read_evt.event_id


def test_process_collector(recorder):
    collector = ProcessCollector(recorder)
    assert collector.collector_name == "process_collector"

    with collector.observe_subprocess("python script.py", simulated_pid=12345) as p_evt:
        assert p_evt.event_type == EventType.PROCESS_EXEC
        assert p_evt.provenance_quality == ProvenanceQuality.OBSERVED
        assert p_evt.payload["pid"] == 12345
        assert p_evt.source.resource_id == "proc:python"

    history = recorder.get_history()
    # History: PROCESS_EXEC, PROCESS_EXIT
    assert len(history) == 2
    assert history[1].event_type == EventType.PROCESS_EXIT
    assert history[1].payload["exit_code"] == 0


def test_network_collector_sanitizes_authorization(recorder):
    collector = NetworkCollector(recorder)
    assert collector.collector_name == "network_collector"

    # Outbound request containing Bearer token in headers
    req_evt = collector.record_request(
        url="https://api.example.com/v1/data",
        method="POST",
        headers={"Authorization": "Bearer sk-proj-123456789012345678901234"},
        body_preview='{"email": "secret_user@example.com"}',
        actor_id="agent:opencode",
    )

    assert req_evt.event_type == EventType.NETWORK_REQUEST
    assert req_evt.destination.resource_id == "net:api.example.com:443"
    # Ensure sensitive items passed through SafePayloadBuilder
    assert "sk-proj-" not in str(req_evt.payload)
    assert "secret_user@example.com" not in str(req_evt.payload)
    assert "[MASKED_EMAIL_" in str(req_evt.payload)

    # Response observation
    resp_evt = collector.record_response(
        url="https://api.example.com/v1/data",
        status_code=200,
        response_preview='{"status": "ok"}',
        causal_event_id=req_evt.event_id,
    )
    assert resp_evt.event_type == EventType.NETWORK_RESPONSE
    assert resp_evt.payload["status_code"] == 200


def test_llm_collector(recorder):
    collector = LLMCollector(recorder)
    assert collector.collector_name == "llm_collector"

    req_evt = collector.record_request(
        provider="OpenRouter",
        model="anthropic/claude-3.5-sonnet",
        prompt_preview="Please debug this function.",
        actor_id="agent:opencode",
    )
    assert req_evt.event_type == EventType.LLM_REQUEST
    assert req_evt.provenance_quality == ProvenanceQuality.OBSERVED
    assert req_evt.payload["provider"] == "OpenRouter"

    resp_evt = collector.record_response(
        provider="OpenRouter",
        model="anthropic/claude-3.5-sonnet",
        completion_preview="Here is the fix.",
        tokens_used=120,
        causal_event_id=req_evt.event_id,
    )
    assert resp_evt.event_type == EventType.LLM_RESPONSE
    assert resp_evt.payload["tokens_used"] == 120
