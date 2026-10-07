"""Unit tests for GuardX DataFlowEngine and boundary information flow tracking."""

import json
import pytest

from guardx.core.bus import InMemoryEventBus
from guardx.core.context import ScopeManager
from guardx.core.enums import EventType
from guardx.core.models import RawObservation, Session
from guardx.core.recorder import EventRecorder
from guardx.collectors.file_collector import FileCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.collectors.llm_collector import LLMCollector
from guardx.lineage.engine import DataFlowEngine
from guardx.lineage.models import CarrierType, DataClassification
from guardx.lineage.store import DataLineageStore


@pytest.fixture
def test_setup():
    session = Session(
        session_id="session_dfe_test",
        agent_name="TestAgent",
        workspace_root="/workspace",
        hmac_key="test_hmac_secret_key_123",
    )
    event_bus = InMemoryEventBus()
    recorder = EventRecorder(session=session, event_bus=event_bus)
    scope_mgr = ScopeManager(recorder=recorder)
    lineage_store = DataLineageStore(session_id=session.session_id)
    lineage_events = []

    def on_lineage_event(m_type, data):
        lineage_events.append((m_type, data))

    df_engine = DataFlowEngine(
        store=lineage_store,
        session_key=session.hmac_key,
        on_lineage_event=on_lineage_event,
    )
    event_bus.subscribe(df_engine)

    return {
        "session": session,
        "recorder": recorder,
        "scope_mgr": scope_mgr,
        "store": lineage_store,
        "engine": df_engine,
        "events": lineage_events,
    }


def test_positive_flow_from_file_to_llm(test_setup):
    """Experiment A verification: File -> Entity -> Token -> ToolResult -> Context -> LLM."""
    rec = test_setup["recorder"]
    store = test_setup["store"]
    engine = test_setup["engine"]

    file_col = FileCollector(rec)
    tool_col = ToolCollector(rec)
    llm_col = LLMCollector(rec)

    # 1. File Read: .env
    content = "DEMO_API_KEY=guardx-demo-not-real\nDEBUG=false"
    file_col.record_file_read(
        file_path=".env",
        content=content,
        actor_id="tool:read_file",
    )

    entities = store.get_all_entities()
    assert len(entities) >= 2  # DEMO_API_KEY (raw) + TOKEN_DEMO_API_KEY (derived)
    raw_key = next(e for e in entities if e.label == "DEMO_API_KEY" and e.representation == "RAW")
    assert raw_key.classification == DataClassification.CREDENTIAL.value
    assert not raw_key.raw_value_persisted

    # 2. Tool Result with token
    tokens = list(engine._token_to_entity.keys())
    assert len(tokens) > 0
    token_str = tokens[0]

    tool_col.record_tool_result(
        tool_name="read_file",
        result_data={"content": f"Config read: DEMO_API_KEY={token_str}"},
        actor_id="tool:read_file",
    )

    # 3. Agent thought
    rec.record(RawObservation(
        event_type=EventType.AGENT_ACTION,
        raw_payload={"thought": "Formulating LLM request"},
        actor_id="agent:groq",
    ))

    # 4. LLM Request containing token
    llm_col.record_request(
        provider="Groq",
        model="openai/gpt-oss-120b",
        prompt_preview=f"Analyze: {token_str}",
        actor_id="agent:groq",
    )

    # Verify Forward Trace from raw_key reaches LLM
    trace = store.trace_forward(raw_key.entity_id)
    assert trace.has_proven_flow is True
    assert any("llm:" in d for d in trace.destinations)
    assert "PROVEN FLOW" in trace.explanation


def test_negative_flow_proves_no_temporal_inference(test_setup):
    """Experiment B verification: File read occurs, later LLM call occurs without secret.
    
    CRITICAL INVARIANT: GuardX must report NO PROVEN FLOW to LLM!
    """
    rec = test_setup["recorder"]
    store = test_setup["store"]

    file_col = FileCollector(rec)
    tool_col = ToolCollector(rec)
    llm_col = LLMCollector(rec)

    # 1. File Read: .env
    content = "DATABASE_PASSWORD=secret_db_pass_123\n"
    file_col.record_file_read(
        file_path=".env",
        content=content,
        actor_id="tool:read_file",
    )

    # 2. Tool result
    tool_col.record_tool_result(
        tool_name="read_file",
        result_data={"content": "File read complete."},
        actor_id="tool:read_file",
    )

    # 3. Completely unrelated LLM Request that does NOT contain any secret or token!
    llm_col.record_request(
        provider="Groq",
        model="openai/gpt-oss-120b",
        prompt_preview="What is 2 + 2?",
        actor_id="agent:groq",
    )

    # Verify Forward Trace from the secret
    entities = store.get_all_entities()
    raw_secret = next(e for e in entities if e.label == "DATABASE_PASSWORD")

    trace = store.trace_forward(raw_secret.entity_id)
    assert trace.has_proven_flow is False
    assert len(trace.destinations) == 0
    assert "NO PROVEN FLOW" in trace.explanation
