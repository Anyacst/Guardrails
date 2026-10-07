"""Unit tests for OpenCodeGuardXAdapter reference integration."""

import os
from guardx.adapters.opencode_adapter import OpenCodeGuardXAdapter
from guardx.core.enums import EventType
from guardx.graph.engine import ProvenanceEngine
from guardx.graph.store import InMemoryGraphStore


def test_opencode_adapter_secure_read(recorder, event_bus, tmp_path):
    store = InMemoryGraphStore()
    engine = ProvenanceEngine(store=store)
    event_bus.subscribe(engine)

    # Create dummy .env file
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-proj-test12345678901234567890\nDEBUG=true\n")

    adapter = OpenCodeGuardXAdapter(recorder=recorder)

    # Execute secure read
    content = adapter.execute_agentguard_read(str(env_file))

    # Assertions on event stream
    history = recorder.get_history()
    event_types = [e.event_type for e in history]

    assert EventType.SCOPE_START in event_types
    assert EventType.TOOL_CALL in event_types
    assert EventType.FILE_READ in event_types
    assert EventType.TOOL_RESULT in event_types
    assert EventType.SCOPE_END in event_types

    # Assertions on graph
    assert store.get_node("tool:agentguard_read") is not None
    assert store.get_node(f"file:{env_file}") is not None or len(store.get_nodes()) >= 3

    # Verification: No raw secrets in any recorded event payload
    for evt in history:
        assert "sk-proj-test" not in str(evt.payload)
