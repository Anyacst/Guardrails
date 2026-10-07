"""Unit tests demonstrating nested ExecutionScopes and end-to-end event flow."""

from guardx.core.context import ScopeManager
from guardx.core.enums import EventType, ScopeStatus
from guardx.core.interfaces import EventSubscriber
from guardx.core.models import GuardXEvent, RawObservation


class BusSpy(EventSubscriber):
    def __init__(self):
        self.received_events = []

    def on_event(self, event: GuardXEvent) -> None:
        self.received_events.append(event)


def test_end_to_end_observation_to_bus_flow(recorder, event_bus):
    """Verifies: RawObservation -> sanitization -> scope attribution -> sequence assignment -> immutable GuardXEvent -> EventBus."""
    spy = BusSpy()
    event_bus.subscribe(spy)

    scope_mgr = ScopeManager(recorder=recorder)

    # 1. Open an execution scope
    with scope_mgr.scope("tool_execution_scope") as scope:
        # 2. Raw observation arrives with sensitive string and file source
        raw_obs = RawObservation(
            event_type=EventType.FILE_READ,
            raw_payload={
                "file_path": ".env",
                "content_snippet": "OPENAI_API_KEY=sk-proj-supersecretkey1234567890",
            },
            actor_id="agent:opencode",
            source_raw=".env",
        )

        # 3. Recorder processes observation
        event = recorder.record(raw_obs)

        # Assertions on created event
        assert event.sequence_number == 2  # seq 1 was SCOPE_START
        assert event.execution_scope_id == scope.scope_id
        assert event.source.resource_id == "file:.env"
        assert "sk-proj-supersecretkey" not in str(event.payload)
        assert "[MASKED_OPENAI_KEY_" in event.payload["content_snippet"]
        assert len(event.data_lineage_ids) == 1
        assert event.data_lineage_ids[0].startswith("entity:")

    # 4. Bus received all events in order
    assert len(spy.received_events) == 3
    assert spy.received_events[0].event_type == EventType.SCOPE_START
    assert spy.received_events[1].event_type == EventType.FILE_READ
    assert spy.received_events[2].event_type == EventType.SCOPE_END
    assert [e.sequence_number for e in spy.received_events] == [1, 2, 3]


def test_nested_execution_scopes(recorder, event_bus):
    """Verifies nested execution scopes (e.g. Agent Task -> Tool Invocation -> Subprocess Exec)."""
    spy = BusSpy()
    event_bus.subscribe(spy)

    scope_mgr = ScopeManager(recorder=recorder)

    # Level 1: Agent Task Scope
    with scope_mgr.scope("agent_task:debug_repo") as root_scope:
        assert root_scope.parent_scope_id is None

        obs1 = recorder.record(RawObservation(
            event_type=EventType.AGENT_ACTION,
            raw_payload={"intent": "Investigate bug in authentication"},
            actor_id="agent:opencode",
        ))
        assert obs1.execution_scope_id == root_scope.scope_id

        # Level 2: Nested Tool Execution Scope
        with scope_mgr.scope("tool:read_file", originating_event_id=obs1.event_id) as tool_scope:
            assert tool_scope.parent_scope_id == root_scope.scope_id

            obs2 = recorder.record(RawObservation(
                event_type=EventType.TOOL_CALL,
                raw_payload={"tool": "read_file", "path": ".env"},
                actor_id="agent:opencode",
                causal_event_id=obs1.event_id,
            ))
            assert obs2.execution_scope_id == tool_scope.scope_id
            assert obs2.causal_event_id == obs1.event_id

            # Level 3: Nested Subprocess Execution Scope
            with scope_mgr.scope("subprocess:cat", originating_event_id=obs2.event_id) as subproc_scope:
                assert subproc_scope.parent_scope_id == tool_scope.scope_id

                obs3 = recorder.record(RawObservation(
                    event_type=EventType.PROCESS_EXEC,
                    raw_payload={"cmd": "cat .env"},
                    actor_id="subproc:cat",
                    causal_event_id=obs2.event_id,
                ))
                assert obs3.execution_scope_id == subproc_scope.scope_id

            assert subproc_scope.status == ScopeStatus.COMPLETED

        assert tool_scope.status == ScopeStatus.COMPLETED

    assert root_scope.status == ScopeStatus.COMPLETED

    # Verify event stream sequencing and hierarchical nesting
    history = recorder.get_history()
    assert len(history) == 9
    # Sequence:
    # 1: SCOPE_START (root)
    # 2: AGENT_ACTION
    # 3: SCOPE_START (tool)
    # 4: TOOL_CALL
    # 5: SCOPE_START (subproc)
    # 6: PROCESS_EXEC
    # 7: SCOPE_END (subproc)
    # 8: SCOPE_END (tool)
    # 9: SCOPE_END (root)
    assert [e.sequence_number for e in history] == list(range(1, 10))
    assert history[0].event_type == EventType.SCOPE_START
    assert history[2].event_type == EventType.SCOPE_START
    assert history[4].event_type == EventType.SCOPE_START
    assert history[6].event_type == EventType.SCOPE_END
    assert history[7].event_type == EventType.SCOPE_END
    assert history[8].event_type == EventType.SCOPE_END
