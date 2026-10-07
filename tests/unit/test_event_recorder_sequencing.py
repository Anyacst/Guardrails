"""Unit tests for EventRecorder centralized sequencing and publication."""

import concurrent.futures
from guardx.core.context import ScopeManager
from guardx.core.enums import EventType
from guardx.core.interfaces import EventSubscriber
from guardx.core.models import GuardXEvent, RawObservation


class RecordingSubscriber(EventSubscriber):
    def __init__(self):
        self.events = []

    def on_event(self, event: GuardXEvent) -> None:
        self.events.append(event)


def test_event_recorder_strict_monotonic_sequence(recorder, event_bus):
    sub = RecordingSubscriber()
    event_bus.subscribe(sub)

    for i in range(1, 6):
        obs = RawObservation(
            event_type=EventType.USER_INPUT,
            raw_payload={"msg": f"Prompt {i}"},
            actor_id="user:alice",
        )
        evt = recorder.record(obs)
        assert evt.sequence_number == i

    assert len(sub.events) == 5
    assert [e.sequence_number for e in sub.events] == [1, 2, 3, 4, 5]


def test_event_recorder_concurrency_safety(recorder):
    """Ensures concurrent observations receive contiguous, unique sequence numbers."""

    def emit(idx: int):
        obs = RawObservation(
            event_type=EventType.USER_INPUT,
            raw_payload={"idx": idx},
            actor_id="user:alice",
        )
        return recorder.record(obs)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        events = list(executor.map(emit, range(50)))

    sequences = [e.sequence_number for e in events]
    assert len(sequences) == 50
    assert len(set(sequences)) == 50
    assert sorted(sequences) == list(range(1, 51))
    assert recorder.current_sequence == 50


def test_event_recorder_automatic_scope_attribution(recorder):
    scope_mgr = ScopeManager(recorder=recorder)

    # 1. Root scope event emitted by scope_mgr
    with scope_mgr.scope("analysis_scope") as sc:
        # 2. Operational event inside scope
        obs = RawObservation(
            event_type=EventType.FILE_READ,
            raw_payload={"path": "src/app.py"},
            actor_id="agent:opencode",
            source_raw="src/app.py",
        )
        evt = recorder.record(obs)

        assert evt.execution_scope_id == sc.scope_id
        assert evt.source is not None
        assert evt.source.resource_id == "file:src/app.py"

    history = recorder.get_history()
    # History should contain: SCOPE_START (seq 1), FILE_READ (seq 2), SCOPE_END (seq 3)
    assert len(history) == 3
    assert history[0].event_type == EventType.SCOPE_START
    assert history[1].event_type == EventType.FILE_READ
    assert history[2].event_type == EventType.SCOPE_END
    assert [e.sequence_number for e in history] == [1, 2, 3]
