"""Unit tests for GuardX invariant enforcement (INV-001 through INV-005)."""

from datetime import datetime, timezone
import pytest

from guardx.core.enums import ActorType, EventType, ResourceType
from guardx.core.invariants import InvariantValidator, InvariantViolation
from guardx.core.models import Actor, GuardXEvent, Resource


@pytest.fixture
def sample_actor():
    return Actor(actor_id="agent:opencode", actor_type=ActorType.AGENT, display_name="OpenCode")


@pytest.fixture
def sample_resource():
    return Resource(resource_id="file:app.py", resource_type=ResourceType.FILE, uri="file://app.py")


def test_inv_001_raw_secret_rejected(sample_actor, sample_resource):
    validator = InvariantValidator()
    now = datetime.now(timezone.utc)

    # Event containing an unmasked OpenAI secret key
    event = GuardXEvent(
        event_id="evt_bad_001",
        session_id="session_001",
        sequence_number=1,
        timestamp=now,
        event_type=EventType.FILE_READ,
        actor=sample_actor,
        source=sample_resource,
        execution_scope_id="scope_1",
        payload={"raw_content": "API_KEY=sk-proj-0123456789012345678901234"},
    )

    with pytest.raises(InvariantViolation) as exc:
        validator.validate_event(event, expected_seq=1)
    assert "[INV-001]" in str(exc.value)


def test_inv_003_sequence_monotonicity(sample_actor, sample_resource):
    validator = InvariantValidator()
    now = datetime.now(timezone.utc)

    event = GuardXEvent(
        event_id="evt_001",
        session_id="session_001",
        sequence_number=5,
        timestamp=now,
        event_type=EventType.USER_INPUT,
        actor=sample_actor,
        payload={"msg": "Hello"},
    )

    with pytest.raises(InvariantViolation) as exc:
        validator.validate_event(event, expected_seq=2)
    assert "[INV-003]" in str(exc.value)


def test_inv_004_missing_scope_on_operational_event(sample_actor, sample_resource):
    validator = InvariantValidator()
    now = datetime.now(timezone.utc)

    # FILE_READ is operational; missing execution_scope_id violates INV-004
    event = GuardXEvent(
        event_id="evt_001",
        session_id="session_001",
        sequence_number=1,
        timestamp=now,
        event_type=EventType.FILE_READ,
        actor=sample_actor,
        source=sample_resource,
        execution_scope_id=None,
        payload={"path": "app.py"},
    )

    with pytest.raises(InvariantViolation) as exc:
        validator.validate_event(event, expected_seq=1)
    assert "[INV-004]" in str(exc.value)


def test_inv_005_causal_ordering_integrity(sample_actor, sample_resource):
    validator = InvariantValidator()
    now = datetime.now(timezone.utc)

    known_sequences = {"evt_parent": 5}

    # Current event has sequence 4, but claims causal trigger was seq 5 (future event!)
    event = GuardXEvent(
        event_id="evt_child",
        session_id="session_001",
        sequence_number=4,
        timestamp=now,
        event_type=EventType.FILE_READ,
        actor=sample_actor,
        source=sample_resource,
        execution_scope_id="scope_1",
        causal_event_id="evt_parent",
        payload={"path": "app.py"},
    )

    with pytest.raises(InvariantViolation) as exc:
        validator.validate_event(event, expected_seq=4, known_event_sequences=known_sequences)
    assert "[INV-005]" in str(exc.value)
