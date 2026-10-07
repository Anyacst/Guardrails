"""Unit tests for GuardX enums, domain models, and immutability."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import pytest

from guardx.core.enums import (
    EventType,
    ActorType,
    ResourceType,
    TrustLevel,
    ProvenanceQuality,
    TransformationSecuritySemantics,
    ScopeStatus,
)
from guardx.core.models import (
    Actor,
    Resource,
    Session,
    ScopeProjection,
    GuardXEvent,
    RawObservation,
)


def test_enums_contain_required_types():
    assert EventType.SCOPE_START == "SCOPE_START"
    assert EventType.SCOPE_END == "SCOPE_END"
    assert EventType.TOOL_CALL == "TOOL_CALL"
    assert EventType.RISK_DETECTED == "RISK_DETECTED"

    assert ActorType.AGENT == "AGENT"
    assert ActorType.USER == "USER"
    assert ActorType.TOOL == "TOOL"

    assert ResourceType.FILE == "FILE"
    assert ResourceType.NETWORK_ENDPOINT == "NETWORK_ENDPOINT"

    assert TrustLevel.LOCAL == "LOCAL"
    assert TrustLevel.EXTERNAL_LLM == "EXTERNAL_LLM"
    assert TrustLevel.UNTRUSTED_EXTERNAL == "UNTRUSTED_EXTERNAL"

    assert ProvenanceQuality.OBSERVED == "OBSERVED"
    assert ProvenanceQuality.DERIVED == "DERIVED"
    assert ProvenanceQuality.INFERRED == "INFERRED"

    assert TransformationSecuritySemantics.PRESERVING == "PRESERVING"
    assert TransformationSecuritySemantics.PROTECTING == "PROTECTING"
    assert TransformationSecuritySemantics.SANITIZING == "SANITIZING"
    assert TransformationSecuritySemantics.AGGREGATING == "AGGREGATING"
    assert TransformationSecuritySemantics.DECLASSIFYING == "DECLASSIFYING"


def test_guardx_event_immutability():
    actor = Actor(actor_id="agent:test", actor_type=ActorType.AGENT, display_name="TestAgent")
    resource = Resource(resource_id="file:config.py", resource_type=ResourceType.FILE, uri="file://config.py")
    now = datetime.now(timezone.utc)

    event = GuardXEvent(
        event_id="evt_001",
        session_id="session_001",
        sequence_number=1,
        timestamp=now,
        event_type=EventType.FILE_READ,
        actor=actor,
        source=resource,
        payload={"path": "config.py"},
    )

    # Immutability check (INV-002)
    with pytest.raises(FrozenInstanceError):
        event.sequence_number = 2

    with pytest.raises(FrozenInstanceError):
        event.event_type = EventType.FILE_WRITE


def test_scope_projection_lifecycle():
    now = datetime.now(timezone.utc)
    proj = ScopeProjection(
        scope_id="scope_123",
        session_id="session_abc",
        parent_scope_id=None,
        actor_id="agent:opencode",
        originating_event_id="evt_001",
        scope_name="test_scope",
        start_time=now,
        status=ScopeStatus.ACTIVE,
    )

    assert proj.status == ScopeStatus.ACTIVE
    assert proj.end_time is None

    later = datetime.now(timezone.utc)
    proj.close(end_time=later, status=ScopeStatus.COMPLETED)

    assert proj.status == ScopeStatus.COMPLETED
    assert proj.end_time == later
