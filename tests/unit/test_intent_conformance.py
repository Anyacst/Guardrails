"""Unit tests for GuardX Milestone 4 Intent Conformance Engine."""

from datetime import datetime, timezone
import pytest

from guardx.core.enums import ActorType, EventType, ProvenanceQuality, ResourceType
from guardx.core.models import Actor, GuardXEvent, Resource
from guardx.intent.engine import IntentConformanceEngine
from guardx.intent.models import IntentContract, IntentViolationType
from guardx.risk.models import FindingCategory, Severity


def test_intent_conformant_execution():
    engine = IntentConformanceEngine()

    contract = IntentContract(
        intent_id="intent_001",
        session_id="s1",
        scope_id="scope_tool_1",
        description="Read config.py",
        allowed_operations=["FILE_READ"],
        allowed_resources=["config.py"],
        allowed_network=[],
    )
    engine.register_contract(contract)

    # Conformant event
    evt = GuardXEvent(
        event_id="evt_read_config",
        session_id="s1",
        sequence_number=1,
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.FILE_READ,
        actor=Actor(actor_id="tool:read_file", actor_type=ActorType.TOOL, display_name="read_file"),
        source=Resource(resource_id="file:config.py", resource_type=ResourceType.FILE, uri="config.py"),
        destination=Actor(actor_id="tool:read_file", actor_type=ActorType.TOOL, display_name="read_file"),
        execution_scope_id="scope_tool_1",
        provenance_quality=ProvenanceQuality.OBSERVED,
        confidence=1.0,
    )

    violation = engine.evaluate_event(evt)
    assert violation is None
    assert len(engine.get_violations("s1")) == 0


def test_intent_resource_scope_mismatch():
    violations = []
    findings = []

    def on_violation(v, f):
        violations.append(v)
        findings.append(f)

    engine = IntentConformanceEngine(on_violation_callback=on_violation)

    contract = IntentContract(
        intent_id="intent_002",
        session_id="s1",
        scope_id="scope_tool_2",
        description="Read config.py only",
        allowed_operations=["FILE_READ"],
        allowed_resources=["config.py"],
        allowed_network=[],
    )
    engine.register_contract(contract)

    # Non-conformant event: reads .env instead of config.py
    evt = GuardXEvent(
        event_id="evt_read_env",
        session_id="s1",
        sequence_number=2,
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.FILE_READ,
        actor=Actor(actor_id="tool:read_file", actor_type=ActorType.TOOL, display_name="read_file"),
        source=Resource(resource_id="file:.env", resource_type=ResourceType.FILE, uri=".env"),
        destination=Actor(actor_id="tool:read_file", actor_type=ActorType.TOOL, display_name="read_file"),
        execution_scope_id="scope_tool_2",
        provenance_quality=ProvenanceQuality.OBSERVED,
        confidence=1.0,
    )

    v = engine.evaluate_event(evt)
    assert v is not None
    assert v.violation_type == IntentViolationType.RESOURCE_SCOPE_MISMATCH
    assert v.actual_resource == "file:.env"
    assert v.severity == Severity.HIGH
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.INTENT_VIOLATION


def test_intent_undeclared_network_effect():
    violations = []
    findings = []

    def on_violation(v, f):
        violations.append(v)
        findings.append(f)

    engine = IntentConformanceEngine(on_violation_callback=on_violation)

    contract = IntentContract(
        intent_id="intent_003",
        session_id="s1",
        scope_id="scope_tool_3",
        description="Local inspection only",
        allowed_operations=["FILE_READ"],
        allowed_resources=["*"],
        allowed_network=[],  # No network allowed!
    )
    engine.register_contract(contract)

    # Non-conformant network call
    evt = GuardXEvent(
        event_id="evt_net_evil",
        session_id="s1",
        sequence_number=3,
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.NETWORK_REQUEST,
        actor=Actor(actor_id="agent:opencode", actor_type=ActorType.AGENT, display_name="opencode"),
        source=Actor(actor_id="agent:opencode", actor_type=ActorType.AGENT, display_name="opencode"),
        destination=Resource(resource_id="https://evil-analytics.com/data", resource_type=ResourceType.NETWORK_ENDPOINT, uri="https://evil-analytics.com/data"),
        execution_scope_id="scope_tool_3",
        provenance_quality=ProvenanceQuality.OBSERVED,
        confidence=1.0,
    )

    v = engine.evaluate_event(evt)
    assert v is not None
    assert v.violation_type == IntentViolationType.UNDECLARED_NETWORK_EFFECT
    assert "https://evil-analytics.com/data" in v.actual_resource
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.INTENT_VIOLATION
