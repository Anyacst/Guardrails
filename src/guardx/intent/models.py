"""Intent Contract and Conformance Models for GuardX Milestone 4.

Defines IntentContract declarations and IntentViolation findings when actual
runtime operations deviate from declared task parameters.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from guardx.risk.models import Severity


class IntentViolationType(str, Enum):
    """Categorization of intent conformance violations."""
    CONFORMANT = "CONFORMANT"
    RESOURCE_SCOPE_MISMATCH = "RESOURCE_SCOPE_MISMATCH"
    UNDECLARED_NETWORK_EFFECT = "UNDECLARED_NETWORK_EFFECT"
    UNDECLARED_PROCESS_EXECUTION = "UNDECLARED_PROCESS_EXECUTION"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"


@dataclass(frozen=True)
class IntentContract:
    """Structured contract declaring allowed operations, resources, and boundaries for a scope."""
    intent_id: str
    session_id: str
    scope_id: str
    description: str
    allowed_operations: List[str] = field(default_factory=list)  # e.g., ["FILE_READ"]
    allowed_resources: List[str] = field(default_factory=list)   # e.g., ["config.py", "app.py"]
    allowed_network: List[str] = field(default_factory=list)     # e.g., []
    allowed_processes: List[str] = field(default_factory=list)   # e.g., []
    declared_by: str = "agent"
    originating_event_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "session_id": self.session_id,
            "scope_id": self.scope_id,
            "description": self.description,
            "allowed_operations": self.allowed_operations,
            "allowed_resources": self.allowed_resources,
            "allowed_network": self.allowed_network,
            "allowed_processes": self.allowed_processes,
            "declared_by": self.declared_by,
            "originating_event_id": self.originating_event_id,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class IntentViolation:
    """Immutable finding documenting a deviation between declared intent and actual runtime effect."""
    violation_id: str
    session_id: str
    intent_id: str
    scope_id: str
    violation_type: IntentViolationType
    actual_operation: str
    actual_resource: str
    event_id: str
    severity: Severity
    explanation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "session_id": self.session_id,
            "intent_id": self.intent_id,
            "scope_id": self.scope_id,
            "violation_type": self.violation_type.value,
            "actual_operation": self.actual_operation,
            "actual_resource": self.actual_resource,
            "event_id": self.event_id,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
