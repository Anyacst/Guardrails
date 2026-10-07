"""Domain models for GuardX Core."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional
from guardx.core.enums import (
    EventType,
    ActorType,
    ResourceType,
    TrustLevel,
    ProvenanceQuality,
    ScopeStatus,
)


@dataclass(frozen=True)
class Actor:
    """Canonical identifier for an entity initiating or executing actions."""

    actor_id: str
    actor_type: ActorType
    display_name: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Resource:
    """Canonical representation of an entity being accessed, mutated, or contacted."""

    resource_id: str
    resource_type: ResourceType
    uri: str
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Session:
    """Represents a bounded execution session of an AI agent."""

    session_id: str
    agent_name: str
    workspace_root: str
    hmac_key: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScopeProjection:
    """Current-state projection of an ExecutionScope.
    
    Derived from immutable SCOPE_START and SCOPE_END events.
    Historical events are never mutated.
    """

    scope_id: str
    session_id: str
    parent_scope_id: Optional[str]
    actor_id: str
    scope_name: str
    start_time: datetime
    originating_event_id: Optional[str] = None
    end_time: Optional[datetime] = None
    status: ScopeStatus = ScopeStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)

    def close(self, end_time: datetime, status: ScopeStatus) -> None:
        """Updates projection state when SCOPE_END event is recorded."""
        self.end_time = end_time
        self.status = status


@dataclass(frozen=True)
class GuardXEvent:
    """Immutable, append-only record of a runtime occurrence in GuardX.
    
    Guarantees:
    - INV-001: Zero raw secrets in payload.
    - INV-002: Frozen/immutable instance.
    - INV-003: Strictly monotonic session-local sequence_number.
    """

    event_id: str
    session_id: str
    sequence_number: int
    timestamp: datetime
    event_type: EventType

    # Canonical Entities
    actor: Actor
    source: Optional[Resource] = None
    destination: Optional[Resource] = None

    # Distinct Relationship Dimensions
    execution_scope_id: Optional[str] = None
    causal_event_id: Optional[str] = None
    data_lineage_ids: tuple[str, ...] = field(default_factory=tuple)

    # Persistence-safe payload (content-inspected, masked where appropriate)
    payload: Dict[str, Any] = field(default_factory=dict)
    provenance_quality: ProvenanceQuality = ProvenanceQuality.OBSERVED
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Convert any list passed into data_lineage_ids to tuple for immutability
        if isinstance(self.data_lineage_ids, list):
            object.__setattr__(self, "data_lineage_ids", tuple(self.data_lineage_ids))


@dataclass
class RawObservation:
    """Transient in-memory data emitted by a collector before sanitization and sequencing.
    
    IMPORTANT:
    RawObservation is strictly transient in memory. It must NEVER be persisted to
    disk, written to databases, or logged in audit streams before passing through
    SafePayloadBuilder and EventRecorder.
    """

    event_type: EventType
    raw_payload: Dict[str, Any]
    actor_id: str
    source_raw: Optional[str] = None
    destination_raw: Optional[str] = None
    causal_event_id: Optional[str] = None
    data_lineage_ids: List[str] = field(default_factory=list)
    provenance_quality: ProvenanceQuality = ProvenanceQuality.OBSERVED
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
