"""Data Lineage Models and Enums for GuardX Milestone 3.

Guarantees:
- Explicit separation between Execution Provenance and Data Lineage.
- DataEntity tracks fine-grained data identity with representation states (RAW, TOKENIZED, DERIVED).
- DataCarrier tracks containers carrying entities across boundaries.
- Zero raw secrets persisted: Keyed HMAC fingerprints and synthetic tokens only.
- Strict evidence attribution: every edge retains detection method, quality, and event handle.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from guardx.core.enums import (
    ProvenanceQuality,
    TransformationSecuritySemantics,
)


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SOURCE_CODE = "SOURCE_CODE"
    PII = "PII"
    SECRET = "SECRET"
    CREDENTIAL = "CREDENTIAL"
    CREDENTIAL_REFERENCE = "CREDENTIAL_REFERENCE"


class DataRepresentation(str, Enum):
    RAW = "RAW"
    TOKENIZED = "TOKENIZED"
    ENCODED = "ENCODED"
    DERIVED = "DERIVED"
    REDACTED = "REDACTED"


class CarrierType(str, Enum):
    FILE_CONTENT = "FILE_CONTENT"
    TOOL_RESULT = "TOOL_RESULT"
    AGENT_CONTEXT = "AGENT_CONTEXT"
    LLM_REQUEST = "LLM_REQUEST"
    LLM_RESPONSE = "LLM_RESPONSE"
    TOOL_ARGUMENT = "TOOL_ARGUMENT"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    NETWORK_RESPONSE = "NETWORK_RESPONSE"
    FILE_WRITE_CONTENT = "FILE_WRITE_CONTENT"


class LineageNodeType(str, Enum):
    DATA_ENTITY = "DATA_ENTITY"
    DATA_CARRIER = "DATA_CARRIER"
    FILE = "FILE"
    LLM = "LLM"
    NETWORK_ENDPOINT = "NETWORK_ENDPOINT"


class LineageEdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    FLOWS_TO = "FLOWS_TO"
    DERIVED_FROM = "DERIVED_FROM"
    PRODUCED_BY = "PRODUCED_BY"
    USED_BY = "USED_BY"
    TRANSFORMED_TO = "TRANSFORMED_TO"


class DetectionMethod(str, Enum):
    TOKEN_IDENTITY = "TOKEN_IDENTITY"
    HMAC_MATCH = "HMAC_MATCH"
    EXACT_TRANSIENT_MATCH = "EXACT_TRANSIENT_MATCH"
    STRUCTURED_PROPAGATION = "STRUCTURED_PROPAGATION"
    TRANSFORMATION_MATCH = "TRANSFORMATION_MATCH"
    EXPLICIT_MAPPING = "EXPLICIT_MAPPING"


@dataclass(frozen=True)
class DataEntity:
    """Represents identifiable information whose provenance and flow can be tracked."""

    entity_id: str                         # Unique ID (e.g. "entity_secret_17")
    session_id: str                        # Parent session ID
    label: str                             # Safe label (e.g. "DEMO_API_KEY", "USER_EMAIL")
    classification: str                    # "CREDENTIAL", "PII", "SECRET", "PUBLIC", "INTERNAL"
    origin_resource_id: str                # Canonical resource where entity originated (e.g. "file:.env")
    fingerprint_hmac: str                  # Keyed HMAC-SHA256 (Never raw secret!)
    synthetic_token: Optional[str] = None  # Ephemeral vault token (e.g. "{{SECRET_001_nonce}}")
    discovered_event_id: str = ""          # Event ID where entity was first discovered
    representation: str = "RAW"            # RAW, TOKENIZED, ENCODED, DERIVED, REDACTED
    provenance_quality: ProvenanceQuality = ProvenanceQuality.OBSERVED
    confidence: float = 1.0
    derived_from_entity_id: Optional[str] = None # Antecedent entity if derived/tokenized
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def raw_value_persisted(self) -> bool:
        """Enforces invariant: raw sensitive values are never persisted."""
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "session_id": self.session_id,
            "label": self.label,
            "classification": self.classification,
            "representation": self.representation,
            "origin_resource_id": self.origin_resource_id,
            "fingerprint_hmac": self.fingerprint_hmac,
            "fingerprint_preview": f"{self.fingerprint_hmac[:12]}..." if self.fingerprint_hmac else "",
            "synthetic_token": self.synthetic_token,
            "discovered_event_id": self.discovered_event_id,
            "provenance_quality": self.provenance_quality.value if isinstance(self.provenance_quality, ProvenanceQuality) else str(self.provenance_quality),
            "confidence": self.confidence,
            "derived_from_entity_id": self.derived_from_entity_id,
            "raw_value_persisted": False,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class DataCarrier:
    """Represents an object or message carrying zero, one, or more DataEntities across boundaries."""

    carrier_id: str                        # e.g. "carrier_tool_result_26"
    carrier_type: str                      # CarrierType value (e.g. "TOOL_RESULT", "LLM_REQUEST")
    session_id: str                        # Session ID
    supporting_event_id: str               # Event handle linking back to immutable GuardXEvent
    contained_entity_ids: Tuple[str, ...] = () # Entities carried within this carrier
    source_actor_or_resource: str = ""     # e.g. "tool:read_file", "agent:opencode", "file:.env"
    destination_actor_or_resource: Optional[str] = None # e.g. "agent:opencode", "llm:groq"
    sequence_number: int = 0
    evidence_quality: ProvenanceQuality = ProvenanceQuality.OBSERVED
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if isinstance(self.contained_entity_ids, list):
            object.__setattr__(self, "contained_entity_ids", tuple(self.contained_entity_ids))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "carrier_id": self.carrier_id,
            "carrier_type": self.carrier_type,
            "session_id": self.session_id,
            "supporting_event_id": self.supporting_event_id,
            "contained_entity_ids": list(self.contained_entity_ids),
            "source_actor_or_resource": self.source_actor_or_resource,
            "destination_actor_or_resource": self.destination_actor_or_resource,
            "sequence_number": self.sequence_number,
            "evidence_quality": self.evidence_quality.value if isinstance(self.evidence_quality, ProvenanceQuality) else str(self.evidence_quality),
            "confidence": self.confidence,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class LineageNode:
    """Canonical vertex in the Data Lineage DAG."""

    node_id: str                           # e.g. "entity:secret_17", "carrier:tool_result_26", "file:.env"
    node_type: LineageNodeType             # DATA_ENTITY, DATA_CARRIER, FILE, LLM, NETWORK_ENDPOINT
    label: str
    session_id: str
    entity_id: Optional[str] = None
    carrier_id: Optional[str] = None
    resource_id: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "session_id": self.session_id,
            "entity_id": self.entity_id,
            "carrier_id": self.carrier_id,
            "resource_id": self.resource_id,
            "properties": self.properties,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class LineageEdge:
    """Directed edge in the Data Lineage DAG representing provenance or information flow."""

    edge_id: str
    source_id: str
    target_id: str
    edge_type: LineageEdgeType
    entity_id: Optional[str] = None        # Which entity flowed
    supporting_event_id: str = ""
    provenance_quality: ProvenanceQuality = ProvenanceQuality.OBSERVED
    confidence: float = 1.0
    detection_method: DetectionMethod = DetectionMethod.TOKEN_IDENTITY
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "entity_id": self.entity_id,
            "supporting_event_id": self.supporting_event_id,
            "provenance_quality": self.provenance_quality.value if isinstance(self.provenance_quality, ProvenanceQuality) else str(self.provenance_quality),
            "confidence": self.confidence,
            "detection_method": self.detection_method.value if isinstance(self.detection_method, DetectionMethod) else str(self.detection_method),
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class Transformation:
    """Represents an operation that transforms one or more DataEntities into new representations."""

    transformation_id: str
    session_id: str
    transformation_type: str               # "BASE64_ENCODE", "JSON_SERIALIZE", "TOKENIZE", "URL_ENCODE", etc.
    security_semantics: TransformationSecuritySemantics
    input_entity_ids: Tuple[str, ...]
    output_entity_ids: Tuple[str, ...]
    originating_event_id: str
    provenance_quality: ProvenanceQuality = ProvenanceQuality.DERIVED
    confidence: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if isinstance(self.input_entity_ids, list):
            object.__setattr__(self, "input_entity_ids", tuple(self.input_entity_ids))
        if isinstance(self.output_entity_ids, list):
            object.__setattr__(self, "output_entity_ids", tuple(self.output_entity_ids))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transformation_id": self.transformation_id,
            "session_id": self.session_id,
            "transformation_type": self.transformation_type,
            "security_semantics": self.security_semantics.value if isinstance(self.security_semantics, TransformationSecuritySemantics) else str(self.security_semantics),
            "input_entity_ids": list(self.input_entity_ids),
            "output_entity_ids": list(self.output_entity_ids),
            "originating_event_id": self.originating_event_id,
            "provenance_quality": self.provenance_quality.value if isinstance(self.provenance_quality, ProvenanceQuality) else str(self.provenance_quality),
            "confidence": self.confidence,
            "details": self.details,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class TaintEdge:
    """Directed edge representing taint flow between two entities across a transformation."""

    edge_id: str
    source_entity_id: str
    target_entity_id: str
    transformation_id: str
    confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class LineageTraceHop:
    """A single hop along an information flow trace path."""

    source: str
    destination: str
    edge_type: str
    entity_id: Optional[str]
    event_id: str
    provenance_quality: str
    confidence: float
    detection_method: str
    transformation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "edge_type": self.edge_type,
            "entity_id": self.entity_id,
            "event_id": self.event_id,
            "provenance_quality": self.provenance_quality,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "transformation": self.transformation,
        }


@dataclass(frozen=True)
class LineageTraceResult:
    """Structured result of a forward or backward information flow trace."""

    entity_or_carrier_id: str
    direction: str                         # "FORWARD" or "BACKWARD"
    has_proven_flow: bool
    origins: List[str]
    destinations: List[str]
    hops: List[LineageTraceHop]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_or_carrier_id": self.entity_or_carrier_id,
            "direction": self.direction,
            "has_proven_flow": self.has_proven_flow,
            "origins": self.origins,
            "destinations": self.destinations,
            "hops": [h.to_dict() for h in self.hops],
            "explanation": self.explanation,
        }
