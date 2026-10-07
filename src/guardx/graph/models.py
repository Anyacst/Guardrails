"""Execution Provenance Graph Models & Schemas.

Guarantees:
- Explicit node types: USER, AGENT, TOOL, FILE, PROCESS, NETWORK_ENDPOINT, LLM, EXECUTION_SCOPE.
- Explicit edge types: INVOKED, READ_FROM, WROTE_TO, SPAWNED, SENT_TO, RECEIVED_FROM, CAUSED_BY, BELONGS_TO_SCOPE, RETURNED_TO.
- Every edge retains supporting event_id, provenance_quality, and confidence.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from guardx.core.enums import ProvenanceQuality


class NodeType(str, Enum):
    USER = "USER"
    AGENT = "AGENT"
    TOOL = "TOOL"
    FILE = "FILE"
    PROCESS = "PROCESS"
    NETWORK_ENDPOINT = "NETWORK_ENDPOINT"
    LLM = "LLM"
    EXECUTION_SCOPE = "EXECUTION_SCOPE"


class EdgeType(str, Enum):
    INVOKED = "INVOKED"
    READ_FROM = "READ_FROM"
    WROTE_TO = "WROTE_TO"
    SPAWNED = "SPAWNED"
    SENT_TO = "SENT_TO"
    RECEIVED_FROM = "RECEIVED_FROM"
    CAUSED_BY = "CAUSED_BY"
    BELONGS_TO_SCOPE = "BELONGS_TO_SCOPE"
    RETURNED_TO = "RETURNED_TO"


@dataclass(frozen=True)
class GraphNode:
    """Canonical vertex in the execution provenance DAG."""

    node_id: str                       # e.g., "agent:opencode", "file:.env", "tool:read_file"
    node_type: NodeType
    label: str
    session_id: str
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "session_id": self.session_id,
            "properties": self.properties,
            "first_seen": self.first_seen.isoformat(),
        }


@dataclass(frozen=True)
class GraphEdge:
    """Directed causal or execution edge between two GraphNodes."""

    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    event_id: str                      # Mandatory provenance handle linking back to immutable event
    provenance_quality: ProvenanceQuality = ProvenanceQuality.OBSERVED
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "event_id": self.event_id,
            "provenance_quality": self.provenance_quality.value,
            "confidence": self.confidence,
            "properties": self.properties,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ExecutionGraph:
    """Subgraph or complete DAG representation for a session."""

    session_id: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }
