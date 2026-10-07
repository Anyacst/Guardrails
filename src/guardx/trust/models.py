"""Trust Boundary Models for GuardX Milestone 4.

Defines trust levels, boundaries, and boundary crossings between resources,
actors, processes, endpoints, and external LLM services.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TrustLevel(str, Enum):
    """Hierarchical and contextual trust classification."""
    LOCAL = "LOCAL"                               # Workspace, local files, child processes, localhost
    TRUSTED_INTERNAL = "TRUSTED_INTERNAL"         # Configured internal company API, secure intranet
    TRUSTED_EXTERNAL = "TRUSTED_EXTERNAL"         # Explicitly approved external services/APIs
    EXTERNAL_LLM = "EXTERNAL_LLM"                 # Remote LLM providers (Groq, OpenAI, Anthropic, OpenRouter)
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"     # Arbitrary untrusted internet endpoints
    UNKNOWN = "UNKNOWN"                           # Unclassified endpoints


TrustTier = TrustLevel


@dataclass(frozen=True)
class TrustBoundaryCrossing:
    """Represents identifiable data or execution crossing from one trust zone to another."""
    crossing_id: str
    session_id: str
    source_resource_or_actor: str
    destination_resource_or_actor: str
    source_trust: TrustLevel
    destination_trust: TrustLevel
    entity_id: Optional[str] = None
    carrier_id: Optional[str] = None
    supporting_event_id: Optional[str] = None
    lineage_hop_count: int = 1
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def boundary_name(self) -> str:
        """Human-readable boundary transition name, e.g. LOCAL -> EXTERNAL_LLM."""
        return f"{self.source_trust.value} -> {self.destination_trust.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "session_id": self.session_id,
            "source_resource_or_actor": self.source_resource_or_actor,
            "destination_resource_or_actor": self.destination_resource_or_actor,
            "source_trust": self.source_trust.value,
            "destination_trust": self.destination_trust.value,
            "boundary_name": self.boundary_name,
            "entity_id": self.entity_id,
            "carrier_id": self.carrier_id,
            "supporting_event_id": self.supporting_event_id,
            "lineage_hop_count": self.lineage_hop_count,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
