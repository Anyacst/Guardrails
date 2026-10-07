"""Attack Chain Models for GuardX Milestone 4.

Defines multi-event causal security patterns connecting execution events,
transformations, and information-flow hops into comprehensive attack chains.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from guardx.risk.models import Severity


class AttackChainType(str, Enum):
    """Recognized multi-event causal attack chain archetypes."""
    POTENTIAL_CREDENTIAL_EXFILTRATION = "POTENTIAL_CREDENTIAL_EXFILTRATION"
    ENCODED_SECRET_EGRESS = "ENCODED_SECRET_EGRESS"
    UNEXPECTED_NETWORK_SIDE_EFFECT = "UNEXPECTED_NETWORK_SIDE_EFFECT"


@dataclass(frozen=True)
class AttackChain:
    """Multi-event causal attack chain backed by verified runtime evidence."""
    chain_id: str
    session_id: str
    chain_type: AttackChainType
    severity: Severity
    confidence: float
    ordered_event_ids: List[str]
    related_entity_ids: List[str]
    source: str
    sink: str
    supporting_findings: List[str]
    explanation: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_value_persisted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "session_id": self.session_id,
            "chain_type": self.chain_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "ordered_event_ids": self.ordered_event_ids,
            "related_entity_ids": self.related_entity_ids,
            "source": self.source,
            "sink": self.sink,
            "supporting_findings": self.supporting_findings,
            "explanation": self.explanation,
            "created_at": self.created_at.isoformat(),
            "raw_value_persisted": False,
            "metadata": self.metadata,
        }
