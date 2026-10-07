"""Security and Risk Finding Models for GuardX Milestone 4.

Defines immutable SecurityFinding / RiskFinding objects, severities, and finding categories.
Zero raw secrets invariant: Plaintext is NEVER stored in findings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Deterministic severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"


class FindingCategory(str, Enum):
    """Categorization of security findings."""
    CREDENTIAL_EXFILTRATION = "CREDENTIAL_EXFILTRATION"
    CREDENTIAL_DISCLOSURE = "CREDENTIAL_DISCLOSURE"
    ENCODED_SECRET_DISCLOSURE = "ENCODED_SECRET_DISCLOSURE"
    PII_EXFILTRATION = "PII_EXFILTRATION"
    PII_DISCLOSURE = "PII_DISCLOSURE"
    UNAUTHORIZED_EGRESS = "UNAUTHORIZED_EGRESS"
    INTENT_VIOLATION = "INTENT_VIOLATION"
    ATTACK_CHAIN = "ATTACK_CHAIN"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class SecurityFinding:
    """Immutable first-class security intelligence finding backed by proven evidence."""
    finding_id: str
    session_id: str
    rule_id: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float
    source_entity_id: Optional[str]
    source_resource_id: Optional[str]
    destination_id: str
    source_trust: str
    destination_trust: str
    boundary_crossing: str
    representation: str
    lineage_path: List[Dict[str, Any]]
    execution_event_ids: List[str]
    supporting_event_ids: List[str]
    explanation: str
    provenance_quality: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_value_persisted: bool = False  # Mandatory invariant
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "source_entity_id": self.source_entity_id,
            "source_resource_id": self.source_resource_id,
            "destination_id": self.destination_id,
            "source_trust": self.source_trust,
            "destination_trust": self.destination_trust,
            "boundary_crossing": self.boundary_crossing,
            "representation": self.representation,
            "lineage_path": self.lineage_path,
            "execution_event_ids": self.execution_event_ids,
            "supporting_event_ids": self.supporting_event_ids,
            "explanation": self.explanation,
            "provenance_quality": self.provenance_quality,
            "created_at": self.created_at.isoformat(),
            "raw_value_persisted": False,
            "metadata": self.metadata,
        }
