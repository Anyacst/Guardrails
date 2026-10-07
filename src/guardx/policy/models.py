"""Policy Models for GuardX Milestone 5.

Defines decision types, policy match structures, and PolicyRule definitions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class DecisionType(str, Enum):
    """Binding runtime policy decision types."""
    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    BLOCK = "BLOCK"
    HUMAN_REVIEW = "HUMAN_REVIEW"


# Strict security order for conflict resolution
DECISION_PRECEDENCE: Dict[DecisionType, int] = {
    DecisionType.BLOCK: 4,
    DecisionType.HUMAN_REVIEW: 3,
    DecisionType.MODIFY: 2,
    DecisionType.ALLOW: 1,
}


@dataclass(frozen=True)
class PolicyMatch:
    """Represents a single policy rule matching a prospective action."""
    policy_id: str
    decision: DecisionType
    priority: int
    reason: str
    modifier: Optional[str] = None
    rule_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyRule:
    """Declarative, deterministic policy rule definition."""
    policy_id: str
    name: str
    description: str
    decision: DecisionType
    priority: int = 100
    enabled: bool = True
    modifier: Optional[str] = None  # e.g., "TOKENIZE", "REDACT"
    reason: str = ""
    allowed_classifications: Optional[Set[str]] = None
    allowed_representations: Optional[Set[str]] = None
    allowed_destination_trusts: Optional[Set[str]] = None
    requires_intent_violation: Optional[bool] = None
    match_conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "decision": self.decision.value,
            "priority": self.priority,
            "enabled": self.enabled,
            "modifier": self.modifier,
            "reason": self.reason,
            "allowed_classifications": sorted(list(self.allowed_classifications)) if self.allowed_classifications else None,
            "allowed_representations": sorted(list(self.allowed_representations)) if self.allowed_representations else None,
            "allowed_destination_trusts": sorted(list(self.allowed_destination_trusts)) if self.allowed_destination_trusts else None,
            "requires_intent_violation": self.requires_intent_violation,
            "metadata": self.metadata,
        }
