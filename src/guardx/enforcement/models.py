"""Enforcement Data Models for GuardX Milestone 5.

Implements ProspectiveAction, EnforcementDecision, ReviewRequest, ActionType, ReviewStatus,
and canonical action hashing.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid

from guardx.policy.models import DecisionType
from guardx.trust.models import TrustTier


class ActionType(str, Enum):
    """Types of actions subject to prospective runtime enforcement."""
    LLM_REQUEST = "LLM_REQUEST"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    FILE_WRITE = "FILE_WRITE"
    TOOL_CALL = "TOOL_CALL"
    PROCESS_EXEC = "PROCESS_EXEC"


class ReviewStatus(str, Enum):
    """Statuses for human-in-the-loop review requests."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


def compute_action_hash(
    action_type: str,
    destination: str,
    operation: str,
    tool_name: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    entity_refs: Optional[List[str]] = None,
    execution_scope_id: Optional[str] = None,
) -> str:
    """Computes a deterministic canonical cryptographic digest over proposed execution parameters.

    Binds the authorization decision to the exact canonical action parameters (INV-M5-006).
    """
    canonical_dict = {
        "action_type": str(action_type),
        "destination": str(destination),
        "operation": str(operation),
        "tool_name": str(tool_name or ""),
        "payload": payload or {},
        "entity_refs": sorted(entity_refs or []),
        "execution_scope_id": str(execution_scope_id or ""),
    }
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProspectiveAction:
    """Immutable proposed action evaluated before any side effect occurs.

    Never contains raw plaintext secrets in persistent structures.
    """
    action_id: str
    session_id: str
    execution_scope_id: Optional[str]
    actor_id: str
    action_type: ActionType
    source: str
    destination: str
    operation: str
    tool_name: Optional[str]
    safe_payload: Dict[str, Any]
    entity_refs: List[str]
    destination_trust: TrustTier
    intent_contract_id: Optional[str]
    action_hash: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        session_id: str,
        action_type: ActionType,
        destination: str,
        operation: str,
        actor_id: str = "agent",
        source: str = "agent",
        tool_name: Optional[str] = None,
        safe_payload: Optional[Dict[str, Any]] = None,
        entity_refs: Optional[List[str]] = None,
        destination_trust: TrustTier = TrustTier.UNTRUSTED_EXTERNAL,
        execution_scope_id: Optional[str] = None,
        intent_contract_id: Optional[str] = None,
        action_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ProspectiveAction":
        aid = action_id or f"action_{uuid.uuid4().hex[:12]}"
        payload = safe_payload or {}
        refs = entity_refs or []
        a_hash = compute_action_hash(
            action_type=action_type.value,
            destination=destination,
            operation=operation,
            tool_name=tool_name,
            payload=payload,
            entity_refs=refs,
            execution_scope_id=execution_scope_id,
        )
        return cls(
            action_id=aid,
            session_id=session_id,
            execution_scope_id=execution_scope_id,
            actor_id=actor_id,
            action_type=action_type,
            source=source,
            destination=destination,
            operation=operation,
            tool_name=tool_name,
            safe_payload=payload,
            entity_refs=refs,
            destination_trust=destination_trust,
            intent_contract_id=intent_contract_id,
            action_hash=a_hash,
            metadata=metadata or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "session_id": self.session_id,
            "execution_scope_id": self.execution_scope_id,
            "actor_id": self.actor_id,
            "action_type": self.action_type.value,
            "source": self.source,
            "destination": self.destination,
            "operation": self.operation,
            "tool_name": self.tool_name,
            "safe_payload": self.safe_payload,
            "entity_refs": self.entity_refs,
            "destination_trust": self.destination_trust.value,
            "intent_contract_id": self.intent_contract_id,
            "action_hash": self.action_hash,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class EnforcementDecision:
    """Immutable enforcement outcome bound to a specific ProspectiveAction and its action_hash."""
    decision_id: str
    session_id: str
    action_id: str
    action_hash: str
    decision: DecisionType
    matched_policy_ids: List[str]
    primary_policy_id: Optional[str]
    reason: str
    risk_finding_ids: List[str]
    matched_entity_ids: List[str]
    original_representation: Optional[str]
    resulting_representation: Optional[str]
    destination: str
    destination_trust: str
    requires_review: bool
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "session_id": self.session_id,
            "action_id": self.action_id,
            "action_hash": self.action_hash,
            "decision": self.decision.value,
            "matched_policy_ids": self.matched_policy_ids,
            "primary_policy_id": self.primary_policy_id,
            "reason": self.reason,
            "risk_finding_ids": self.risk_finding_ids,
            "matched_entity_ids": self.matched_entity_ids,
            "original_representation": self.original_representation,
            "resulting_representation": self.resulting_representation,
            "destination": self.destination,
            "destination_trust": self.destination_trust,
            "requires_review": self.requires_review,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ReviewRequest:
    """Immutable pending or resolved human review item (INV-M5-004, INV-M5-005)."""
    review_id: str
    session_id: str
    action_id: str
    decision_id: str
    action_hash: str
    reason: str
    severity: str
    policy_id: str
    safe_preview: Dict[str, Any]
    entity_classifications: List[str]
    destination: str
    status: ReviewStatus = ReviewStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None
    resolver: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def resolve(self, new_status: ReviewStatus, resolver: str = "human") -> "ReviewRequest":
        """Returns a new immutable ReviewRequest with updated status."""
        return ReviewRequest(
            review_id=self.review_id,
            session_id=self.session_id,
            action_id=self.action_id,
            decision_id=self.decision_id,
            action_hash=self.action_hash,
            reason=self.reason,
            severity=self.severity,
            policy_id=self.policy_id,
            safe_preview=self.safe_preview,
            entity_classifications=self.entity_classifications,
            destination=self.destination,
            status=new_status,
            created_at=self.created_at,
            resolved_at=datetime.now(timezone.utc).isoformat(),
            resolver=resolver,
            metadata=self.metadata,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "review_id": self.review_id,
            "session_id": self.session_id,
            "action_id": self.action_id,
            "decision_id": self.decision_id,
            "action_hash": self.action_hash,
            "reason": self.reason,
            "severity": self.severity,
            "policy_id": self.policy_id,
            "safe_preview": self.safe_preview,
            "entity_classifications": self.entity_classifications,
            "destination": self.destination,
            "status": self.status.value,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "resolver": self.resolver,
            "metadata": self.metadata,
        }
