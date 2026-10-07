"""PostExecutionVerifier for GuardX Milestone 5.

Verifies that executed side effects match the prospective authorized action (INV-M5-009).
Binds ProspectiveAction, EnforcementDecision, and observed runtime GuardXEvents.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional

from guardx.core.enums import EventType
from guardx.core.models import GuardXEvent
from guardx.enforcement.models import ActionType, EnforcementDecision, ProspectiveAction


@dataclass(frozen=True)
class VerificationResult:
    """Immutable result of post-execution verification."""
    verification_id: str
    session_id: str
    action_id: str
    decision_id: str
    action_hash: str
    status: str  # "VERIFIED" or "MISMATCH"
    is_verified: bool
    observed_event_ids: List[str]
    details: Dict[str, Any]
    mismatch_reasons: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "session_id": self.session_id,
            "action_id": self.action_id,
            "decision_id": self.decision_id,
            "action_hash": self.action_hash,
            "status": self.status,
            "is_verified": self.is_verified,
            "observed_event_ids": self.observed_event_ids,
            "details": self.details,
            "mismatch_reasons": self.mismatch_reasons,
            "created_at": self.created_at,
        }


class PostExecutionVerifier:
    """Compares prospective authorized action with observed runtime events."""

    def __init__(self):
        self._lock = threading.Lock()
        self._results: Dict[str, VerificationResult] = {}

    def verify(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        observed_events: List[GuardXEvent],
    ) -> VerificationResult:
        """Verifies observed events against the authorized prospective action."""
        import uuid
        vid = f"verif_{uuid.uuid4().hex[:12]}"
        mismatches: List[str] = []
        observed_ids = [e.event_id for e in observed_events]

        if not observed_events:
            mismatches.append("Zero supporting runtime observation events available")
            res = VerificationResult(
                verification_id=vid,
                session_id=action.session_id,
                action_id=action.action_id,
                decision_id=decision.decision_id,
                action_hash=action.action_hash,
                status="MISMATCH",
                is_verified=False,
                observed_event_ids=[],
                details={"error": "no_observed_events"},
                mismatch_reasons=mismatches,
            )
            with self._lock:
                self._results[vid] = res
            return res

        # Primary observed event (usually the principal side-effect event)
        primary_evt = observed_events[0]

        # 1. Verify Destination / Target Resource
        observed_dest = (
            primary_evt.destination
            or primary_evt.resource
            or primary_evt.safe_payload.get("endpoint")
            or primary_evt.safe_payload.get("model")
            or primary_evt.safe_payload.get("path")
            or ""
        )
        if action.destination and observed_dest:
            # Check for substring or normalized equality
            if action.destination not in observed_dest and observed_dest not in action.destination:
                mismatches.append(
                    f"Destination mismatch: prospective authorized destination '{action.destination}' != observed '{observed_dest}'"
                )

        # 2. Verify Execution Scope
        if action.execution_scope_id and primary_evt.scope_id:
            if action.execution_scope_id != primary_evt.scope_id:
                mismatches.append(
                    f"Scope mismatch: prospective scope '{action.execution_scope_id}' != observed '{primary_evt.scope_id}'"
                )

        # 3. Verify Action Type vs Event Type
        type_matched = False
        if action.action_type == ActionType.LLM_REQUEST and primary_evt.event_type in (EventType.LLM_REQUEST, EventType.LLM_RESPONSE):
            type_matched = True
        elif action.action_type == ActionType.NETWORK_REQUEST and primary_evt.event_type in (EventType.NETWORK_REQUEST, EventType.NETWORK_RESPONSE):
            type_matched = True
        elif action.action_type == ActionType.FILE_WRITE and primary_evt.event_type in (EventType.FILE_WRITE, EventType.TOOL_CALL):
            type_matched = True
        elif action.action_type == ActionType.TOOL_CALL and primary_evt.event_type in (EventType.TOOL_CALL, EventType.TOOL_RESULT):
            type_matched = True
        elif action.action_type == ActionType.PROCESS_EXEC and primary_evt.event_type in (EventType.PROCESS_EXEC, EventType.PROCESS_SPAWNED):
            type_matched = True

        if not type_matched:
            mismatches.append(
                f"Action type mismatch: prospective '{action.action_type.value}' != observed event '{primary_evt.event_type.value}'"
            )

        is_verified = (len(mismatches) == 0)
        status = "VERIFIED" if is_verified else "MISMATCH"

        res = VerificationResult(
            verification_id=vid,
            session_id=action.session_id,
            action_id=action.action_id,
            decision_id=decision.decision_id,
            action_hash=action.action_hash,
            status=status,
            is_verified=is_verified,
            observed_event_ids=observed_ids,
            details={
                "action_type": action.action_type.value,
                "prospective_destination": action.destination,
                "observed_destination": observed_dest,
                "event_types": [e.event_type.value for e in observed_events],
            },
            mismatch_reasons=mismatches,
        )

        with self._lock:
            self._results[vid] = res
        return res

    def get_result(self, verification_id: str) -> Optional[VerificationResult]:
        with self._lock:
            return self._results.get(verification_id)

    def get_results_for_session(self, session_id: str) -> List[VerificationResult]:
        with self._lock:
            return [r for r in self._results.values() if r.session_id == session_id]
