"""EnforcementGateway for GuardX Milestone 5.

The core prospective runtime guardrail. Enforces security decisions BEFORE
any protected side effect occurs (INV-M5-001 through INV-M5-009).
"""

import asyncio
from datetime import datetime, timezone
import inspect
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import uuid

from guardx.core.enums import EventType, ProvenanceQuality
# pyrefly: ignore [missing-import]
from guardx.core.recorder import EventRecorder
from guardx.core.models import GuardXEvent
from guardx.enforcement.analyzer import ProspectiveAnalyzer
from guardx.enforcement.exceptions import (
    ActionBlockedError,
    ModificationFailedError,
    ReviewDeniedError,
    ReviewExpiredError,
    ReviewRequiredError,
    TOCTOUViolationError,
)
from guardx.enforcement.models import (
    ActionType,
    EnforcementDecision,
    ProspectiveAction,
    ReviewRequest,
    ReviewStatus,
    compute_action_hash,
)
from guardx.enforcement.modifier import ActionModifier
from guardx.enforcement.review import HumanReviewQueue
from guardx.enforcement.verification import PostExecutionVerifier, VerificationResult
from guardx.intent.models import IntentContract
from guardx.policy.engine import PolicyEngine
from guardx.policy.models import DecisionType, PolicyMatch
from guardx.trust.models import TrustLevel


class EnforcementGateway:
    """Evaluates prospective actions and guards execution boundaries."""

    def __init__(
        self,
        recorder: Optional[EventRecorder] = None,
        policy_engine: Optional[PolicyEngine] = None,
        analyzer: Optional[ProspectiveAnalyzer] = None,
        modifier: Optional[ActionModifier] = None,
        review_queue: Optional[HumanReviewQueue] = None,
        verifier: Optional[PostExecutionVerifier] = None,
        token_store: Optional[Any] = None,
    ):
        self.recorder = recorder
        self.policy_engine = policy_engine or PolicyEngine()
        self.analyzer = analyzer or ProspectiveAnalyzer()
        self.modifier = modifier or ActionModifier(token_store=token_store)
        self.review_queue = review_queue or HumanReviewQueue()
        self.verifier = verifier or PostExecutionVerifier()
        self._decisions: Dict[str, EnforcementDecision] = {}
        self._actions: Dict[str, ProspectiveAction] = {}
        self._action_events: Dict[str, List[GuardXEvent]] = {}
        self._lock = threading.Lock()

    def evaluate(
        self,
        action: ProspectiveAction,
        raw_content: Any = None,
        intent_contracts: Optional[List[IntentContract]] = None,
    ) -> EnforcementDecision:
        """Prospective evaluation of an action before side effect execution."""
        with self._lock:
            self._actions[action.action_id] = action

        # 1. Emit ACTION_PROPOSED
        self._emit_event(
            event_type=EventType.ACTION_PROPOSED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload={
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "destination": action.destination,
                "operation": action.operation,
                "action_hash": action.action_hash,
                "entity_refs": action.entity_refs,
            },
        )

        # 2. Prospective analysis
        analysis = self.analyzer.analyze(
            action=action,
            raw_content=raw_content,
            intent_contracts=intent_contracts,
        )

        # 3. Policy evaluation
        decision_type, primary_match, all_matches = self.policy_engine.evaluate(
            classification=analysis.primary_classification,
            destination_trust=analysis.destination_trust,
            representation=analysis.primary_representation,
            transformation_semantics=analysis.transformation_semantics,
            has_intent_violation=analysis.has_intent_violation,
            action_type=action.action_type.value,
            context={"destination": action.destination, "operation": action.operation},
        )

        # 4. Emit POLICY_MATCHED
        for m in all_matches:
            self._emit_event(
                event_type=EventType.POLICY_MATCHED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload={
                    "action_id": action.action_id,
                    "policy_id": m.policy_id,
                    "rule_name": m.rule_name,
                    "decision": m.decision.value,
                    "priority": m.priority,
                    "reason": m.reason,
                },
            )

        # 5. Build immutable EnforcementDecision
        decision_id = f"dec_{uuid.uuid4().hex[:12]}"
        decision = EnforcementDecision(
            decision_id=decision_id,
            session_id=action.session_id,
            action_id=action.action_id,
            action_hash=action.action_hash,
            decision=decision_type,
            matched_policy_ids=[m.policy_id for m in all_matches],
            primary_policy_id=primary_match.policy_id if primary_match else None,
            reason=primary_match.reason if primary_match else "Default policy resolution",
            risk_finding_ids=analysis.risk_finding_ids,
            matched_entity_ids=[e.entity_id for e in analysis.detected_entities],
            original_representation=analysis.primary_representation,
            resulting_representation=(
                "TOKENIZED" if decision_type == DecisionType.MODIFY else analysis.primary_representation
            ),
            destination=action.destination,
            destination_trust=analysis.destination_trust.value,
            requires_review=(decision_type == DecisionType.HUMAN_REVIEW),
            created_at=datetime.now(timezone.utc).isoformat(),
            metadata={"rule_count": len(all_matches)},
        )

        with self._lock:
            self._decisions[decision.decision_id] = decision

        # 6. Emit DECISION_CREATED
        self._emit_event(
            event_type=EventType.DECISION_CREATED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload=decision.to_dict(),
        )

        return decision

    def execute(
        self,
        action: ProspectiveAction,
        executor: Callable[..., Any],
        raw_content: Any = None,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]] = None,
        intent_contracts: Optional[List[IntentContract]] = None,
    ) -> Any:
        """Synchronous enforcement execution lifecycle."""
        decision = self.evaluate(action=action, raw_content=raw_content, intent_contracts=intent_contracts)

        # TOCTOU Verification before proceeding (INV-M5-006)
        self._verify_anti_toctou(action, decision)

        # BLOCK (INV-M5-001)
        if decision.decision == DecisionType.BLOCK:
            self._emit_event(
                event_type=EventType.ACTION_BLOCKED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload={
                    "action_id": action.action_id,
                    "decision_id": decision.decision_id,
                    "reason": decision.reason,
                    "destination": action.destination,
                },
            )
            # Executor is NEVER called
            raise ActionBlockedError(
                f"Action blocked by policy {decision.primary_policy_id}: {decision.reason}",
                action_id=action.action_id,
                policy_id=decision.primary_policy_id,
            )

        # MODIFY (INV-M5-002, INV-M5-003)
        if decision.decision == DecisionType.MODIFY:
            return self._handle_modify_sync(
                action=action,
                decision=decision,
                executor=executor,
                raw_content=raw_content,
                observed_events_fn=observed_events_fn,
                intent_contracts=intent_contracts,
            )

        # HUMAN_REVIEW (INV-M5-004, INV-M5-005)
        if decision.decision == DecisionType.HUMAN_REVIEW:
            return self._handle_review_sync(
                action=action,
                decision=decision,
                executor=executor,
                raw_content=raw_content,
                observed_events_fn=observed_events_fn,
            )

        # ALLOW (INV-M5-001, Section 13)
        return self._execute_and_verify(
            action=action,
            decision=decision,
            executor=executor,
            raw_content=raw_content,
            observed_events_fn=observed_events_fn,
        )

    async def execute_async(
        self,
        action: ProspectiveAction,
        executor: Callable[..., Any],
        raw_content: Any = None,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]] = None,
        intent_contracts: Optional[List[IntentContract]] = None,
        review_timeout: float = 30.0,
    ) -> Any:
        """Asynchronous enforcement execution lifecycle."""
        decision = self.evaluate(action=action, raw_content=raw_content, intent_contracts=intent_contracts)

        # Anti-TOCTOU
        self._verify_anti_toctou(action, decision)

        # BLOCK
        if decision.decision == DecisionType.BLOCK:
            self._emit_event(
                event_type=EventType.ACTION_BLOCKED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload={
                    "action_id": action.action_id,
                    "decision_id": decision.decision_id,
                    "reason": decision.reason,
                    "destination": action.destination,
                },
            )
            raise ActionBlockedError(
                f"Action blocked by policy {decision.primary_policy_id}: {decision.reason}",
                action_id=action.action_id,
                policy_id=decision.primary_policy_id,
            )

        # MODIFY
        if decision.decision == DecisionType.MODIFY:
            return await self._handle_modify_async(
                action=action,
                decision=decision,
                executor=executor,
                raw_content=raw_content,
                observed_events_fn=observed_events_fn,
                intent_contracts=intent_contracts,
            )

        # HUMAN_REVIEW
        if decision.decision == DecisionType.HUMAN_REVIEW:
            return await self._handle_review_async(
                action=action,
                decision=decision,
                executor=executor,
                raw_content=raw_content,
                observed_events_fn=observed_events_fn,
                review_timeout=review_timeout,
            )

        # ALLOW
        return await self._execute_and_verify_async(
            action=action,
            decision=decision,
            executor=executor,
            raw_content=raw_content,
            observed_events_fn=observed_events_fn,
        )

    def _handle_modify_sync(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        executor: Callable[..., Any],
        raw_content: Any,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]],
        intent_contracts: Optional[List[IntentContract]],
    ) -> Any:
        """Executes the modification pipeline synchronously."""
        analysis = self.analyzer.analyze(action=action, raw_content=raw_content)
        replacement_action, modified_payload = self.modifier.modify(
            action=action,
            raw_payload=raw_content,
            entities=analysis.detected_entities,
        )

        with self._lock:
            self._actions[replacement_action.action_id] = replacement_action

        self._emit_event(
            event_type=EventType.ACTION_MODIFIED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload={
                "original_action_id": action.action_id,
                "replacement_action_id": replacement_action.action_id,
                "original_action_hash": action.action_hash,
                "replacement_action_hash": replacement_action.action_hash,
                "modification": "TOKENIZED",
            },
        )

        # Re-evaluate replacement action prospective analysis (INV-M5-003, Section 15, 17)
        re_decision = self.evaluate(
            action=replacement_action,
            raw_content=modified_payload,
            intent_contracts=intent_contracts,
        )

        if re_decision.decision != DecisionType.ALLOW:
            # Still unsafe -> BLOCK
            self._emit_event(
                event_type=EventType.ACTION_BLOCKED,
                session_id=replacement_action.session_id,
                actor_id=replacement_action.actor_id,
                scope_id=replacement_action.execution_scope_id,
                safe_payload={
                    "action_id": replacement_action.action_id,
                    "reason": "Re-analysis of modified action remained unsafe",
                },
            )
            raise ModificationFailedError(
                f"Modified action re-analysis rejected by policy: {re_decision.decision.value}",
                action_id=replacement_action.action_id,
            )

        # Execute replacement only
        return self._execute_and_verify(
            action=replacement_action,
            decision=re_decision,
            executor=executor,
            raw_content=modified_payload,
            observed_events_fn=observed_events_fn,
        )

    async def _handle_modify_async(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        executor: Callable[..., Any],
        raw_content: Any,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]],
        intent_contracts: Optional[List[IntentContract]],
    ) -> Any:
        """Executes the modification pipeline asynchronously."""
        analysis = self.analyzer.analyze(action=action, raw_content=raw_content)
        replacement_action, modified_payload = self.modifier.modify(
            action=action,
            raw_payload=raw_content,
            entities=analysis.detected_entities,
        )

        with self._lock:
            self._actions[replacement_action.action_id] = replacement_action

        self._emit_event(
            event_type=EventType.ACTION_MODIFIED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload={
                "original_action_id": action.action_id,
                "replacement_action_id": replacement_action.action_id,
                "original_action_hash": action.action_hash,
                "replacement_action_hash": replacement_action.action_hash,
                "modification": "TOKENIZED",
            },
        )

        # Re-evaluate replacement action prospective analysis (INV-M5-003, Section 15, 17)
        re_decision = self.evaluate(
            action=replacement_action,
            raw_content=modified_payload,
            intent_contracts=intent_contracts,
        )

        if re_decision.decision != DecisionType.ALLOW:
            self._emit_event(
                event_type=EventType.ACTION_BLOCKED,
                session_id=replacement_action.session_id,
                actor_id=replacement_action.actor_id,
                scope_id=replacement_action.execution_scope_id,
                safe_payload={
                    "action_id": replacement_action.action_id,
                    "reason": "Re-analysis of modified action remained unsafe",
                },
            )
            raise ModificationFailedError(
                f"Modified action re-analysis rejected by policy: {re_decision.decision.value}",
                action_id=replacement_action.action_id,
            )

        return await self._execute_and_verify_async(
            action=replacement_action,
            decision=re_decision,
            executor=executor,
            raw_content=modified_payload,
            observed_events_fn=observed_events_fn,
        )

    def _handle_review_sync(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        executor: Callable[..., Any],
        raw_content: Any,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]],
    ) -> Any:
        """Handles human review queue synchronously."""
        rev = self.review_queue.request_review(
            action=action,
            decision_id=decision.decision_id,
            reason=decision.reason,
            policy_id=decision.primary_policy_id or "P8_INTENT_VIOLATION",
        )
        self._emit_event(
            event_type=EventType.REVIEW_REQUESTED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload=rev.to_dict(),
        )

        # Wait for approval (INV-M5-004, INV-M5-005)
        resolved = self.review_queue.wait_for_review_sync(rev.review_id)
        if resolved.status == ReviewStatus.APPROVED:
            self._emit_event(
                event_type=EventType.REVIEW_APPROVED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload=resolved.to_dict(),
            )
            self._verify_anti_toctou(action, decision)
            return self._execute_and_verify(
                action=action,
                decision=decision,
                executor=executor,
                raw_content=raw_content,
                observed_events_fn=observed_events_fn,
            )
        elif resolved.status == ReviewStatus.DENIED:
            self._emit_event(
                event_type=EventType.REVIEW_DENIED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload=resolved.to_dict(),
            )
            raise ReviewDeniedError("Action was denied by human reviewer", review_id=rev.review_id)
        else:
            self._emit_event(
                event_type=EventType.REVIEW_EXPIRED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload=resolved.to_dict(),
            )
            raise ReviewExpiredError("Human review expired without approval", review_id=rev.review_id)

    async def _handle_review_async(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        executor: Callable[..., Any],
        raw_content: Any,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]],
        review_timeout: float = 30.0,
    ) -> Any:
        """Handles human review queue asynchronously."""
        rev = self.review_queue.request_review(
            action=action,
            decision_id=decision.decision_id,
            reason=decision.reason,
            policy_id=decision.primary_policy_id or "P8_INTENT_VIOLATION",
        )
        self._emit_event(
            event_type=EventType.REVIEW_REQUESTED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload=rev.to_dict(),
        )

        resolved = await self.review_queue.wait_for_review(rev.review_id, timeout=review_timeout)
        if resolved.status == ReviewStatus.APPROVED:
            self._emit_event(
                event_type=EventType.REVIEW_APPROVED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload=resolved.to_dict(),
            )
            self._verify_anti_toctou(action, decision)
            return await self._execute_and_verify_async(
                action=action,
                decision=decision,
                executor=executor,
                raw_content=raw_content,
                observed_events_fn=observed_events_fn,
            )
        elif resolved.status == ReviewStatus.DENIED:
            self._emit_event(
                event_type=EventType.REVIEW_DENIED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload=resolved.to_dict(),
            )
            raise ReviewDeniedError("Action was denied by human reviewer", review_id=rev.review_id)
        else:
            self._emit_event(
                event_type=EventType.REVIEW_EXPIRED,
                session_id=action.session_id,
                actor_id=action.actor_id,
                scope_id=action.execution_scope_id,
                safe_payload=resolved.to_dict(),
            )
            raise ReviewExpiredError("Human review expired without approval", review_id=rev.review_id)

    def _execute_and_verify(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        executor: Callable[..., Any],
        raw_content: Any,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]],
    ) -> Any:
        """Executes permitted side effect and verifies observed events."""
        # Check callable parameters to pass modified content if accepted
        sig = inspect.signature(executor)
        if len(sig.parameters) > 0 and raw_content is not None:
            result = executor(raw_content)
        else:
            result = executor()

        self._emit_event(
            event_type=EventType.ACTION_EXECUTED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload={
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "destination": action.destination,
                "action_hash": action.action_hash,
            },
        )

        # Run PostExecutionVerifier (Section 22, 28)
        self._run_verification(action, decision, observed_events_fn)
        return result

    async def _execute_and_verify_async(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        executor: Callable[..., Any],
        raw_content: Any,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]],
    ) -> Any:
        """Asynchronously executes permitted side effect and verifies observed events."""
        sig = inspect.signature(executor)
        if len(sig.parameters) > 0 and raw_content is not None:
            if inspect.iscoroutinefunction(executor):
                result = await executor(raw_content)
            else:
                result = executor(raw_content)
        else:
            if inspect.iscoroutinefunction(executor):
                result = await executor()
            else:
                result = executor()

        self._emit_event(
            event_type=EventType.ACTION_EXECUTED,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload={
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "destination": action.destination,
                "action_hash": action.action_hash,
            },
        )

        self._run_verification(action, decision, observed_events_fn)
        return result

    def _verify_anti_toctou(self, action: ProspectiveAction, decision: EnforcementDecision) -> None:
        """Validates that action parameters have not mutated between evaluation and execution (INV-M5-006)."""
        recomputed_hash = compute_action_hash(
            action_type=action.action_type.value,
            destination=action.destination,
            operation=action.operation,
            tool_name=action.tool_name,
            payload=action.safe_payload,
            entity_refs=action.entity_refs,
            execution_scope_id=action.execution_scope_id,
        )
        if recomputed_hash != decision.action_hash:
            raise TOCTOUViolationError(
                f"Anti-TOCTOU violation detected: action hash mutated ({recomputed_hash} != {decision.action_hash})",
                expected_hash=decision.action_hash,
                actual_hash=recomputed_hash,
                action_id=action.action_id,
            )

    def _run_verification(
        self,
        action: ProspectiveAction,
        decision: EnforcementDecision,
        observed_events_fn: Optional[Callable[[], List[GuardXEvent]]],
    ) -> Optional[VerificationResult]:
        """Runs post-execution verification against observed events."""
        observed_events = observed_events_fn() if observed_events_fn else []
        verif_result = self.verifier.verify(
            action=action,
            decision=decision,
            observed_events=observed_events,
        )

        event_type = EventType.POST_EXECUTION_VERIFIED if verif_result.is_verified else EventType.POST_EXECUTION_MISMATCH
        self._emit_event(
            event_type=event_type,
            session_id=action.session_id,
            actor_id=action.actor_id,
            scope_id=action.execution_scope_id,
            safe_payload=verif_result.to_dict(),
        )
        return verif_result

    def _emit_event(
        self,
        event_type: EventType,
        session_id: str,
        actor_id: str,
        scope_id: Optional[str],
        safe_payload: Dict[str, Any],
    ) -> None:
        """Emits an immutable GuardXEvent if recorder is configured."""
        if not self.recorder:
            return
        evt = self.recorder.record(
            event_type=event_type,
            session_id=session_id,
            actor_id=actor_id or "gateway",
            scope_id=scope_id,
            safe_payload=safe_payload,
            raw_payload=None,  # NEVER raw secrets in persistent enforcement events
            provenance_quality=ProvenanceQuality.VERIFIED,
        )
        with self._lock:
            self._action_events.setdefault(session_id, []).append(evt)

    def get_decision(self, decision_id: str) -> Optional[EnforcementDecision]:
        with self._lock:
            return self._decisions.get(decision_id)

    def get_decisions_for_session(self, session_id: str) -> List[EnforcementDecision]:
        with self._lock:
            return [d for r_id, d in self._decisions.items() if d.session_id == session_id]

    def get_action(self, action_id: str) -> Optional[ProspectiveAction]:
        with self._lock:
            return self._actions.get(action_id)
