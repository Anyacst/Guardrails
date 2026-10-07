"""Intent Conformance Engine for GuardX Milestone 4.

Compares declared intent contracts against actual runtime operations
to detect scope mismatches, undeclared network activity, and unauthorized processes.
"""

import fnmatch
import threading
from typing import Any, Callable, Dict, List, Optional
import uuid

from guardx.core.enums import EventType
from guardx.core.interfaces import EventSubscriber
from guardx.core.models import GuardXEvent
from guardx.intent.models import IntentContract, IntentViolation, IntentViolationType
from guardx.risk.models import FindingCategory, SecurityFinding, Severity


class IntentConformanceEngine(EventSubscriber):
    """Monitors events against declared IntentContracts and generates IntentViolations."""

    def __init__(
        self,
        scope_manager: Optional[Any] = None,
        on_violation_callback: Optional[Callable[[IntentViolation, SecurityFinding], None]] = None,
    ):
        self.scope_manager = scope_manager
        self.on_violation_callback = on_violation_callback
        self._lock = threading.RLock()
        self._contracts_by_scope: Dict[str, IntentContract] = {}
        self._contracts_by_id: Dict[str, IntentContract] = {}
        self._violations: List[IntentViolation] = []

    def register_contract(self, contract: IntentContract) -> None:
        """Explicitly registers an intent contract for an execution scope."""
        with self._lock:
            self._contracts_by_id[contract.intent_id] = contract
            self._contracts_by_scope[contract.scope_id] = contract

    def on_event(self, event: GuardXEvent) -> None:
        """Processes runtime event against active intent contracts."""
        self.evaluate_event(event)

    def evaluate_event(self, event: GuardXEvent) -> Optional[IntentViolation]:
        """Evaluates an event for adherence to the active scope's intent contract."""
        with self._lock:
            # Auto-register contract from INTENT_DECLARED events if structured
            if event.event_type == EventType.INTENT_DECLARED and event.execution_scope_id:
                payload = event.payload or {}
                if "allowed_resources" in payload or "allowed_operations" in payload:
                    contract = IntentContract(
                        intent_id=f"intent_{event.event_id[:8]}",
                        session_id=event.session_id,
                        scope_id=event.execution_scope_id,
                        description=str(payload.get("intent", payload.get("description", "Declared intent"))),
                        allowed_operations=list(payload.get("allowed_operations", [])),
                        allowed_resources=list(payload.get("allowed_resources", [])),
                        allowed_network=list(payload.get("allowed_network", [])),
                        allowed_processes=list(payload.get("allowed_processes", [])),
                        declared_by=event.actor.actor_id,
                        originating_event_id=event.event_id,
                    )
                    self.register_contract(contract)
                return None

            scope_id = event.execution_scope_id
            if not scope_id:
                return None

            # Hierarchical scope resolution: check current scope or any ancestor scope
            contract: Optional[IntentContract] = None
            curr_scope_id: Optional[str] = scope_id
            while curr_scope_id:
                if curr_scope_id in self._contracts_by_scope:
                    contract = self._contracts_by_scope[curr_scope_id]
                    break
                if self.scope_manager and hasattr(self.scope_manager, "get_scope"):
                    proj = self.scope_manager.get_scope(curr_scope_id)
                    curr_scope_id = proj.parent_scope_id if proj else None
                else:
                    break

            if not contract:
                return None

            violation: Optional[IntentViolation] = None

            def _get_id(res_or_actor: Any) -> str:
                if res_or_actor is None:
                    return ""
                return getattr(res_or_actor, "resource_id", getattr(res_or_actor, "actor_id", str(res_or_actor)))

            op_name = event.event_type.value

            # 1. Check Network Operations (Undeclared Network Effect)
            if event.event_type == EventType.NETWORK_REQUEST:
                net_endpoint = _get_id(event.destination) or "unknown"
                if contract.allowed_network is not None:
                    is_allowed = any(
                        fnmatch.fnmatch(net_endpoint, n) or n in net_endpoint or n == "*"
                        for n in contract.allowed_network
                    )
                    if not is_allowed:
                        violation = IntentViolation(
                            violation_id=f"viol_{uuid.uuid4().hex[:12]}",
                            session_id=event.session_id,
                            intent_id=contract.intent_id,
                            scope_id=scope_id,
                            violation_type=IntentViolationType.UNDECLARED_NETWORK_EFFECT,
                            actual_operation=op_name,
                            actual_resource=net_endpoint,
                            event_id=event.event_id,
                            severity=Severity.HIGH,
                            explanation=f"Undeclared network call to '{net_endpoint}' occurred during execution scope declared for '{contract.description}'.",
                        )

            # 2. Check Operation Type
            if not violation and contract.allowed_operations and op_name not in contract.allowed_operations:
                # Operational actions only
                if event.event_type in (EventType.FILE_READ, EventType.FILE_WRITE, EventType.NETWORK_REQUEST, EventType.PROCESS_EXEC):
                    target_id = _get_id(event.destination) or _get_id(event.source) or "unknown"
                    violation = IntentViolation(
                        violation_id=f"viol_{uuid.uuid4().hex[:12]}",
                        session_id=event.session_id,
                        intent_id=contract.intent_id,
                        scope_id=scope_id,
                        violation_type=IntentViolationType.OPERATION_NOT_ALLOWED,
                        actual_operation=op_name,
                        actual_resource=target_id,
                        event_id=event.event_id,
                        severity=Severity.HIGH,
                        explanation=f"Operation '{op_name}' is not permitted by intent contract '{contract.description}'. Allowed: {contract.allowed_operations}",
                    )

            # 3. Check File Operations (Resource Mismatch)
            if not violation and event.event_type in (EventType.FILE_READ, EventType.FILE_WRITE):
                # For read, the resource read from is source; for write, destination
                if event.event_type == EventType.FILE_READ:
                    target_path = _get_id(event.source) or _get_id(event.destination)
                else:
                    target_path = _get_id(event.destination) or _get_id(event.source)

                clean_path = target_path.replace("file:", "")
                if contract.allowed_resources:
                    is_allowed = any(
                        fnmatch.fnmatch(clean_path, r) or fnmatch.fnmatch(target_path, r) or clean_path.endswith(r) or r == "*"
                        for r in contract.allowed_resources
                    )
                    if not is_allowed:
                        violation = IntentViolation(
                            violation_id=f"viol_{uuid.uuid4().hex[:12]}",
                            session_id=event.session_id,
                            intent_id=contract.intent_id,
                            scope_id=scope_id,
                            violation_type=IntentViolationType.RESOURCE_SCOPE_MISMATCH,
                            actual_operation=op_name,
                            actual_resource=target_path,
                            event_id=event.event_id,
                            severity=Severity.HIGH,
                            explanation=f"Resource '{target_path}' accessed outside declared contract scope '{contract.description}'. Allowed resources: {contract.allowed_resources}",
                        )


            if violation:
                self._violations.append(violation)

                # Generate SecurityFinding
                finding = SecurityFinding(
                    finding_id=f"find_{uuid.uuid4().hex[:12]}",
                    session_id=event.session_id,
                    rule_id=f"RULE_INTENT_{violation.violation_type.value}",
                    title=f"Intent Violation: {violation.violation_type.value} ({violation.actual_resource})",
                    category=FindingCategory.INTENT_VIOLATION,
                    severity=violation.severity,
                    confidence=1.0,
                    source_entity_id=None,
                    source_resource_id=violation.actual_resource,
                    destination_id=violation.actual_resource,
                    source_trust="LOCAL",
                    destination_trust="UNKNOWN",
                    boundary_crossing="INTENT_BOUNDARY",
                    representation="RAW",
                    lineage_path=[],
                    execution_event_ids=[event.event_id],
                    supporting_event_ids=[event.event_id],
                    explanation=violation.explanation,
                    provenance_quality="OBSERVED",
                    raw_value_persisted=False,
                    metadata={"contract_id": contract.intent_id, "scope_id": scope_id},
                )

                if self.on_violation_callback:
                    self.on_violation_callback(violation, finding)

                return violation

            return None

    def get_violations(self, session_id: Optional[str] = None) -> List[IntentViolation]:
        with self._lock:
            if session_id:
                return [v for v in self._violations if v.session_id == session_id]
            return list(self._violations)

    def get_contracts(self, session_id: Optional[str] = None) -> List[IntentContract]:
        with self._lock:
            if session_id:
                return [c for c in self._contracts_by_id.values() if c.session_id == session_id]
            return list(self._contracts_by_id.values())
