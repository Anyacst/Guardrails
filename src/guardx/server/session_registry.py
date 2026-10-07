"""Session Registry for GuardX Server.

Manages active sessions, their EventRecorders, EventBuses, ScopeManagers,
and ProvenanceEngines.
"""

from datetime import datetime, timezone
import os
import threading
from typing import Any, Dict, List, Optional
import uuid

from guardx.core.bus import InMemoryEventBus
from guardx.core.context import ScopeManager
from guardx.core.crypto import generate_session_key
from guardx.core.models import Session
from guardx.core.recorder import EventRecorder
from guardx.graph.engine import ProvenanceEngine
from guardx.graph.store import InMemoryGraphStore


class SessionContext:
    """Encapsulates all runtime components for an active session."""

    def __init__(self, session: Session):
        self.session = session
        self.event_bus = InMemoryEventBus()
        self.graph_store = InMemoryGraphStore()
        self.provenance_engine = ProvenanceEngine(store=self.graph_store)
        self.event_bus.subscribe(self.provenance_engine)

        from guardx.server.broadcaster import WebSocketBroadcaster
        self.broadcaster = WebSocketBroadcaster(self)
        self.event_bus.subscribe(self.broadcaster)

        from guardx.lineage.store import DataLineageStore
        from guardx.lineage.engine import DataFlowEngine
        self.lineage_store = DataLineageStore(session_id=session.session_id)

        # Milestone 4 Security Intelligence Foundation
        from guardx.security.store import SecurityOverlayStore
        from guardx.trust.resolver import TrustResolver
        from guardx.trust.engine import TrustBoundaryEngine
        from guardx.risk.engine import RiskPathEngine
        from guardx.intent.engine import IntentConformanceEngine
        from guardx.chains.detector import AttackChainDetector

        self.security_store = SecurityOverlayStore(session_id=session.session_id)
        self.trust_resolver = TrustResolver(workspace_root=session.workspace_root)

        self.trust_boundary_engine = TrustBoundaryEngine(
            resolver=self.trust_resolver,
            on_crossing_callback=self._handle_trust_boundary_crossed,
        )

        self.risk_path_engine = RiskPathEngine(
            lineage_store=self.lineage_store,
            trust_resolver=self.trust_resolver,
            on_finding_callback=self._handle_security_finding,
        )

        self.recorder = EventRecorder(
            session=self.session,
            event_bus=self.event_bus,
        )
        self.scope_manager = ScopeManager(recorder=self.recorder)

        self.intent_conformance_engine = IntentConformanceEngine(
            scope_manager=self.scope_manager,
            on_violation_callback=self._handle_intent_violation,
        )
        self.event_bus.subscribe(self.intent_conformance_engine)

        self.attack_chain_detector = AttackChainDetector(
            lineage_store=self.lineage_store,
            trust_resolver=self.trust_resolver,
            on_chain_callback=self._handle_attack_chain,
        )

        self.data_flow_engine = DataFlowEngine(
            store=self.lineage_store,
            session_key=session.hmac_key,
            on_lineage_event=self._handle_lineage_event,
        )
        self.event_bus.subscribe(self.data_flow_engine)

        # Milestone 5 Prospective Runtime Enforcement
        # Only initialised when GUARDX_ENFORCEMENT=true (default: false)
        self.policy_engine = None
        self.review_queue = None
        self.prospective_analyzer = None
        self.action_modifier = None
        self.post_execution_verifier = None
        self.enforcement_gateway = None

        if os.environ.get("GUARDX_ENFORCEMENT", "false").lower() in ("true", "1", "yes"):
            from guardx.policy.engine import PolicyEngine
            from guardx.enforcement.analyzer import ProspectiveAnalyzer
            from guardx.enforcement.modifier import ActionModifier
            from guardx.enforcement.review import HumanReviewQueue
            from guardx.enforcement.verification import PostExecutionVerifier
            from guardx.enforcement.gateway import EnforcementGateway

            self.policy_engine = PolicyEngine()
            self.review_queue = HumanReviewQueue(
                on_review_event=lambda msg_type, data: self.broadcaster.broadcast_enforcement_event(msg_type, data)
            )
            self.prospective_analyzer = ProspectiveAnalyzer(
                session_key=session.hmac_key,
                trust_resolver=self.trust_resolver,
                lineage_store=self.lineage_store,
                intent_engine=self.intent_conformance_engine,
            )
            self.action_modifier = ActionModifier()
            self.post_execution_verifier = PostExecutionVerifier()
            self.enforcement_gateway = EnforcementGateway(
                recorder=self.recorder,
                policy_engine=self.policy_engine,
                analyzer=self.prospective_analyzer,
                modifier=self.action_modifier,
                review_queue=self.review_queue,
                verifier=self.post_execution_verifier,
            )

    def _handle_lineage_event(self, msg_type: str, data: Dict[str, Any]) -> None:
        """Handles lineage event, broadcasts it, and evaluates trust boundaries and security risks."""
        self.broadcaster.broadcast_lineage_event(msg_type, data)

        if msg_type == "flow.created":
            source_id = data.get("source_id", "")
            target_id = data.get("target_id", "")
            entity_id = data.get("entity_id")
            event_id = data.get("event_id")

            # 1. Evaluate Trust Boundary Crossing
            crossing = self.trust_boundary_engine.evaluate_hop(
                session_id=self.session.session_id,
                source_id=source_id,
                destination_id=target_id,
                entity_id=entity_id,
                supporting_event_id=event_id,
            )

            # 2. Evaluate Risk Path
            if entity_id:
                ent = self.lineage_store.get_entity(entity_id)
                if ent:
                    self.risk_path_engine.evaluate_entity(ent, self.session.session_id)

    def _handle_trust_boundary_crossed(self, crossing: Any) -> None:
        self.security_store.add_crossing(crossing)
        self.broadcaster.broadcast_security_event("trust_boundary.crossed", crossing.to_dict())

    def _handle_security_finding(self, finding: Any) -> None:
        self.security_store.add_finding(finding)
        self.broadcaster.broadcast_security_event("risk.detected", finding.to_dict())
        # Evaluate for attack chains
        self.attack_chain_detector.evaluate_findings([finding], self.session.session_id)

    def _handle_intent_violation(self, violation: Any, finding: Any) -> None:
        self.security_store.add_intent_violation(violation)
        self.security_store.add_finding(finding)
        self.broadcaster.broadcast_security_event("intent.violation", violation.to_dict())
        self.broadcaster.broadcast_security_event("risk.detected", finding.to_dict())
        # Evaluate for attack chains
        self.attack_chain_detector.evaluate_findings([finding], self.session.session_id, violations=[violation])

    def _handle_attack_chain(self, chain: Any) -> None:
        self.security_store.add_attack_chain(chain)
        self.broadcaster.broadcast_security_event("attack_chain.detected", chain.to_dict())


class SessionRegistry:
    """Thread-safe registry of GuardX sessions."""

    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: Dict[str, SessionContext] = {}

    def create_session(
        self,
        session_id: Optional[str] = None,
        agent_name: str = "OpenCode",
        workspace_root: str = "/workspace",
    ) -> SessionContext:
        """Creates and registers a new SessionContext."""
        with self._lock:
            s_id = session_id or f"session_{uuid.uuid4().hex[:12]}"
            if s_id in self._sessions:
                return self._sessions[s_id]

            session = Session(
                session_id=s_id,
                agent_name=agent_name,
                workspace_root=workspace_root,
                hmac_key=generate_session_key(),
                start_time=datetime.now(timezone.utc),
            )
            ctx = SessionContext(session=session)
            self._sessions[s_id] = ctx
            return ctx

    def get_session(self, session_id: str) -> Optional[SessionContext]:
        """Retrieves an active SessionContext by session_id."""
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self) -> List[Session]:
        """Returns list of all registered Session objects."""
        with self._lock:
            return [ctx.session for ctx in self._sessions.values()]

    def clear(self) -> None:
        """Clears all sessions (used for test teardown)."""
        with self._lock:
            self._sessions.clear()


global_session_registry = SessionRegistry()
