"""Centralized Event Creation, Sequencing, and Publication Engine.

Guarantees:
- Centralized atomic session-local sequence assignment (Concurrency-safe).
- Content sanitization boundary (Zero raw secrets reach GuardXEvent).
- Canonical actor and resource resolution.
- ExecutionScope attribution from contextvars.
- Invariant validation before publication.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional
import uuid

from guardx.core.context import (
    get_current_actor,
    get_current_scope,
    get_current_session,
    set_current_session,
)
from guardx.core.enums import EventType, ScopeStatus
from guardx.core.interfaces import (
    ActorResolver,
    EventBus,
    ResourceResolver,
)
from guardx.core.invariants import InvariantValidator
from guardx.core.models import (
    Actor,
    GuardXEvent,
    RawObservation,
    Resource,
    ScopeProjection,
    Session,
)
from guardx.core.resolvers import DefaultActorResolver, DefaultResourceResolver
from guardx.core.sanitizer import SafePayloadBuilder


class EventRecorder:
    """Centralized coordinator converting RawObservations into immutable GuardXEvents."""

    def __init__(
        self,
        session: Session,
        event_bus: EventBus,
        actor_resolver: Optional[ActorResolver] = None,
        resource_resolver: Optional[ResourceResolver] = None,
        safe_payload_builder: Optional[SafePayloadBuilder] = None,
        invariant_validator: Optional[InvariantValidator] = None,
    ):
        self.session = session
        self.event_bus = event_bus
        self.actor_resolver = actor_resolver or DefaultActorResolver()
        self.resource_resolver = resource_resolver or DefaultResourceResolver()
        self.safe_payload_builder = safe_payload_builder or SafePayloadBuilder()
        self.invariant_validator = invariant_validator or InvariantValidator()

        # Thread-safe sequencing and history tracking
        self._seq_lock = threading.Lock()
        self._current_seq = 0
        self._known_event_sequences: Dict[str, int] = {}
        self._history: List[GuardXEvent] = []

        # Initialize session in ContextVar
        set_current_session(session)

    @property
    def current_sequence(self) -> int:
        with self._seq_lock:
            return self._current_seq

    def get_history(self) -> List[GuardXEvent]:
        with self._seq_lock:
            return list(self._history)

    def get_event(self, event_id: str) -> Optional[GuardXEvent]:
        with self._seq_lock:
            for evt in self._history:
                if evt.event_id == event_id:
                    return evt
            return None

    def record_scope_start(self, scope: ScopeProjection) -> GuardXEvent:
        """Emits an immutable SCOPE_START event."""
        causal_id = None
        if scope.originating_event_id and scope.originating_event_id in self._known_event_sequences:
            causal_id = scope.originating_event_id

        obs = RawObservation(
            event_type=EventType.SCOPE_START,
            raw_payload={
                "scope_id": scope.scope_id,
                "scope_name": scope.scope_name,
                "parent_scope_id": scope.parent_scope_id,
                "originating_event_id": scope.originating_event_id,
            },
            actor_id=scope.actor_id,
            causal_event_id=causal_id,
            metadata=scope.metadata,
        )
        return self._create_and_publish(obs, explicit_scope_id=scope.scope_id)

    def record_scope_end(self, scope: ScopeProjection) -> GuardXEvent:
        """Emits an immutable SCOPE_END event."""
        duration_ms = 0.0
        if scope.end_time and scope.start_time:
            duration_ms = (scope.end_time - scope.start_time).total_seconds() * 1000.0

        obs = RawObservation(
            event_type=EventType.SCOPE_END,
            raw_payload={
                "scope_id": scope.scope_id,
                "scope_name": scope.scope_name,
                "status": scope.status.value,
                "duration_ms": duration_ms,
            },
            actor_id=scope.actor_id,
            metadata=scope.metadata,
        )
        return self._create_and_publish(obs, explicit_scope_id=scope.scope_id)

    def record(self, observation: RawObservation) -> GuardXEvent:
        """Normalizes, sanitizes, sequences, and publishes a raw observation."""
        return self._create_and_publish(observation)

    def _create_and_publish(
        self,
        observation: RawObservation,
        explicit_scope_id: Optional[str] = None,
    ) -> GuardXEvent:
        # 1. Resolve canonical Actor
        if observation.actor_id.startswith("user:"):
            actor = self.actor_resolver.resolve_user(observation.actor_id.replace("user:", ""))
        elif observation.actor_id.startswith("tool:"):
            actor = self.actor_resolver.resolve_tool(observation.actor_id.replace("tool:", ""))
        elif observation.actor_id.startswith("subproc:"):
            actor = self.actor_resolver.resolve_subprocess(observation.actor_id.replace("subproc:", ""))
        else:
            agent_id = observation.actor_id.replace("agent:", "")
            actor = self.actor_resolver.resolve_agent(agent_id)

        # 2. Resolve Resources
        source_resource: Optional[Resource] = None
        if observation.source_raw:
            if observation.source_raw.startswith(("http://", "https://", "net:")):
                clean_host = observation.source_raw.replace("net:", "")
                source_resource = self.resource_resolver.resolve_network(clean_host)
            elif observation.source_raw.startswith("tool:"):
                source_resource = self.resource_resolver.resolve_tool(observation.source_raw.replace("tool:", ""))
            elif observation.source_raw.startswith("proc:"):
                source_resource = self.resource_resolver.resolve_process(observation.source_raw.replace("proc:", ""))
            else:
                source_resource = self.resource_resolver.resolve_file(
                    observation.source_raw, self.session.workspace_root
                )

        destination_resource: Optional[Resource] = None
        if observation.destination_raw:
            if observation.destination_raw.startswith(("http://", "https://", "net:")):
                clean_host = observation.destination_raw.replace("net:", "")
                destination_resource = self.resource_resolver.resolve_network(clean_host)
            elif observation.destination_raw.startswith("tool:"):
                destination_resource = self.resource_resolver.resolve_tool(observation.destination_raw.replace("tool:", ""))
            elif observation.destination_raw.startswith("proc:"):
                destination_resource = self.resource_resolver.resolve_process(observation.destination_raw.replace("proc:", ""))
            else:
                destination_resource = self.resource_resolver.resolve_file(
                    observation.destination_raw, self.session.workspace_root
                )

        # 3. Attach Scope Attribution
        if explicit_scope_id:
            scope_id = explicit_scope_id
        else:
            current_scope = get_current_scope()
            if current_scope:
                scope_id = current_scope.scope_id
            elif observation.event_type not in self.invariant_validator.ROOT_LIFECYCLE_EVENTS:
                # Fallback to session root execution scope for detached/ambient runtime observations
                scope_id = f"scope_{self.session.session_id}_root"
            else:
                scope_id = None

        # 4. Content Sanitization Boundary (Guarantees INV-001)
        safe_payload, discovered = self.safe_payload_builder.sanitize_payload(
            observation.raw_payload, self.session.hmac_key
        )

        # Merge discovered entities into lineage IDs
        lineage_ids = list(observation.data_lineage_ids)
        for disc in discovered:
            entity_ref = f"entity:{disc['fingerprint_hmac'][:12]}"
            if entity_ref not in lineage_ids:
                lineage_ids.append(entity_ref)

        # 5. Atomic Sequence Assignment & Event Creation
        with self._seq_lock:
            self._current_seq += 1
            next_seq = self._current_seq
            event_id = f"evt_{uuid.uuid4().hex[:16]}"
            timestamp = datetime.now(timezone.utc)

            event_meta = dict(observation.metadata)
            if discovered:
                event_meta["sanitized_entities"] = discovered

            event = GuardXEvent(
                event_id=event_id,
                session_id=self.session.session_id,
                sequence_number=next_seq,
                timestamp=timestamp,
                event_type=observation.event_type,
                actor=actor,
                source=source_resource,
                destination=destination_resource,
                execution_scope_id=scope_id,
                causal_event_id=observation.causal_event_id,
                data_lineage_ids=tuple(lineage_ids),
                payload=safe_payload,
                provenance_quality=observation.provenance_quality,
                confidence=observation.confidence,
                metadata=event_meta,
            )

            # 6. Invariant Validation
            self.invariant_validator.validate_event(
                event=event,
                expected_seq=next_seq,
                known_event_sequences=self._known_event_sequences,
            )

            # Record event in known sequences and history
            self._known_event_sequences[event_id] = next_seq
            self._history.append(event)

        # 7. Publish Event to EventBus
        self.event_bus.publish(event)

        return event
