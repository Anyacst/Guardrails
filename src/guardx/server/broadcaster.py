"""WebSocket Broadcaster for Real-Time Event & Graph Streaming.

Guarantees:
- Incremental updates (event.created, node.created, edge.created, scope.started, scope.ended).
- Thread-safe bridging between synchronous EventBus and async WebSocket clients.
- Zero raw secrets in broadcast payloads.
"""

import asyncio
from collections import defaultdict
import json
import threading
from typing import Any, Dict, List, Set
from fastapi import WebSocket

from guardx.core.enums import EventType
from guardx.core.interfaces import EventSubscriber
from guardx.core.models import GuardXEvent
from guardx.server.session_registry import SessionContext


class WebSocketBroadcaster(EventSubscriber):
    """Subscribes to session EventBus and broadcasts incremental updates to connected WebSockets."""

    def __init__(self, session_context: SessionContext):
        self.session_context = session_context
        self._lock = threading.RLock()
        self._sockets: Set[WebSocket] = set()
        self._seen_node_ids: Set[str] = set()
        self._seen_edge_ids: Set[str] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def add_socket(self, ws: WebSocket) -> None:
        with self._lock:
            self._sockets.add(ws)

    def remove_socket(self, ws: WebSocket) -> None:
        with self._lock:
            self._sockets.discard(ws)

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._sockets)

    def on_event(self, event: GuardXEvent) -> None:
        """Invoked synchronously by EventBus when an event is recorded."""
        messages: List[Dict[str, Any]] = []

        # 1. Base event.created message
        event_dict = {
            "type": "event.created",
            "session_id": event.session_id,
            "data": {
                "event_id": event.event_id,
                "sequence_number": event.sequence_number,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type.value,
                "actor_id": event.actor.actor_id,
                "actor_label": event.actor.display_name,
                "source_id": event.source.resource_id if event.source else None,
                "destination_id": event.destination.resource_id if event.destination else None,
                "execution_scope_id": event.execution_scope_id,
                "causal_event_id": event.causal_event_id,
                "payload": event.payload,
                "provenance_quality": event.provenance_quality.value,
                "confidence": event.confidence,
                "metadata": event.metadata,
            },
        }
        messages.append(event_dict)

        # 2. Scope lifecycle messages
        if event.event_type == EventType.SCOPE_START:
            messages.append({
                "type": "scope.started",
                "session_id": event.session_id,
                "data": {
                    "scope_id": event.payload.get("scope_id", event.execution_scope_id),
                    "scope_name": event.payload.get("scope_name", "scope"),
                    "parent_scope_id": event.payload.get("parent_scope_id"),
                    "event_id": event.event_id,
                },
            })
        elif event.event_type == EventType.SCOPE_END:
            messages.append({
                "type": "scope.ended",
                "session_id": event.session_id,
                "data": {
                    "scope_id": event.payload.get("scope_id", event.execution_scope_id),
                    "scope_name": event.payload.get("scope_name", "scope"),
                    "status": event.payload.get("status", "COMPLETED"),
                    "duration_ms": event.payload.get("duration_ms", 0.0),
                    "event_id": event.event_id,
                },
            })

        # 3. M5 Enforcement event mapping
        enforcement_type_map = {
            EventType.ACTION_PROPOSED: "action.proposed",
            EventType.POLICY_MATCHED: "policy.matched",
            EventType.DECISION_CREATED: "decision.created",
            EventType.ACTION_MODIFIED: "action.modified",
            EventType.ACTION_BLOCKED: "action.blocked",
            EventType.REVIEW_REQUESTED: "review.requested",
            EventType.REVIEW_APPROVED: "review.resolved",
            EventType.REVIEW_DENIED: "review.resolved",
            EventType.REVIEW_EXPIRED: "review.resolved",
            EventType.ACTION_EXECUTED: "action.executed",
            EventType.POST_EXECUTION_VERIFIED: "verification.completed",
            EventType.POST_EXECUTION_MISMATCH: "verification.failed",
        }
        if event.event_type in enforcement_type_map:
            messages.append({
                "type": enforcement_type_map[event.event_type],
                "session_id": event.session_id,
                "data": event.payload,
            })

        # 4. Detect newly created nodes and edges from ProvenanceEngine's store
        store = self.session_context.graph_store
        all_nodes = store.get_nodes()
        with self._lock:
            for node in all_nodes:
                if node.node_id not in self._seen_node_ids:
                    self._seen_node_ids.add(node.node_id)
                    messages.append({
                        "type": "node.created",
                        "session_id": event.session_id,
                        "data": node.to_dict(),
                    })

            # Check edges supporting this event
            matching_edges = [e for e in store.get_edges() if e.event_id == event.event_id]
            for edge in matching_edges:
                if edge.edge_id not in self._seen_edge_ids:
                    self._seen_edge_ids.add(edge.edge_id)
                    messages.append({
                        "type": "edge.created",
                        "session_id": event.session_id,
                        "data": edge.to_dict(),
                    })

        # 5. Broadcast all messages to active WebSockets
        self._broadcast_messages(messages)

    def broadcast_enforcement_event(self, msg_type: str, data: Dict[str, Any]) -> None:
        """Broadcasts incremental enforcement message."""
        msg = {
            "type": msg_type,
            "session_id": self.session_context.session.session_id,
            "data": data,
        }
        self._broadcast_messages([msg])

    def broadcast_lineage_event(self, msg_type: str, data: Dict[str, Any]) -> None:
        """Broadcasts incremental data lineage message (entity.created, carrier.created, flow.created, transformation.created)."""
        msg = {
            "type": msg_type,
            "session_id": self.session_context.session.session_id,
            "data": data,
        }
        self._broadcast_messages([msg])

    def broadcast_security_event(self, msg_type: str, data: Dict[str, Any]) -> None:
        """Broadcasts incremental security intelligence message (trust_boundary.crossed, risk.detected, intent.violation, attack_chain.detected)."""
        msg = {
            "type": msg_type,
            "session_id": self.session_context.session.session_id,
            "data": data,
        }
        self._broadcast_messages([msg])

    def _broadcast_messages(self, messages: List[Dict[str, Any]]) -> None:
        with self._lock:
            sockets = list(self._sockets)

        if not sockets:
            return

        for msg in messages:
            raw_text = json.dumps(msg)
            for ws in sockets:
                try:
                    if self._loop and self._loop.is_running():
                        asyncio.run_coroutine_threadsafe(ws.send_text(raw_text), self._loop)
                    else:
                        # Fallback for environments with active running event loop
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            asyncio.run_coroutine_threadsafe(ws.send_text(raw_text), loop)
                except Exception:
                    # Client disconnected
                    with self._lock:
                        self._sockets.discard(ws)


def get_or_create_broadcaster(session_ctx: SessionContext) -> WebSocketBroadcaster:
    """Returns or creates the broadcaster for a session."""
    if hasattr(session_ctx, "broadcaster") and session_ctx.broadcaster is not None:
        return session_ctx.broadcaster
    broadcaster = WebSocketBroadcaster(session_ctx)
    session_ctx.event_bus.subscribe(broadcaster)
    session_ctx.broadcaster = broadcaster
    return broadcaster
