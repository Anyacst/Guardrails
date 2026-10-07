"""Provenance Engine for GuardX.

Guarantees:
- Real-time ingestion of immutable GuardXEvents from EventBus.
- Deterministic construction of Execution Provenance DAG.
- Canonical node preservation (USER, AGENT, TOOL, FILE, PROCESS, NETWORK_ENDPOINT, LLM, SCOPE).
- Complete causal edge attribution with event_id, provenance_quality, and confidence.
"""

from typing import Dict, List, Optional
import uuid

from guardx.core.enums import ActorType, EventType, ProvenanceQuality, ResourceType
from guardx.core.interfaces import EventSubscriber
from guardx.core.models import GuardXEvent
from guardx.graph.models import EdgeType, ExecutionGraph, GraphEdge, GraphNode, NodeType
from guardx.graph.store import GraphStore, InMemoryGraphStore


class ProvenanceEngine(EventSubscriber):
    """Processes GuardXEvents from EventBus and maintains the Execution Provenance DAG."""

    def __init__(self, store: Optional[GraphStore] = None):
        self.store = store or InMemoryGraphStore()
        # Maps event_id -> primary node_id associated with event
        self._event_to_node: Dict[str, str] = {}
        # Maps scope_id -> parent_scope_id
        self._scope_parents: Dict[str, Optional[str]] = {}

    def on_event(self, event: GuardXEvent) -> None:
        """Processes newly published immutable event and updates graph."""
        self.process_event(event)

    def process_event(self, event: GuardXEvent) -> None:
        """Projects a GuardXEvent into the Execution Provenance DAG."""
        session_id = event.session_id

        # 1. Ensure Actor Node
        actor_node = self._ensure_actor_node(event)
        primary_node_id = actor_node.node_id

        # 2. Ensure ExecutionScope Node if present
        if event.execution_scope_id:
            scope_node_id = f"scope:{event.execution_scope_id}"
            scope_node = self.store.get_node(scope_node_id)
            if not scope_node:
                scope_node = GraphNode(
                    node_id=scope_node_id,
                    node_type=NodeType.EXECUTION_SCOPE,
                    label=event.metadata.get("scope_name", event.execution_scope_id),
                    session_id=session_id,
                )
                self.store.add_node(scope_node)

        # 3. Handle Event Type Specific Projections
        if event.event_type == EventType.USER_INPUT:
            primary_node_id = actor_node.node_id

        elif event.event_type == EventType.AGENT_ACTION:
            primary_node_id = actor_node.node_id

        elif event.event_type == EventType.SCOPE_START:
            scope_id = event.payload.get("scope_id") or event.execution_scope_id
            if scope_id:
                scope_node_id = f"scope:{scope_id}"
                self.store.add_node(
                    GraphNode(
                        node_id=scope_node_id,
                        node_type=NodeType.EXECUTION_SCOPE,
                        label=event.payload.get("scope_name", scope_id),
                        session_id=session_id,
                    )
                )
                parent_id = event.payload.get("parent_scope_id")
                if parent_id:
                    self._scope_parents[scope_id] = parent_id
                    # Link parent scope -> child scope
                    self._add_edge(
                        source_id=f"scope:{parent_id}",
                        target_id=scope_node_id,
                        edge_type=EdgeType.INVOKED,
                        event=event,
                    )
                primary_node_id = scope_node_id

        elif event.event_type == EventType.TOOL_CALL:
            tool_name = event.payload.get("tool_name", "tool")
            tool_node_id = f"tool:{tool_name.strip().lower()}"
            tool_node = self.store.get_node(tool_node_id)
            if not tool_node:
                tool_node = GraphNode(
                    node_id=tool_node_id,
                    node_type=NodeType.TOOL,
                    label=tool_name,
                    session_id=session_id,
                )
                self.store.add_node(tool_node)

            # Agent -> Tool (INVOKED)
            self._add_edge(
                source_id=actor_node.node_id,
                target_id=tool_node_id,
                edge_type=EdgeType.INVOKED,
                event=event,
            )
            primary_node_id = tool_node_id

        elif event.event_type == EventType.TOOL_RESULT:
            tool_name = event.payload.get("tool_name", "tool")
            tool_node_id = f"tool:{tool_name.strip().lower()}"
            # Tool -> Agent (RETURNED_TO)
            agent_id = "agent:opencode"
            self._add_edge(
                source_id=tool_node_id,
                target_id=agent_id,
                edge_type=EdgeType.RETURNED_TO,
                event=event,
            )
            primary_node_id = tool_node_id

        elif event.event_type == EventType.FILE_READ:
            file_res = event.source
            if file_res:
                file_node = self._ensure_resource_node(file_res, session_id)
                # Actor/Tool -> File (READ_FROM)
                self._add_edge(
                    source_id=actor_node.node_id,
                    target_id=file_node.node_id,
                    edge_type=EdgeType.READ_FROM,
                    event=event,
                )
                primary_node_id = file_node.node_id

        elif event.event_type == EventType.FILE_WRITE:
            file_res = event.destination
            if file_res:
                file_node = self._ensure_resource_node(file_res, session_id)
                # Actor/Tool -> File (WROTE_TO)
                self._add_edge(
                    source_id=actor_node.node_id,
                    target_id=file_node.node_id,
                    edge_type=EdgeType.WROTE_TO,
                    event=event,
                )
                primary_node_id = file_node.node_id

        elif event.event_type == EventType.PROCESS_EXEC:
            proc_res = event.source
            if proc_res:
                proc_node = self._ensure_resource_node(proc_res, session_id)
                # Tool/Actor -> Process (SPAWNED)
                self._add_edge(
                    source_id=actor_node.node_id,
                    target_id=proc_node.node_id,
                    edge_type=EdgeType.SPAWNED,
                    event=event,
                )
                primary_node_id = proc_node.node_id

        elif event.event_type == EventType.NETWORK_REQUEST:
            net_res = event.destination
            if net_res:
                net_node = self._ensure_resource_node(net_res, session_id)
                # Agent/Tool -> Network Endpoint (SENT_TO)
                self._add_edge(
                    source_id=actor_node.node_id,
                    target_id=net_node.node_id,
                    edge_type=EdgeType.SENT_TO,
                    event=event,
                )
                primary_node_id = net_node.node_id

        elif event.event_type == EventType.NETWORK_RESPONSE:
            net_res = event.source
            if net_res:
                net_node = self._ensure_resource_node(net_res, session_id)
                # Network Endpoint -> Agent/Tool (RECEIVED_FROM)
                self._add_edge(
                    source_id=net_node.node_id,
                    target_id=actor_node.node_id,
                    edge_type=EdgeType.RECEIVED_FROM,
                    event=event,
                )
                primary_node_id = net_node.node_id

        elif event.event_type == EventType.LLM_REQUEST:
            endpoint = event.payload.get("endpoint", "llm:model")
            provider = event.payload.get("provider", "LLM")
            llm_node_id = f"llm:{provider.lower()}"
            llm_node = self.store.get_node(llm_node_id)
            if not llm_node:
                llm_node = GraphNode(
                    node_id=llm_node_id,
                    node_type=NodeType.LLM,
                    label=f"{provider} ({event.payload.get('model', 'default')})",
                    session_id=session_id,
                    properties={"endpoint": endpoint},
                )
                self.store.add_node(llm_node)

            # Agent -> LLM (SENT_TO)
            self._add_edge(
                source_id=actor_node.node_id,
                target_id=llm_node_id,
                edge_type=EdgeType.SENT_TO,
                event=event,
            )
            primary_node_id = llm_node_id

        elif event.event_type == EventType.LLM_RESPONSE:
            provider = event.payload.get("provider", "LLM")
            llm_node_id = f"llm:{provider.lower()}"
            # LLM -> Agent (RETURNED_TO)
            self._add_edge(
                source_id=llm_node_id,
                target_id=actor_node.node_id,
                edge_type=EdgeType.RETURNED_TO,
                event=event,
            )
            primary_node_id = llm_node_id

        # 4. Attach Scope Membership Edge
        if event.execution_scope_id:
            scope_node_id = f"scope:{event.execution_scope_id}"
            if primary_node_id != scope_node_id:
                self._add_edge(
                    source_id=primary_node_id,
                    target_id=scope_node_id,
                    edge_type=EdgeType.BELONGS_TO_SCOPE,
                    event=event,
                )

        # 5. Attach Explicit Causal Edge
        if event.causal_event_id and event.causal_event_id in self._event_to_node:
            causal_node_id = self._event_to_node[event.causal_event_id]
            if causal_node_id != primary_node_id:
                self._add_edge(
                    source_id=causal_node_id,
                    target_id=primary_node_id,
                    edge_type=EdgeType.CAUSED_BY,
                    event=event,
                )

        self._event_to_node[event.event_id] = primary_node_id

    def _ensure_actor_node(self, event: GuardXEvent) -> GraphNode:
        actor = event.actor
        node = self.store.get_node(actor.actor_id)
        if not node:
            type_map = {
                ActorType.USER: NodeType.USER,
                ActorType.AGENT: NodeType.AGENT,
                ActorType.TOOL: NodeType.TOOL,
                ActorType.SUBPROCESS: NodeType.PROCESS,
                ActorType.SYSTEM: NodeType.AGENT,
            }
            node = GraphNode(
                node_id=actor.actor_id,
                node_type=type_map.get(actor.actor_type, NodeType.AGENT),
                label=actor.display_name,
                session_id=event.session_id,
                properties=actor.metadata,
            )
            self.store.add_node(node)
        return node

    def _ensure_resource_node(self, res, session_id: str) -> GraphNode:
        node = self.store.get_node(res.resource_id)
        if not node:
            type_map = {
                ResourceType.FILE: NodeType.FILE,
                ResourceType.PROCESS: NodeType.PROCESS,
                ResourceType.TOOL: NodeType.TOOL,
                ResourceType.NETWORK_ENDPOINT: NodeType.NETWORK_ENDPOINT,
                ResourceType.LLM: NodeType.LLM,
            }
            node = GraphNode(
                node_id=res.resource_id,
                node_type=type_map.get(res.resource_type, NodeType.FILE),
                label=res.uri,
                session_id=session_id,
                properties={"trust_level": res.trust_level.value, **res.metadata},
            )
            self.store.add_node(node)
        return node

    def _add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        event: GuardXEvent,
    ) -> None:
        edge = GraphEdge(
            edge_id=f"edge_{uuid.uuid4().hex[:12]}",
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            event_id=event.event_id,
            provenance_quality=event.provenance_quality,
            confidence=event.confidence,
            properties={"timestamp": event.timestamp.isoformat()},
        )
        self.store.add_edge(edge)

    def explain_execution_causality(self, target_node_id: str) -> Dict[str, Any]:
        """Traces the backward execution/causal path to answer 'What execution events led to this action?'.
        
        CRITICAL SEMANTIC GUARANTEE:
        This explains EXECUTION relationships and EVENT CAUSALITY only.
        It does NOT claim or imply sensitive data flow between resources.
        Information flow is established separately by the Data Lineage engine in Milestone 3.
        """
        ancestor_ids = self.store.get_ancestors(target_node_id)
        ancestor_nodes = [self.store.get_node(nid) for nid in ancestor_ids if self.store.get_node(nid)]
        target_node = self.store.get_node(target_node_id)
        if target_node:
            ancestor_nodes.append(target_node)
        return {
            "target_node_id": target_node_id,
            "semantic_layer": "EXECUTION_PROVENANCE",
            "disclaimer": "Explains execution/event causality only; does NOT imply unproven data flow",
            "causal_nodes": [n.to_dict() for n in ancestor_nodes],
        }

    def explain_causality(self, target_node_id: str) -> List[GraphNode]:
        """Traces backward execution/causal path (execution relationships only, not data flow)."""
        ancestor_ids = self.store.get_ancestors(target_node_id)
        ancestor_nodes = [self.store.get_node(nid) for nid in ancestor_ids if self.store.get_node(nid)]
        target_node = self.store.get_node(target_node_id)
        if target_node:
            ancestor_nodes.append(target_node)
        return ancestor_nodes
