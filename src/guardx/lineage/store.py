"""Data Lineage Store for GuardX Milestone 3.

Guarantees:
- Dedicated, isolated store for Data Lineage (strictly separated from Execution Provenance).
- Thread-safe storage for DataEntity, DataCarrier, Transformation, LineageNode, and LineageEdge.
- Graph traversals for forward trace (where did information go?) and backward trace (where did information originate?).
- Explicit "NO PROVEN FLOW" reporting when evidence does not establish flow to a sink.
- Zero raw secrets persisted: Keyed HMAC fingerprints and synthetic tokens only.
"""

from collections import deque
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from guardx.core.enums import ProvenanceQuality
from guardx.lineage.models import (
    CarrierType,
    DataCarrier,
    DataEntity,
    DetectionMethod,
    LineageEdge,
    LineageEdgeType,
    LineageNode,
    LineageNodeType,
    LineageTraceHop,
    LineageTraceResult,
    Transformation,
)


class DataLineageStore:
    """Thread-safe graph and entity store dedicated to sensitive data lineage."""

    def __init__(self, session_id: str = ""):
        self.session_id = session_id
        self._lock = threading.RLock()
        self._entities: Dict[str, DataEntity] = {}
        self._carriers: Dict[str, DataCarrier] = {}
        self._transformations: Dict[str, Transformation] = {}
        self._nodes: Dict[str, LineageNode] = {}
        self._edges: Dict[str, LineageEdge] = {}
        self._forward_adj: Dict[str, List[LineageEdge]] = {}
        self._backward_adj: Dict[str, List[LineageEdge]] = {}

    # -------------------------------------------------------------------------
    # Mutation Methods
    # -------------------------------------------------------------------------

    def add_entity(self, entity: DataEntity) -> LineageNode:
        """Stores a DataEntity and ensures its canonical LineageNode exists."""
        with self._lock:
            self._entities[entity.entity_id] = entity
            node_id = f"entity:{entity.entity_id}"
            node = LineageNode(
                node_id=node_id,
                node_type=LineageNodeType.DATA_ENTITY,
                label=f"{entity.label} ({entity.representation})",
                session_id=entity.session_id or self.session_id,
                entity_id=entity.entity_id,
                properties={
                    "classification": entity.classification,
                    "representation": entity.representation,
                    "fingerprint_hmac": entity.fingerprint_hmac,
                    "fingerprint_preview": f"{entity.fingerprint_hmac[:12]}..." if entity.fingerprint_hmac else "",
                    "synthetic_token": entity.synthetic_token,
                    "origin_resource_id": entity.origin_resource_id,
                    "discovered_event_id": entity.discovered_event_id,
                    "raw_value_persisted": False,
                    "confidence": entity.confidence,
                },
            )
            self._nodes[node_id] = node
            return node

    def add_carrier(self, carrier: DataCarrier) -> LineageNode:
        """Stores a DataCarrier and ensures its canonical LineageNode exists."""
        with self._lock:
            self._carriers[carrier.carrier_id] = carrier
            node_id = f"carrier:{carrier.carrier_id}"
            node = LineageNode(
                node_id=node_id,
                node_type=LineageNodeType.DATA_CARRIER,
                label=f"{carrier.carrier_type}#{carrier.sequence_number}",
                session_id=carrier.session_id or self.session_id,
                carrier_id=carrier.carrier_id,
                properties={
                    "carrier_type": carrier.carrier_type,
                    "supporting_event_id": carrier.supporting_event_id,
                    "contained_entity_ids": list(carrier.contained_entity_ids),
                    "source": carrier.source_actor_or_resource,
                    "destination": carrier.destination_actor_or_resource,
                    "sequence_number": carrier.sequence_number,
                    "confidence": carrier.confidence,
                },
            )
            self._nodes[node_id] = node
            return node

    def ensure_resource_node(
        self,
        node_id: str,
        node_type: LineageNodeType,
        label: str,
        session_id: str = "",
        properties: Optional[Dict[str, Any]] = None,
    ) -> LineageNode:
        """Ensures a resource node (FILE, LLM, NETWORK_ENDPOINT) exists in the lineage DAG."""
        with self._lock:
            if node_id in self._nodes:
                return self._nodes[node_id]
            node = LineageNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                session_id=session_id or self.session_id,
                resource_id=node_id,
                properties=properties or {},
            )
            self._nodes[node_id] = node
            return node

    def add_edge(self, edge: LineageEdge) -> LineageEdge:
        """Stores a LineageEdge and updates forward and backward adjacency lists."""
        with self._lock:
            self._edges[edge.edge_id] = edge
            if edge.source_id not in self._forward_adj:
                self._forward_adj[edge.source_id] = []
            self._forward_adj[edge.source_id].append(edge)

            if edge.target_id not in self._backward_adj:
                self._backward_adj[edge.target_id] = []
            self._backward_adj[edge.target_id].append(edge)
            return edge

    def add_transformation(self, transformation: Transformation) -> None:
        """Stores a deterministic Transformation record."""
        with self._lock:
            self._transformations[transformation.transformation_id] = transformation

    # -------------------------------------------------------------------------
    # Retrieval Methods
    # -------------------------------------------------------------------------

    def get_entity(self, entity_id: str) -> Optional[DataEntity]:
        with self._lock:
            return self._entities.get(entity_id)

    def get_all_entities(self) -> List[DataEntity]:
        with self._lock:
            return list(self._entities.values())

    def get_carrier(self, carrier_id: str) -> Optional[DataCarrier]:
        with self._lock:
            return self._carriers.get(carrier_id)

    def get_all_carriers(self) -> List[DataCarrier]:
        with self._lock:
            return list(self._carriers.values())

    def get_node(self, node_id: str) -> Optional[LineageNode]:
        with self._lock:
            return self._nodes.get(node_id)

    def get_all_nodes(self) -> List[LineageNode]:
        with self._lock:
            return list(self._nodes.values())

    def get_edge(self, edge_id: str) -> Optional[LineageEdge]:
        with self._lock:
            return self._edges.get(edge_id)

    def get_all_edges(self) -> List[LineageEdge]:
        with self._lock:
            return list(self._edges.values())

    def get_transformation(self, transformation_id: str) -> Optional[Transformation]:
        with self._lock:
            return self._transformations.get(transformation_id)

    def get_all_transformations(self) -> List[Transformation]:
        with self._lock:
            return list(self._transformations.values())

    # -------------------------------------------------------------------------
    # Lineage Tracing (Forward & Backward)
    # -------------------------------------------------------------------------

    def trace_forward(self, entity_or_node_id: str) -> LineageTraceResult:
        """Traces where identifiable information moved forward along causal lineage paths.
        
        Answers: Where did this information go?
        """
        with self._lock:
            start_node_id = entity_or_node_id
            if start_node_id not in self._nodes:
                alt = f"entity:{entity_or_node_id}"
                if alt in self._nodes:
                    start_node_id = alt
                else:
                    alt_carrier = f"carrier:{entity_or_node_id}"
                    if alt_carrier in self._nodes:
                        start_node_id = alt_carrier
                    else:
                        for ent in self._entities.values():
                            if ent.label == entity_or_node_id:
                                start_node_id = f"entity:{ent.entity_id}"
                                break

            if start_node_id not in self._nodes:
                return LineageTraceResult(
                    entity_or_carrier_id=entity_or_node_id,
                    direction="FORWARD",
                    has_proven_flow=False,
                    origins=[],
                    destinations=[],
                    hops=[],
                    explanation=f"Entity or node '{entity_or_node_id}' not found in lineage graph.",
                )

            # BFS traversal forward
            visited_nodes: Set[str] = {start_node_id}
            queue = deque([start_node_id])
            hops: List[LineageTraceHop] = []
            destinations: Set[str] = set()

            while queue:
                curr = queue.popleft()
                out_edges = self._forward_adj.get(curr, [])
                for edge in out_edges:
                    tgt = edge.target_id
                    tgt_node = self._nodes.get(tgt)

                    # Determine if target is an external sink (LLM, FILE write, NETWORK)
                    if tgt_node:
                        if tgt_node.node_type in (
                            LineageNodeType.LLM,
                            LineageNodeType.NETWORK_ENDPOINT,
                        ):
                            destinations.add(tgt)
                        elif tgt_node.node_type == LineageNodeType.FILE and edge.edge_type in (
                            LineageEdgeType.FLOWS_TO,
                            LineageEdgeType.PRODUCED_BY,
                        ):
                            destinations.add(tgt)

                    transformation_name = None
                    if edge.metadata and "transformation_type" in edge.metadata:
                        transformation_name = edge.metadata["transformation_type"]

                    hop = LineageTraceHop(
                        source=edge.source_id,
                        destination=edge.target_id,
                        edge_type=edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type),
                        entity_id=edge.entity_id,
                        event_id=edge.supporting_event_id,
                        provenance_quality=edge.provenance_quality.value if hasattr(edge.provenance_quality, "value") else str(edge.provenance_quality),
                        confidence=edge.confidence,
                        detection_method=edge.detection_method.value if hasattr(edge.detection_method, "value") else str(edge.detection_method),
                        transformation=transformation_name,
                    )
                    hops.append(hop)

                    if tgt not in visited_nodes:
                        visited_nodes.add(tgt)
                        queue.append(tgt)

            # Determine origin
            origin_res = []
            entity_obj = self._entities.get(entity_or_node_id.replace("entity:", ""))
            if entity_obj and entity_obj.origin_resource_id:
                origin_res.append(entity_obj.origin_resource_id)

            has_proven_flow = len(destinations) > 0

            if has_proven_flow:
                explanation = (
                    f"PROVEN FLOW: Entity flowed across {len(hops)} hops and reached destination(s): "
                    + ", ".join(sorted(destinations))
                )
            else:
                explanation = (
                    "NO PROVEN FLOW: Information was tracked across internal carriers, but concrete "
                    "evidence confirms it did NOT propagate to external sinks or destination endpoints."
                )

            return LineageTraceResult(
                entity_or_carrier_id=entity_or_node_id,
                direction="FORWARD",
                has_proven_flow=has_proven_flow,
                origins=origin_res,
                destinations=sorted(list(destinations)),
                hops=hops,
                explanation=explanation,
            )

    def trace_backward(self, carrier_or_entity_id: str) -> LineageTraceResult:
        """Traces where identifiable information originated backward along causal lineage paths.
        
        Answers: Where did this information originate?
        """
        with self._lock:
            start_node_id = carrier_or_entity_id
            if start_node_id not in self._nodes:
                for prefix in ("carrier:", "entity:", "file:", "llm:"):
                    alt = f"{prefix}{carrier_or_entity_id}"
                    if alt in self._nodes:
                        start_node_id = alt
                        break

            if start_node_id not in self._nodes:
                for ent in self._entities.values():
                    if ent.label == carrier_or_entity_id:
                        start_node_id = f"entity:{ent.entity_id}"
                        break

            if start_node_id not in self._nodes:
                return LineageTraceResult(
                    entity_or_carrier_id=carrier_or_entity_id,
                    direction="BACKWARD",
                    has_proven_flow=False,
                    origins=[],
                    destinations=[],
                    hops=[],
                    explanation=f"Node '{carrier_or_entity_id}' not found in lineage graph.",
                )

            visited_nodes: Set[str] = {start_node_id}
            queue = deque([start_node_id])
            hops: List[LineageTraceHop] = []
            origins: Set[str] = set()

            while queue:
                curr = queue.popleft()
                in_edges = self._backward_adj.get(curr, [])
                for edge in in_edges:
                    src = edge.source_id
                    src_node = self._nodes.get(src)

                    if src_node:
                        if src_node.node_type in (
                            LineageNodeType.FILE,
                            LineageNodeType.NETWORK_ENDPOINT,
                        ):
                            origins.add(src)
                        elif src_node.node_type == LineageNodeType.DATA_ENTITY:
                            ent_id = src_node.entity_id or src.replace("entity:", "")
                            ent = self._entities.get(ent_id)
                            if ent and ent.origin_resource_id:
                                origins.add(ent.origin_resource_id)

                    transformation_name = None
                    if edge.metadata and "transformation_type" in edge.metadata:
                        transformation_name = edge.metadata["transformation_type"]

                    hop = LineageTraceHop(
                        source=edge.source_id,
                        destination=edge.target_id,
                        edge_type=edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type),
                        entity_id=edge.entity_id,
                        event_id=edge.supporting_event_id,
                        provenance_quality=edge.provenance_quality.value if hasattr(edge.provenance_quality, "value") else str(edge.provenance_quality),
                        confidence=edge.confidence,
                        detection_method=edge.detection_method.value if hasattr(edge.detection_method, "value") else str(edge.detection_method),
                        transformation=transformation_name,
                    )
                    hops.append(hop)

                    if src not in visited_nodes:
                        visited_nodes.add(src)
                        queue.append(src)

            has_proven_flow = len(origins) > 0
            explanation = (
                f"Information originated from: {', '.join(sorted(origins))}"
                if origins
                else "No origins discovered in backward trace."
            )

            return LineageTraceResult(
                entity_or_carrier_id=carrier_or_entity_id,
                direction="BACKWARD",
                has_proven_flow=has_proven_flow,
                origins=sorted(list(origins)),
                destinations=[start_node_id],
                hops=hops,
                explanation=explanation,
            )

    # -------------------------------------------------------------------------
    # Snapshot Serialization
    # -------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serializes entire lineage graph snapshot without any raw secrets."""
        with self._lock:
            return {
                "session_id": self.session_id,
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges.values()],
                "entities": [e.to_dict() for e in self._entities.values()],
                "carriers": [c.to_dict() for c in self._carriers.values()],
                "transformations": [t.to_dict() for t in self._transformations.values()],
            }
