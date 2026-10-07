"""GraphStore Interface & InMemoryGraphStore for Execution Provenance.

Guarantees:
- Graph operations: add_node, add_edge, get_node, get_edges, get_ancestors, get_descendants, find_path.
- Prevents duplicate canonical nodes.
- Thread-safe graph mutation.
"""

from abc import ABC, abstractmethod
from collections import deque
import threading
from typing import Dict, List, Optional, Set

from guardx.graph.models import EdgeType, ExecutionGraph, GraphEdge, GraphNode


class GraphStore(ABC):
    """Abstract interface for storing and traversing the execution provenance DAG."""

    @abstractmethod
    def add_node(self, node: GraphNode) -> None:
        """Adds or idempotently merges a node."""
        pass

    @abstractmethod
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieves a node by canonical ID."""
        pass

    @abstractmethod
    def get_nodes(self) -> List[GraphNode]:
        """Returns all nodes in store."""
        pass

    @abstractmethod
    def add_edge(self, edge: GraphEdge) -> None:
        """Adds a directed edge."""
        pass

    @abstractmethod
    def get_edges(
        self,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        edge_type: Optional[EdgeType] = None,
    ) -> List[GraphEdge]:
        """Queries edges by source, target, or type filter."""
        pass

    @abstractmethod
    def get_ancestors(self, node_id: str) -> Set[str]:
        """Returns set of all node IDs that lead into node_id."""
        pass

    @abstractmethod
    def get_descendants(self, node_id: str) -> Set[str]:
        """Returns set of all node IDs reachable from node_id."""
        pass

    @abstractmethod
    def find_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Returns ordered list of node IDs forming a path from source to target."""
        pass

    @abstractmethod
    def get_scope_subgraph(self, scope_id: str) -> ExecutionGraph:
        """Returns subgraph belonging to execution scope."""
        pass

    @abstractmethod
    def get_session_graph(self, session_id: str) -> ExecutionGraph:
        """Returns complete graph for session."""
        pass


class InMemoryGraphStore(GraphStore):
    """Thread-safe in-memory execution DAG store."""

    def __init__(self):
        self._lock = threading.RLock()
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._outgoing: Dict[str, List[GraphEdge]] = {}
        self._incoming: Dict[str, List[GraphEdge]] = {}

    def add_node(self, node: GraphNode) -> None:
        with self._lock:
            if node.node_id not in self._nodes:
                self._nodes[node.node_id] = node
                self._outgoing[node.node_id] = []
                self._incoming[node.node_id] = []
            else:
                # Merge properties if updated
                existing = self._nodes[node.node_id]
                merged_props = {**existing.properties, **node.properties}
                merged_node = GraphNode(
                    node_id=node.node_id,
                    node_type=existing.node_type,
                    label=existing.label,
                    session_id=existing.session_id,
                    properties=merged_props,
                    first_seen=existing.first_seen,
                )
                self._nodes[node.node_id] = merged_node

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        with self._lock:
            return self._nodes.get(node_id)

    def get_nodes(self) -> List[GraphNode]:
        with self._lock:
            return list(self._nodes.values())

    def add_edge(self, edge: GraphEdge) -> None:
        with self._lock:
            # Avoid duplicate identical edges
            for existing in self._outgoing.get(edge.source_id, []):
                if (
                    existing.source_id == edge.source_id
                    and existing.target_id == edge.target_id
                    and existing.edge_type == edge.edge_type
                    and existing.event_id == edge.event_id
                ):
                    return

            self._edges.append(edge)
            self._outgoing.setdefault(edge.source_id, []).append(edge)
            self._incoming.setdefault(edge.target_id, []).append(edge)

    def get_edges(
        self,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        edge_type: Optional[EdgeType] = None,
    ) -> List[GraphEdge]:
        with self._lock:
            if source_id:
                candidates = self._outgoing.get(source_id, [])
            elif target_id:
                candidates = self._incoming.get(target_id, [])
            else:
                candidates = self._edges

            result = []
            for e in candidates:
                if source_id and e.source_id != source_id:
                    continue
                if target_id and e.target_id != target_id:
                    continue
                if edge_type and e.edge_type != edge_type:
                    continue
                result.append(e)
            return result

    def get_ancestors(self, node_id: str) -> Set[str]:
        """BFS backward traversal along incoming edges."""
        with self._lock:
            ancestors = set()
            queue = deque([node_id])
            while queue:
                curr = queue.popleft()
                for edge in self._incoming.get(curr, []):
                    parent = edge.source_id
                    if parent not in ancestors:
                        ancestors.add(parent)
                        queue.append(parent)
            return ancestors

    def get_descendants(self, node_id: str) -> Set[str]:
        """BFS forward traversal along outgoing edges."""
        with self._lock:
            descendants = set()
            queue = deque([node_id])
            while queue:
                curr = queue.popleft()
                for edge in self._outgoing.get(curr, []):
                    child = edge.target_id
                    if child not in descendants:
                        descendants.add(child)
                        queue.append(child)
            return descendants

    def find_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Finds shortest directed path from source_id to target_id."""
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return None
            if source_id == target_id:
                return [source_id]

            queue = deque([[source_id]])
            visited = {source_id}

            while queue:
                path = queue.popleft()
                curr = path[-1]

                for edge in self._outgoing.get(curr, []):
                    next_node = edge.target_id
                    if next_node == target_id:
                        return path + [next_node]
                    if next_node not in visited:
                        visited.add(next_node)
                        queue.append(path + [next_node])

            return None

    def get_scope_subgraph(self, scope_id: str) -> ExecutionGraph:
        """Returns nodes and edges directly associated with an execution scope."""
        with self._lock:
            scope_node_id = f"scope:{scope_id}" if not scope_id.startswith("scope:") else scope_id
            related_nodes = {scope_node_id}

            # Find all nodes linked to scope via BELONGS_TO_SCOPE
            for edge in self._incoming.get(scope_node_id, []):
                if edge.edge_type == EdgeType.BELONGS_TO_SCOPE:
                    related_nodes.add(edge.source_id)

            nodes = [self._nodes[nid] for nid in related_nodes if nid in self._nodes]
            edges = [
                e
                for e in self._edges
                if e.source_id in related_nodes and e.target_id in related_nodes
            ]

            session_id = nodes[0].session_id if nodes else "unknown"
            return ExecutionGraph(session_id=session_id, nodes=nodes, edges=edges)

    def get_session_graph(self, session_id: str) -> ExecutionGraph:
        """Returns all nodes and edges belonging to session."""
        with self._lock:
            nodes = [n for n in self._nodes.values() if n.session_id == session_id]
            node_ids = {n.node_id for n in nodes}
            edges = [
                e
                for e in self._edges
                if e.source_id in node_ids and e.target_id in node_ids
            ]
            return ExecutionGraph(session_id=session_id, nodes=nodes, edges=edges)
