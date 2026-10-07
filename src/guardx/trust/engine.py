"""Trust Boundary Engine for GuardX Milestone 4.

Monitors proven information flow and execution hops to identify
when data or causal flow crosses between different trust levels.
"""

from typing import Any, Callable, Dict, List, Optional
import uuid

from guardx.trust.models import TrustBoundaryCrossing, TrustLevel
from guardx.trust.resolver import TrustResolver


class TrustBoundaryEngine:
    """Evaluates provenance and lineage paths to detect trust boundary crossings."""

    def __init__(
        self,
        resolver: Optional[TrustResolver] = None,
        on_crossing_callback: Optional[Callable[[TrustBoundaryCrossing], None]] = None,
    ):
        self.resolver = resolver or TrustResolver()
        self.on_crossing_callback = on_crossing_callback
        self._crossings: List[TrustBoundaryCrossing] = []

    def evaluate_hop(
        self,
        session_id: str,
        source_id: str,
        destination_id: str,
        entity_id: Optional[str] = None,
        carrier_id: Optional[str] = None,
        supporting_event_id: Optional[str] = None,
        lineage_hop_count: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[TrustBoundaryCrossing]:
        """Evaluates whether a single hop crosses a trust boundary."""
        source_trust = self.resolver.resolve(source_id)
        dest_trust = self.resolver.resolve(destination_id)

        if source_trust != dest_trust and dest_trust not in (TrustLevel.UNKNOWN, TrustLevel.LOCAL):
            crossing = TrustBoundaryCrossing(
                crossing_id=f"cross_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                source_resource_or_actor=source_id,
                destination_resource_or_actor=destination_id,
                source_trust=source_trust,
                destination_trust=dest_trust,
                entity_id=entity_id,
                carrier_id=carrier_id,
                supporting_event_id=supporting_event_id,
                lineage_hop_count=lineage_hop_count,
                metadata=metadata or {},
            )
            self._crossings.append(crossing)
            if self.on_crossing_callback:
                self.on_crossing_callback(crossing)
            return crossing

        return None

    def get_crossings(self, session_id: Optional[str] = None) -> List[TrustBoundaryCrossing]:
        if session_id:
            return [c for c in self._crossings if c.session_id == session_id]
        return list(self._crossings)
