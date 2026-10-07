"""Base Collector Abstraction for GuardX Runtime Observation.

Guarantees:
- Collectors NEVER directly construct persistent GuardXEvents.
- Collectors emit transient RawObservation objects to the centralized EventRecorder.
- Concurrency-safe observation lifecycle.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import RawObservation
from guardx.core.recorder import EventRecorder


class BaseCollector(ABC):
    """Abstract base class for all GuardX runtime observation collectors."""

    def __init__(self, recorder: EventRecorder):
        self.recorder = recorder

    @property
    @abstractmethod
    def collector_name(self) -> str:
        """Unique identifier for this collector."""
        pass

    def emit_observation(
        self,
        event_type: EventType,
        raw_payload: Dict[str, Any],
        actor_id: str,
        source_raw: Optional[str] = None,
        destination_raw: Optional[str] = None,
        causal_event_id: Optional[str] = None,
        provenance_quality: ProvenanceQuality = ProvenanceQuality.OBSERVED,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Constructs a transient RawObservation and sends it to EventRecorder.
        
        Returns the resulting immutable GuardXEvent produced by EventRecorder.
        """
        obs = RawObservation(
            event_type=event_type,
            raw_payload=raw_payload,
            actor_id=actor_id,
            source_raw=source_raw,
            destination_raw=destination_raw,
            causal_event_id=causal_event_id,
            provenance_quality=provenance_quality,
            confidence=confidence,
            metadata=metadata or {},
        )
        return self.recorder.record(obs)
