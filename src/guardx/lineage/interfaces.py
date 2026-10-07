"""Forward-Compatible Abstract Interfaces for Data Lineage and Transformations."""

from abc import ABC, abstractmethod
from typing import List, Optional
from guardx.lineage.models import DataEntity, Transformation, TaintEdge


class LineageTracker(ABC):
    """Abstract interface for entity lineage tracking and propagation."""

    @abstractmethod
    def register_entity(self, entity: DataEntity) -> None:
        """Register newly discovered data entity."""
        pass

    @abstractmethod
    def trace_backward(self, entity_id: str) -> List[DataEntity]:
        """Trace origins and antecedent entities backward to source."""
        pass

    @abstractmethod
    def trace_forward(self, entity_id: str) -> List[DataEntity]:
        """Trace destination and descendant entities forward to sinks."""
        pass


class TransformationEngine(ABC):
    """Abstract interface for recording and evaluating transformations."""

    @abstractmethod
    def record_transformation(self, transformation: Transformation) -> TaintEdge:
        """Record transformation and produce corresponding taint edge."""
        pass
