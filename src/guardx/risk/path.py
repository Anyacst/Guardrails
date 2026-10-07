"""Explainable Risk Path Data Structures for GuardX Milestone 4.

Packages complete end-to-end provenance and data lineage evidence
for every security finding.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from guardx.lineage.models import LineageTraceHop


@dataclass(frozen=True)
class ExplainableRiskPath:
    """Complete, human-interpretable evidence chain for a security finding."""
    source_resource: str
    source_entity_id: str
    source_entity_label: str
    classification: str
    representation: str
    destination_resource: str
    source_trust: str
    destination_trust: str
    boundary_transition: str
    hops: List[Dict[str, Any]]
    transformations: List[str]
    supporting_event_ids: List[str]
    evidence_quality: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_resource": self.source_resource,
            "source_entity_id": self.source_entity_id,
            "source_entity_label": self.source_entity_label,
            "classification": self.classification,
            "representation": self.representation,
            "destination_resource": self.destination_resource,
            "source_trust": self.source_trust,
            "destination_trust": self.destination_trust,
            "boundary_transition": self.boundary_transition,
            "hops": self.hops,
            "transformations": self.transformations,
            "supporting_event_ids": self.supporting_event_ids,
            "evidence_quality": self.evidence_quality,
            "confidence": self.confidence,
        }
