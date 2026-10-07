"""Deterministic Transformation Engine for GuardX Milestone 3.

Guarantees:
- Deterministic tracking of transformations (COPY, CONCAT, FORMAT, JSON_SERIALIZE, BASE64_ENCODE, URL_ENCODE, TOKENIZE, REDACT).
- Explicit security semantics (PRESERVING vs SANITIZING).
- Preservation of backward traceability: derived entities link back to antecedent entities.
- Zero raw secrets persisted: Keyed HMACs and synthetic tokens only.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from guardx.core.crypto import compute_keyed_fingerprint
from guardx.core.enums import (
    ProvenanceQuality,
    TransformationSecuritySemantics,
)
from guardx.lineage.models import (
    DataClassification,
    DataEntity,
    DataRepresentation,
    DetectionMethod,
    LineageEdge,
    LineageEdgeType,
    LineageNode,
    LineageNodeType,
    Transformation,
)
from guardx.lineage.store import DataLineageStore


class TransformationEngine:
    """Manages deterministic transformations of sensitive data entities."""

    TRANSFORMATION_SEMANTICS: Dict[str, TransformationSecuritySemantics] = {
        "COPY": TransformationSecuritySemantics.PRESERVING,
        "CONCAT": TransformationSecuritySemantics.PRESERVING,
        "FORMAT": TransformationSecuritySemantics.PRESERVING,
        "JSON_SERIALIZE": TransformationSecuritySemantics.PRESERVING,
        "BASE64_ENCODE": TransformationSecuritySemantics.PRESERVING,
        "URL_ENCODE": TransformationSecuritySemantics.PRESERVING,
        "TOKENIZE": TransformationSecuritySemantics.SANITIZING,
        "REDACT": TransformationSecuritySemantics.SANITIZING,
    }

    def __init__(self, store: DataLineageStore, session_key: str = ""):
        self.store = store
        self.session_key = session_key

    def transform(
        self,
        transformation_type: str,
        input_entities: List[DataEntity],
        originating_event_id: str,
        output_label: Optional[str] = None,
        output_synthetic_token: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Transformation, DataEntity, LineageEdge]:
        """Applies a deterministic transformation, creating a derived DataEntity and lineage edge.
        
        Backward traceability: Output entity links directly back to input entities.
        """
        if not input_entities:
            raise ValueError("Transformations require at least one input DataEntity")

        primary_input = input_entities[0]
        tf_type = transformation_type.upper()
        semantics = self.TRANSFORMATION_SEMANTICS.get(
            tf_type, TransformationSecuritySemantics.PRESERVING
        )

        tf_id = f"tf_{uuid.uuid4().hex[:12]}"
        output_entity_id = f"entity_derived_{uuid.uuid4().hex[:12]}"

        # Determine representation and classification
        if tf_type == "TOKENIZE":
            representation = DataRepresentation.TOKENIZED.value
            classification = DataClassification.CREDENTIAL_REFERENCE.value
            token = output_synthetic_token or f"{{{{TOKEN_{primary_input.label}_{uuid.uuid4().hex[:8]}}}}}"
        elif tf_type in ("BASE64_ENCODE", "URL_ENCODE"):
            representation = DataRepresentation.ENCODED.value
            classification = primary_input.classification
            token = output_synthetic_token
        elif tf_type == "REDACT":
            representation = DataRepresentation.REDACTED.value
            classification = primary_input.classification
            token = output_synthetic_token or "[REDACTED]"
        else:
            representation = DataRepresentation.DERIVED.value
            classification = primary_input.classification
            token = output_synthetic_token

        # Derive a keyed HMAC fingerprint for the derived representation
        fingerprint_content = f"{primary_input.fingerprint_hmac}:{tf_type}:{output_entity_id}"
        derived_fingerprint = compute_keyed_fingerprint(
            fingerprint_content, self.session_key or "guardx_derived_key"
        )

        derived_entity = DataEntity(
            entity_id=output_entity_id,
            session_id=primary_input.session_id,
            label=output_label or f"{primary_input.label}_{tf_type.lower()}",
            classification=classification,
            representation=representation,
            origin_resource_id=primary_input.origin_resource_id,
            fingerprint_hmac=derived_fingerprint,
            synthetic_token=token,
            discovered_event_id=originating_event_id,
            provenance_quality=ProvenanceQuality.DERIVED,
            confidence=1.0,
            derived_from_entity_id=primary_input.entity_id,
            metadata={
                "transformation_id": tf_id,
                "transformation_type": tf_type,
                "input_entity_ids": [e.entity_id for e in input_entities],
                **(details or {}),
            },
        )

        # Record Transformation
        tf_record = Transformation(
            transformation_id=tf_id,
            session_id=primary_input.session_id,
            transformation_type=tf_type,
            security_semantics=semantics,
            input_entity_ids=tuple(e.entity_id for e in input_entities),
            output_entity_ids=(derived_entity.entity_id,),
            originating_event_id=originating_event_id,
            provenance_quality=ProvenanceQuality.DERIVED,
            confidence=1.0,
            details=details or {},
        )

        # Store entity and transformation
        self.store.add_entity(derived_entity)
        self.store.add_transformation(tf_record)

        # Create lineage edge: input -> derived (TRANSFORMED_TO)
        edge = LineageEdge(
            edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
            source_id=f"entity:{primary_input.entity_id}",
            target_id=f"entity:{derived_entity.entity_id}",
            edge_type=LineageEdgeType.TRANSFORMED_TO,
            entity_id=derived_entity.entity_id,
            supporting_event_id=originating_event_id,
            provenance_quality=ProvenanceQuality.DERIVED,
            confidence=1.0,
            detection_method=DetectionMethod.TRANSFORMATION_MATCH,
            metadata={
                "transformation_id": tf_id,
                "transformation_type": tf_type,
                "security_semantics": semantics.value,
            },
        )
        self.store.add_edge(edge)

        return tf_record, derived_entity, edge
