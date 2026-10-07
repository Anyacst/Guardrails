"""Unit tests for forward-compatible DataEntity and Transformation models."""

from dataclasses import FrozenInstanceError
import pytest

from guardx.core.enums import ProvenanceQuality, TransformationSecuritySemantics
from guardx.lineage.models import DataEntity, TaintEdge, Transformation


def test_data_entity_creation_and_immutability():
    entity = DataEntity(
        entity_id="entity_001",
        session_id="session_001",
        label="OPENAI_API_KEY",
        classification="CREDENTIAL",
        origin_resource_id="file:.env",
        fingerprint_hmac="a" * 64,
        synthetic_token="<GUARDX_SECRET_001>",
        discovered_event_id="evt_001",
    )

    assert entity.entity_id == "entity_001"
    assert entity.classification == "CREDENTIAL"
    assert entity.fingerprint_hmac == "a" * 64

    with pytest.raises(FrozenInstanceError):
        entity.classification = "PUBLIC"


def test_transformation_creation_and_immutability():
    tf = Transformation(
        transformation_id="tf_001",
        session_id="session_001",
        transformation_type="BASE64_ENCODE",
        security_semantics=TransformationSecuritySemantics.PRESERVING,
        input_entity_ids=("entity_001",),
        output_entity_ids=("entity_002",),
        originating_event_id="evt_002",
        provenance_quality=ProvenanceQuality.DERIVED,
        confidence=1.0,
        details={"algorithm": "base64"},
    )

    assert tf.transformation_type == "BASE64_ENCODE"
    assert tf.security_semantics == TransformationSecuritySemantics.PRESERVING
    assert tf.input_entity_ids == ("entity_001",)

    edge = TaintEdge(
        edge_id="edge_001",
        source_entity_id="entity_001",
        target_entity_id="entity_002",
        transformation_id="tf_001",
        confidence=1.0,
    )

    assert edge.source_entity_id == "entity_001"
    assert edge.target_entity_id == "entity_002"
