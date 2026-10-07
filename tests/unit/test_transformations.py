"""Unit tests for GuardX Deterministic Transformation Engine."""

import pytest
from guardx.core.enums import TransformationSecuritySemantics
from guardx.lineage.models import (
    DataClassification,
    DataEntity,
    DataRepresentation,
    LineageEdgeType,
)
from guardx.lineage.store import DataLineageStore
from guardx.lineage.transformations import TransformationEngine


def test_transformations_security_semantics_and_backward_lineage():
    store = DataLineageStore(session_id="session_tf")
    engine = TransformationEngine(store=store, session_key="test_key_tf")

    # 1. Base sensitive entity
    secret = DataEntity(
        entity_id="secret_root",
        session_id="session_tf",
        label="DATABASE_PASSWORD",
        classification=DataClassification.CREDENTIAL.value,
        representation=DataRepresentation.RAW.value,
        origin_resource_id="file:.env",
        fingerprint_hmac="hmac_db_pass_123",
    )
    store.add_entity(secret)

    # 2. BASE64_ENCODE (PRESERVING)
    tf1, b64_entity, edge1 = engine.transform(
        transformation_type="BASE64_ENCODE",
        input_entities=[secret],
        originating_event_id="evt_01",
        output_synthetic_token="{{B64_TOKEN}}",
    )
    assert tf1.security_semantics == TransformationSecuritySemantics.PRESERVING
    assert b64_entity.representation == DataRepresentation.ENCODED.value
    assert b64_entity.derived_from_entity_id == "secret_root"
    assert edge1.edge_type == LineageEdgeType.TRANSFORMED_TO

    # 3. JSON_SERIALIZE (PRESERVING)
    tf2, json_entity, edge2 = engine.transform(
        transformation_type="JSON_SERIALIZE",
        input_entities=[b64_entity],
        originating_event_id="evt_02",
        output_synthetic_token='{"key": "{{B64_TOKEN}}"}',
    )
    assert tf2.security_semantics == TransformationSecuritySemantics.PRESERVING
    assert json_entity.representation == DataRepresentation.DERIVED.value
    assert json_entity.derived_from_entity_id == b64_entity.entity_id

    # 4. Backward trace from json_entity should reach secret_root
    backward = store.trace_backward(json_entity.entity_id)
    assert backward.has_proven_flow is True
    assert "file:.env" in backward.origins
    # Verify hops reach secret_root
    hop_sources = [h.source for h in backward.hops]
    assert "entity:secret_root" in hop_sources


def test_sanitizing_transformations():
    store = DataLineageStore(session_id="session_tf_san")
    engine = TransformationEngine(store=store, session_key="test_key_tf")

    secret = DataEntity(
        entity_id="api_key_root",
        session_id="session_tf_san",
        label="API_KEY",
        classification=DataClassification.CREDENTIAL.value,
        representation=DataRepresentation.RAW.value,
        origin_resource_id="file:.env",
        fingerprint_hmac="hmac_api_root",
    )
    store.add_entity(secret)

    # TOKENIZE (SANITIZING)
    tf_tok, tok_entity, edge_tok = engine.transform(
        transformation_type="TOKENIZE",
        input_entities=[secret],
        originating_event_id="evt_tok",
        output_synthetic_token="{{SECRET_001_nonce}}",
    )
    assert tf_tok.security_semantics == TransformationSecuritySemantics.SANITIZING
    assert tok_entity.representation == DataRepresentation.TOKENIZED.value
    assert tok_entity.classification == DataClassification.CREDENTIAL_REFERENCE.value

    # REDACT (SANITIZING)
    tf_red, red_entity, edge_red = engine.transform(
        transformation_type="REDACT",
        input_entities=[secret],
        originating_event_id="evt_red",
    )
    assert tf_red.security_semantics == TransformationSecuritySemantics.SANITIZING
    assert red_entity.representation == DataRepresentation.REDACTED.value
    assert red_entity.synthetic_token == "[REDACTED]"
