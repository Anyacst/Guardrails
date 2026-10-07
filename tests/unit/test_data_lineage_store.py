"""Unit tests for GuardX DataLineageStore and Forward/Backward Lineage Tracing."""

import pytest
from guardx.core.enums import ProvenanceQuality
from guardx.lineage.models import (
    CarrierType,
    DataCarrier,
    DataClassification,
    DataEntity,
    DataRepresentation,
    DetectionMethod,
    LineageEdge,
    LineageEdgeType,
    LineageNodeType,
)
from guardx.lineage.store import DataLineageStore


def test_lineage_store_entity_and_carrier_registration():
    store = DataLineageStore(session_id="session_test")

    entity = DataEntity(
        entity_id="entity_secret_01",
        session_id="session_test",
        label="DEMO_API_KEY",
        classification=DataClassification.CREDENTIAL.value,
        representation=DataRepresentation.RAW.value,
        origin_resource_id="file:.env",
        fingerprint_hmac="hmac_test_12345",
        synthetic_token=None,
        discovered_event_id="evt_01",
    )
    node = store.add_entity(entity)

    assert node.node_id == "entity:entity_secret_01"
    assert node.node_type == LineageNodeType.DATA_ENTITY
    assert store.get_entity("entity_secret_01") == entity
    assert not entity.raw_value_persisted

    carrier = DataCarrier(
        carrier_id="carrier_01",
        carrier_type=CarrierType.FILE_CONTENT.value,
        session_id="session_test",
        supporting_event_id="evt_01",
        contained_entity_ids=(entity.entity_id,),
        source_actor_or_resource="file:.env",
        destination_actor_or_resource="agent:groq",
    )
    c_node = store.add_carrier(carrier)

    assert c_node.node_id == "carrier:carrier_01"
    assert c_node.node_type == LineageNodeType.DATA_CARRIER
    assert store.get_carrier("carrier_01") == carrier


def test_forward_and_backward_lineage_trace():
    store = DataLineageStore(session_id="session_test")

    # 1. File node
    file_node = store.ensure_resource_node("file:.env", LineageNodeType.FILE, ".env")

    # 2. Entity
    entity = DataEntity(
        entity_id="secret_42",
        session_id="session_test",
        label="STRIPE_SECRET_KEY",
        classification=DataClassification.CREDENTIAL.value,
        representation=DataRepresentation.RAW.value,
        origin_resource_id="file:.env",
        fingerprint_hmac="hmac_stripe_42",
    )
    store.add_entity(entity)

    # 3. File -> CONTAINS -> Entity
    store.add_edge(LineageEdge(
        edge_id="e1",
        source_id="file:.env",
        target_id="entity:secret_42",
        edge_type=LineageEdgeType.CONTAINS,
        entity_id="secret_42",
        supporting_event_id="evt_read",
        detection_method=DetectionMethod.STRUCTURED_PROPAGATION,
    ))

    # 4. Carrier
    carrier = DataCarrier(
        carrier_id="c_tool_result",
        carrier_type=CarrierType.TOOL_RESULT.value,
        session_id="session_test",
        supporting_event_id="evt_tool",
        contained_entity_ids=("secret_42",),
    )
    store.add_carrier(carrier)

    # Entity -> FLOWS_TO -> Carrier
    store.add_edge(LineageEdge(
        edge_id="e2",
        source_id="entity:secret_42",
        target_id="carrier:c_tool_result",
        edge_type=LineageEdgeType.FLOWS_TO,
        entity_id="secret_42",
        supporting_event_id="evt_tool",
        detection_method=DetectionMethod.STRUCTURED_PROPAGATION,
    ))

    # 5. LLM Sink node
    llm_node = store.ensure_resource_node("llm:groq", LineageNodeType.LLM, "Groq LLM")

    # Carrier -> FLOWS_TO -> LLM
    store.add_edge(LineageEdge(
        edge_id="e3",
        source_id="carrier:c_tool_result",
        target_id="llm:groq",
        edge_type=LineageEdgeType.FLOWS_TO,
        entity_id="secret_42",
        supporting_event_id="evt_llm",
        detection_method=DetectionMethod.TOKEN_IDENTITY,
    ))

    # Test Forward Trace: from secret_42 to destinations
    fwd = store.trace_forward("secret_42")
    assert fwd.has_proven_flow is True
    assert "llm:groq" in fwd.destinations
    assert len(fwd.hops) == 2  # secret_42 -> carrier -> llm:groq
    assert "PROVEN FLOW" in fwd.explanation

    # Test Backward Trace: from llm:groq back to origins
    bwd = store.trace_backward("llm:groq")
    assert bwd.has_proven_flow is True
    assert "file:.env" in bwd.origins
    assert len(bwd.hops) == 3


def test_negative_no_flow_scenario():
    """Verifies that an entity not connected to a sink reports NO PROVEN FLOW."""
    store = DataLineageStore(session_id="session_test")

    entity = DataEntity(
        entity_id="isolated_secret",
        session_id="session_test",
        label="ISOLATED_KEY",
        classification=DataClassification.CREDENTIAL.value,
        representation=DataRepresentation.RAW.value,
        origin_resource_id="file:.env",
        fingerprint_hmac="hmac_iso",
    )
    store.add_entity(entity)

    # No edges to any sink
    fwd = store.trace_forward("isolated_secret")
    assert fwd.has_proven_flow is False
    assert len(fwd.destinations) == 0
    assert "NO PROVEN FLOW" in fwd.explanation


def test_lineage_store_serialization_zero_secrets():
    """Ensures serialized snapshot contains zero raw secrets."""
    store = DataLineageStore(session_id="session_test")
    entity = DataEntity(
        entity_id="ent_01",
        session_id="session_test",
        label="PASSWORD",
        classification=DataClassification.CREDENTIAL.value,
        representation=DataRepresentation.RAW.value,
        origin_resource_id="file:.env",
        fingerprint_hmac="a" * 64,
        synthetic_token="{{SECRET_001}}",
    )
    store.add_entity(entity)

    snapshot = store.to_dict()
    serialized = str(snapshot)
    assert "a" * 64 in serialized
    assert "{{SECRET_001}}" in serialized
    assert snapshot["entities"][0]["raw_value_persisted"] is False
