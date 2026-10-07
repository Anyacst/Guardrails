"""End-to-End Tests for GuardX Milestone 3 — Sensitive Data Lineage & Information Flow.

Verifies:
1. Experiment A — Positive Flow (Sensitive entity -> token -> carriers -> LLM Request -> Groq)
2. Experiment B — Negative Flow (File read + LLM request with NO secret -> NO PROVEN FLOW)
3. Experiment C — Transformation (Secret -> Base64 -> JSON -> Request with backward trace)
4. Milestone 3 REST API endpoints (lineage, entities, forward trace, backward trace, experiment runner)
5. Strict Invariant: Zero raw secrets in REST payloads, traces, or entity snapshots.
"""

from fastapi.testclient import TestClient
import pytest

from guardx.server.app import create_app
from guardx.server.session_registry import global_session_registry


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_experiment_a_positive_flow_e2e(client):
    """Experiment A: Confirms concrete evidence along every hop to LLM."""
    resp = client.post("/api/sessions/m3_exp_a/demo/run_lineage_experiment?experiment=positive")
    assert resp.status_code == 200
    data = resp.json()

    assert data["experiment"] == "positive"
    assert data["status"] == "completed"
    assert data["has_proven_flow"] is True
    assert any("llm:" in d for d in data["destinations"])
    assert "PROVEN FLOW" in data["explanation"]

    # Verify GET /api/sessions/m3_exp_a/lineage
    l_resp = client.get("/api/sessions/m3_exp_a/lineage")
    assert l_resp.status_code == 200
    lineage = l_resp.json()
    assert len(lineage["nodes"]) > 0
    assert len(lineage["edges"]) > 0
    assert len(lineage["entities"]) > 0
    assert len(lineage["carriers"]) > 0

    # Ensure zero raw secrets in serialized lineage
    raw_str = str(lineage)
    assert "guardx-demo-not-real" not in raw_str
    assert "guardx-demo-password" not in raw_str


def test_experiment_b_negative_flow_e2e(client):
    """Experiment B: Proves GuardX does NOT infer flow merely because events are sequential."""
    resp = client.post("/api/sessions/m3_exp_b/demo/run_lineage_experiment?experiment=negative")
    assert resp.status_code == 200
    data = resp.json()

    assert data["experiment"] == "negative"
    assert data["status"] == "completed"
    assert data["has_proven_flow"] is False
    assert len(data["destinations"]) == 0
    assert "NO PROVEN FLOW" in data["explanation"]


def test_experiment_c_transformation_e2e(client):
    """Experiment C: Secret -> Base64 -> JSON -> Request with backward trace to origin."""
    resp = client.post("/api/sessions/m3_exp_c/demo/run_lineage_experiment?experiment=transformation")
    assert resp.status_code == 200
    data = resp.json()

    assert data["experiment"] == "transformation"
    assert data["status"] == "completed"
    assert data["reaches_origin_secret"] is True
    assert data["hops_count"] >= 2
    assert "file:.env" in str(data["backward_origins"])


def test_lineage_trace_endpoints_e2e(client):
    """Verifies forward and backward trace REST API endpoints."""
    # First run experiment A to populate session
    client.post("/api/sessions/m3_trace_test/demo/run_lineage_experiment?experiment=positive")

    # Get entities
    ent_resp = client.get("/api/sessions/m3_trace_test/lineage/entities")
    assert ent_resp.status_code == 200
    entities = ent_resp.json()
    assert len(entities) > 0
    first_ent_id = entities[0]["entity_id"]

    # Test forward trace endpoint
    fwd_resp = client.get(f"/api/sessions/m3_trace_test/lineage/trace/forward/{first_ent_id}")
    assert fwd_resp.status_code == 200
    fwd_data = fwd_resp.json()
    assert fwd_data["direction"] == "FORWARD"
    assert fwd_data["has_proven_flow"] is True
    assert len(fwd_data["hops"]) > 0

    # Test backward trace endpoint
    llm_node_id = fwd_data["destinations"][0]
    bwd_resp = client.get(f"/api/sessions/m3_trace_test/lineage/trace/backward/{llm_node_id}")
    assert bwd_resp.status_code == 200
    bwd_data = bwd_resp.json()
    assert bwd_data["direction"] == "BACKWARD"
    assert bwd_data["has_proven_flow"] is True
    assert len(bwd_data["origins"]) > 0
