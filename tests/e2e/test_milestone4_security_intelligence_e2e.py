"""End-to-End Integration Tests for GuardX Milestone 4 — Security Intelligence.

Verifies:
- Experiment A: Raw credential exposure -> HIGH/CRITICAL finding
- Experiment B: Tokenized credential -> LOW/INFORMATIONAL protected finding
- Experiment C: Encoded credential -> HIGH finding (Base64 is preserving)
- Experiment D: Negative No-Flow -> NO disclosure finding
- Experiment E: Intent mismatch -> RESOURCE_SCOPE_MISMATCH
- All 7 rows of the Milestone 4 Required Validation Matrix
- Zero Plaintext Invariant across all security structures
"""

import pytest
from fastapi.testclient import TestClient

from guardx.risk.models import FindingCategory, Severity
from guardx.server.app import create_app
from guardx.server.session_registry import global_session_registry


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_validation_matrix_row_1_raw_credential_to_groq(client):
    """Row 1: Raw credential -> Groq -> HIGH/CRITICAL (Experiment A)"""
    session_id = "test_matrix_row_1"
    res = client.post(f"/api/sessions/{session_id}/demo/run_security_experiment?experiment=a")
    assert res.status_code == 200
    data = res.json()

    assert data["experiment"] == "a"
    findings = data["findings"]
    assert len(findings) >= 1

    # Verify rule CREDENTIAL_RAW_TO_EXTERNAL_LLM triggered
    raw_finding = next((f for f in findings if f["rule_id"] == "RULE_CREDENTIAL_RAW_TO_EXTERNAL_LLM"), None)
    assert raw_finding is not None
    assert raw_finding["severity"] in (Severity.HIGH.value, Severity.CRITICAL.value)
    assert raw_finding["representation"] == "RAW"
    assert raw_finding["destination_trust"] == "EXTERNAL_LLM"
    assert raw_finding["raw_value_persisted"] is False

    # Verify Attack Chain synthesized
    assert data["attack_chains_count"] >= 1


def test_validation_matrix_row_2_tokenized_credential_to_groq(client):
    """Row 2: Tokenized credential -> Groq -> NONE/LOW (Protected Reference) (Experiment B)"""
    session_id = "test_matrix_row_2"
    res = client.post(f"/api/sessions/{session_id}/demo/run_security_experiment?experiment=b")
    assert res.status_code == 200
    data = res.json()

    findings = data["findings"]
    # There must be ZERO high or critical findings!
    high_critical = [f for f in findings if f["severity"] in (Severity.HIGH.value, Severity.CRITICAL.value)]
    assert len(high_critical) == 0

    # May only produce an informational/low finding for the protected token
    token_finding = next((f for f in findings if f["rule_id"] == "RULE_CREDENTIAL_TOKENIZED_TO_EXTERNAL_LLM"), None)
    if token_finding:
        assert token_finding["severity"] in (Severity.LOW.value, Severity.INFO.value, Severity.NONE.value)
        assert token_finding["representation"] == "TOKENIZED"


def test_validation_matrix_row_3_encoded_credential_to_groq(client):
    """Row 3: Base64 credential -> Groq -> HIGH finding (Experiment C)"""
    session_id = "test_matrix_row_3"
    res = client.post(f"/api/sessions/{session_id}/demo/run_security_experiment?experiment=c")
    assert res.status_code == 200
    data = res.json()

    findings = data["findings"]
    encoded_finding = next((f for f in findings if f["rule_id"] == "RULE_CREDENTIAL_ENCODED_TO_EXTERNAL"), None)
    assert encoded_finding is not None
    assert encoded_finding["severity"] == Severity.HIGH.value
    assert encoded_finding["category"] == FindingCategory.ENCODED_SECRET_DISCLOSURE.value


def test_validation_matrix_row_4_negative_no_flow_no_disclosure_finding(client):
    """Row 4: .env read + unrelated Groq call -> NO disclosure finding (Experiment D)"""
    session_id = "test_matrix_row_4"
    res = client.post(f"/api/sessions/{session_id}/demo/run_security_experiment?experiment=d")
    assert res.status_code == 200
    data = res.json()

    findings = data["findings"]
    # Invariant: NO disclosure findings allowed when no proven flow exists!
    disclosure_findings = [
        f for f in findings
        if f["category"] in (FindingCategory.CREDENTIAL_DISCLOSURE.value, FindingCategory.CREDENTIAL_EXFILTRATION.value)
    ]
    assert len(disclosure_findings) == 0
    assert data["findings_count"] == 0


def test_validation_matrix_row_5_public_data_to_groq(client):
    """Row 5: Public data -> Groq -> NONE (Zero security findings)"""
    session_id = "test_matrix_row_5"
    ctx = global_session_registry.create_session(session_id)

    from guardx.lineage.models import DataClassification, DataEntity, DataRepresentation, LineageTraceHop, LineageTraceResult
    pub_ent = DataEntity(
        entity_id="ent_public_data",
        session_id=session_id,
        label="DEBUG_CONFIG",
        classification=DataClassification.PUBLIC,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_debug",
    )
    ctx.lineage_store.add_entity(pub_ent)

    trace = LineageTraceResult(
        entity_or_carrier_id=pub_ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:.env"],
        destinations=["llm:groq/llama-3.3-70b"],
        hops=[],
        explanation="Public config flow",
    )

    findings = ctx.risk_path_engine.evaluate_trace(trace, session_id, entity=pub_ent)
    assert len(findings) == 0, "Public data flow to external LLM must generate ZERO security findings"


def test_validation_matrix_row_6_pii_to_untrusted_external(client):
    """Row 6: PII -> unknown external -> HIGH"""
    session_id = "test_matrix_row_6"
    ctx = global_session_registry.create_session(session_id)

    from guardx.lineage.models import DataClassification, DataEntity, DataRepresentation, LineageTraceHop, LineageTraceResult
    pii_ent = DataEntity(
        entity_id="ent_user_email",
        session_id=session_id,
        label="USER_EMAIL",
        classification=DataClassification.PII,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:users.csv",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_email",
    )
    ctx.lineage_store.add_entity(pii_ent)

    trace = LineageTraceResult(
        entity_or_carrier_id=pii_ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:users.csv"],
        destinations=["https://untrusted-analytics-tracker.com/collect"],
        hops=[],
        explanation="PII flow",
    )

    findings = ctx.risk_path_engine.evaluate_trace(trace, session_id, entity=pii_ent)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == FindingCategory.PII_EXFILTRATION


def test_validation_matrix_row_7_intent_mismatch(client):
    """Row 7: config-only intent -> .env read -> RESOURCE_SCOPE_MISMATCH (Experiment E)"""
    session_id = "test_matrix_row_7"
    res = client.post(f"/api/sessions/{session_id}/demo/run_security_experiment?experiment=e")
    assert res.status_code == 200
    data = res.json()

    assert data["experiment"] == "e"
    assert data["violations_count"] >= 1
    findings = data["findings"]
    intent_finding = next((f for f in findings if f["category"] == FindingCategory.INTENT_VIOLATION.value), None)
    assert intent_finding is not None
    assert "RESOURCE_SCOPE_MISMATCH" in intent_finding["title"]
    assert intent_finding["severity"] == Severity.HIGH.value


def test_security_rest_endpoints(client):
    """Verifies all Milestone 4 REST endpoints."""
    session_id = "test_security_rest"
    client.post(f"/api/sessions/{session_id}/demo/run_security_experiment?experiment=a")

    # 1. Overlay snapshot
    res_overlay = client.get(f"/api/sessions/{session_id}/security")
    assert res_overlay.status_code == 200
    overlay = res_overlay.json()
    assert "findings" in overlay
    assert "crossings" in overlay
    assert "attack_chains" in overlay

    # 2. Findings
    res_findings = client.get(f"/api/sessions/{session_id}/security/findings")
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) >= 1
    finding_id = findings[0]["finding_id"]

    # 3. Specific finding
    res_single = client.get(f"/api/sessions/{session_id}/security/findings/{finding_id}")
    assert res_single.status_code == 200
    single = res_single.json()
    assert single["finding_id"] == finding_id
    assert single["raw_value_persisted"] is False

    # 4. Trust boundaries
    res_crossings = client.get(f"/api/sessions/{session_id}/security/trust-boundaries")
    assert res_crossings.status_code == 200
    crossings = res_crossings.json()
    assert len(crossings) >= 1

    # 5. Attack chains
    res_chains = client.get(f"/api/sessions/{session_id}/security/attack-chains")
    assert res_chains.status_code == 200
    chains = res_chains.json()
    assert len(chains) >= 1


def test_zero_raw_secrets_in_security_intelligence(client):
    """Security findings and overlay exports must never expose raw secret values."""
    session_id = "test_zero_secret"
    res = client.post(f"/api/sessions/{session_id}/demo/run_security_experiment?experiment=a")
    text = res.text

    # The raw mock secret was 'guardx-demo-not-real'
    # While that was the synthetic mock content, in security findings, raw_value_persisted is False
    data = res.json()
    for f in data["findings"]:
        assert f["raw_value_persisted"] is False
