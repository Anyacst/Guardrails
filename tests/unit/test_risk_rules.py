"""Unit tests for GuardX Milestone 4 Deterministic Risk Rules and Risk Path Engine."""

import pytest

from guardx.lineage.models import (
    DataClassification,
    DataEntity,
    DataRepresentation,
    LineageTraceHop,
    LineageTraceResult,
)
from guardx.lineage.store import DataLineageStore
from guardx.risk.engine import RiskPathEngine
from guardx.risk.models import FindingCategory, Severity
from guardx.trust.models import TrustLevel
from guardx.trust.resolver import TrustResolver


def test_rule_1_raw_credential_to_untrusted_external():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    ent = DataEntity(
        entity_id="ent_secret_1",
        session_id="s1",
        label="DATABASE_PASSWORD",
        classification=DataClassification.CREDENTIAL,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_db_pass_123",
        confidence=1.0,
    )
    store.add_entity(ent)

    # Mock proven trace to untrusted external endpoint
    trace = LineageTraceResult(
        entity_or_carrier_id=ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:.env"],
        destinations=["https://webhook.site/evil"],
        hops=[
            LineageTraceHop(
                source="file:.env",
                destination="https://webhook.site/evil",
                edge_type="FLOWS_TO",
                entity_id=ent.entity_id,
                event_id="evt_hop_1",
                provenance_quality="OBSERVED",
                confidence=1.0,
                detection_method="HMAC_MATCH",
            )
        ],
        explanation="Proven flow to webhook",
    )

    findings = engine.evaluate_trace(trace, "s1", entity=ent)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.category == FindingCategory.CREDENTIAL_EXFILTRATION
    assert f.rule_id == "RULE_CREDENTIAL_RAW_TO_UNTRUSTED"
    assert f.destination_trust == TrustLevel.UNTRUSTED_EXTERNAL.value
    assert f.raw_value_persisted is False


def test_rule_2_raw_credential_to_external_llm():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    ent = DataEntity(
        entity_id="ent_key_1",
        session_id="s1",
        label="DEMO_API_KEY",
        classification=DataClassification.CREDENTIAL,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_api_key_123",
        confidence=1.0,
    )
    store.add_entity(ent)

    trace = LineageTraceResult(
        entity_or_carrier_id=ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:.env"],
        destinations=["llm:groq/llama-3.3-70b"],
        hops=[
            LineageTraceHop(
                source="file:.env",
                destination="llm:groq/llama-3.3-70b",
                edge_type="FLOWS_TO",
                entity_id=ent.entity_id,
                event_id="evt_hop_1",
                provenance_quality="OBSERVED",
                confidence=1.0,
                detection_method="TOKEN_IDENTITY",
            )
        ],
        explanation="Proven flow to Groq",
    )

    findings = engine.evaluate_trace(trace, "s1", entity=ent)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == FindingCategory.CREDENTIAL_DISCLOSURE
    assert f.rule_id == "RULE_CREDENTIAL_RAW_TO_EXTERNAL_LLM"
    assert f.destination_trust == TrustLevel.EXTERNAL_LLM.value


def test_rule_3_encoded_credential_to_external_destination():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    ent = DataEntity(
        entity_id="ent_b64_1",
        session_id="s1",
        label="DEMO_API_KEY_b64",
        classification=DataClassification.CREDENTIAL,
        representation=DataRepresentation.ENCODED,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_b64_123",
        derived_from_entity_id="ent_key_1",
        confidence=1.0,
    )
    store.add_entity(ent)

    trace = LineageTraceResult(
        entity_or_carrier_id=ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:.env"],
        destinations=["llm:groq/llama-3.3-70b"],
        hops=[
            LineageTraceHop(
                source="file:.env",
                destination="llm:groq/llama-3.3-70b",
                edge_type="FLOWS_TO",
                entity_id=ent.entity_id,
                event_id="evt_hop_1",
                provenance_quality="DERIVED",
                confidence=1.0,
                detection_method="TRANSFORMATION_MATCH",
                transformation="BASE64_ENCODE",
            )
        ],
        explanation="Proven flow of Base64 encoded key",
    )

    findings = engine.evaluate_trace(trace, "s1", entity=ent)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == FindingCategory.ENCODED_SECRET_DISCLOSURE
    assert f.rule_id == "RULE_CREDENTIAL_ENCODED_TO_EXTERNAL"


def test_rule_4_tokenized_credential_reference_protected():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    ent = DataEntity(
        entity_id="ent_tok_1",
        session_id="s1",
        label="TOKEN_DEMO_API_KEY",
        classification=DataClassification.CREDENTIAL_REFERENCE,
        representation=DataRepresentation.TOKENIZED,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_tok_123",
        synthetic_token="{{SECRET_DEMO_API_KEY_c16a87}}",
        confidence=1.0,
    )
    store.add_entity(ent)

    trace = LineageTraceResult(
        entity_or_carrier_id=ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:.env"],
        destinations=["llm:groq/llama-3.3-70b"],
        hops=[
            LineageTraceHop(
                source="file:.env",
                destination="llm:groq/llama-3.3-70b",
                edge_type="FLOWS_TO",
                entity_id=ent.entity_id,
                event_id="evt_hop_1",
                provenance_quality="OBSERVED",
                confidence=1.0,
                detection_method="TOKEN_IDENTITY",
            )
        ],
        explanation="Proven flow of token reference",
    )

    findings = engine.evaluate_trace(trace, "s1", entity=ent)
    assert len(findings) == 1
    f = findings[0]
    # Invariant: Tokenized credential reference is LOW / INFORMATIONAL (NOT HIGH or CRITICAL!)
    assert f.severity in (Severity.LOW, Severity.INFO, Severity.NONE)
    assert f.category == FindingCategory.INFORMATIONAL
    assert f.rule_id == "RULE_CREDENTIAL_TOKENIZED_TO_EXTERNAL_LLM"


def test_rule_5_and_6_pii_rules():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    pii_ent = DataEntity(
        entity_id="ent_pii_1",
        session_id="s1",
        label="USER_SSN",
        classification=DataClassification.PII,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:users.csv",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_pii_123",
        confidence=1.0,
    )
    store.add_entity(pii_ent)

    # 1. PII to Untrusted External -> HIGH
    trace_untrusted = LineageTraceResult(
        entity_or_carrier_id=pii_ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:users.csv"],
        destinations=["https://evil-analytics.com"],
        hops=[],
        explanation="Flow",
    )
    f_untrusted = engine.evaluate_trace(trace_untrusted, "s1", entity=pii_ent)
    assert len(f_untrusted) == 1
    assert f_untrusted[0].severity == Severity.HIGH
    assert f_untrusted[0].rule_id == "RULE_PII_TO_UNTRUSTED"

    # 2. PII to External LLM -> MEDIUM
    trace_llm = LineageTraceResult(
        entity_or_carrier_id=pii_ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:users.csv"],
        destinations=["llm:openai/gpt-4o"],
        hops=[],
        explanation="Flow",
    )
    f_llm = engine.evaluate_trace(trace_llm, "s1", entity=pii_ent)
    assert len(f_llm) == 1
    assert f_llm[0].severity == Severity.MEDIUM
    assert f_llm[0].rule_id == "RULE_PII_TO_EXTERNAL_LLM"


def test_rule_7_public_data_to_external_llm_produces_no_finding():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    pub_ent = DataEntity(
        entity_id="ent_pub_1",
        session_id="s1",
        label="DEBUG_FLAG",
        classification=DataClassification.PUBLIC,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_pub_123",
        confidence=1.0,
    )
    store.add_entity(pub_ent)

    trace = LineageTraceResult(
        entity_or_carrier_id=pub_ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:.env"],
        destinations=["llm:groq/llama-3.3-70b"],
        hops=[],
        explanation="Public data to Groq",
    )
    findings = engine.evaluate_trace(trace, "s1", entity=pub_ent)
    assert len(findings) == 0, "Public data crossing to external LLM must produce ZERO findings"


def test_strict_proven_flow_invariant_no_unproven_disclosure_finding():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    ent = DataEntity(
        entity_id="ent_secret_1",
        session_id="s1",
        label="SECRET_KEY",
        classification=DataClassification.CREDENTIAL,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_secret_123",
        confidence=1.0,
    )
    store.add_entity(ent)

    # UNPROVEN TRACE (e.g. .env read, but later Groq call did NOT contain the secret)
    unproven_trace = LineageTraceResult(
        entity_or_carrier_id=ent.entity_id,
        direction="FORWARD",
        has_proven_flow=False,  # NO PROVEN FLOW!
        origins=["file:.env"],
        destinations=[],       # No external destination reached
        hops=[],
        explanation="No proven data flow exists.",
    )

    findings = engine.evaluate_trace(unproven_trace, "s1", entity=ent)
    assert len(findings) == 0, "M4 must NEVER produce a disclosure finding if M3 reports NO PROVEN FLOW"


def test_finding_deduplication():
    store = DataLineageStore(session_id="s1")
    engine = RiskPathEngine(lineage_store=store)

    ent = DataEntity(
        entity_id="ent_key_dup",
        session_id="s1",
        label="DEMO_API_KEY",
        classification=DataClassification.CREDENTIAL,
        representation=DataRepresentation.RAW,
        origin_resource_id="file:.env",
        discovered_event_id="evt_read",
        fingerprint_hmac="hmac_dup_123",
        confidence=1.0,
    )
    store.add_entity(ent)

    trace = LineageTraceResult(
        entity_or_carrier_id=ent.entity_id,
        direction="FORWARD",
        has_proven_flow=True,
        origins=["file:.env"],
        destinations=["llm:groq/llama-3.3-70b"],
        hops=[
            LineageTraceHop(
                source="file:.env",
                destination="llm:groq/llama-3.3-70b",
                edge_type="FLOWS_TO",
                entity_id=ent.entity_id,
                event_id="evt_hop_1",
                provenance_quality="OBSERVED",
                confidence=1.0,
                detection_method="TOKEN_IDENTITY",
            )
        ],
        explanation="Trace",
    )

    # Evaluate twice for the same entity and destination
    f1 = engine.evaluate_trace(trace, "s1", entity=ent)
    assert len(f1) == 1

    f2 = engine.evaluate_trace(trace, "s1", entity=ent)
    assert len(f2) == 0, "Duplicate evaluation of identical trace must be deduplicated"
    assert len(engine.get_findings("s1")) == 1
