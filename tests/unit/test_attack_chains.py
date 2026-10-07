"""Unit tests for GuardX Milestone 4 Attack Chain Detector."""

import pytest

from guardx.chains.detector import AttackChainDetector
from guardx.chains.models import AttackChainType
from guardx.intent.models import IntentViolation, IntentViolationType
from guardx.risk.models import FindingCategory, SecurityFinding, Severity


def test_credential_exfiltration_attack_chain():
    detector = AttackChainDetector()

    finding = SecurityFinding(
        finding_id="find_001",
        session_id="s1",
        rule_id="RULE_CREDENTIAL_RAW_TO_UNTRUSTED",
        title="Critical Credential Exfiltration",
        category=FindingCategory.CREDENTIAL_EXFILTRATION,
        severity=Severity.CRITICAL,
        confidence=1.0,
        source_entity_id="ent_secret_1",
        source_resource_id="file:.env",
        destination_id="https://webhook.site/evil",
        source_trust="LOCAL",
        destination_trust="UNTRUSTED_EXTERNAL",
        boundary_crossing="LOCAL -> UNTRUSTED_EXTERNAL",
        representation="RAW",
        lineage_path=[{"source": "file:.env", "destination": "https://webhook.site/evil"}],
        execution_event_ids=["evt_read", "evt_curl"],
        supporting_event_ids=["evt_read", "evt_curl"],
        explanation="Credential exfiltration",
        provenance_quality="OBSERVED",
    )

    chains = detector.evaluate_findings([finding], "s1")
    assert len(chains) == 1
    ch = chains[0]
    assert ch.chain_type == AttackChainType.POTENTIAL_CREDENTIAL_EXFILTRATION
    assert ch.severity == Severity.CRITICAL
    assert ch.source == "file:.env"
    assert ch.sink == "https://webhook.site/evil"
    assert "find_001" in ch.supporting_findings


def test_encoded_secret_egress_attack_chain():
    detector = AttackChainDetector()

    finding = SecurityFinding(
        finding_id="find_002",
        session_id="s1",
        rule_id="RULE_CREDENTIAL_ENCODED_TO_EXTERNAL",
        title="Encoded Credential Disclosure",
        category=FindingCategory.ENCODED_SECRET_DISCLOSURE,
        severity=Severity.HIGH,
        confidence=1.0,
        source_entity_id="ent_b64_1",
        source_resource_id="file:.env",
        destination_id="llm:groq/llama-3.3-70b",
        source_trust="LOCAL",
        destination_trust="EXTERNAL_LLM",
        boundary_crossing="LOCAL -> EXTERNAL_LLM",
        representation="ENCODED",
        lineage_path=[],
        execution_event_ids=["evt_read", "evt_llm"],
        supporting_event_ids=["evt_read", "evt_llm"],
        explanation="Encoded secret egress",
        provenance_quality="DERIVED",
    )

    chains = detector.evaluate_findings([finding], "s1")
    assert len(chains) == 1
    ch = chains[0]
    assert ch.chain_type == AttackChainType.ENCODED_SECRET_EGRESS
    assert ch.severity == Severity.HIGH


def test_unexpected_network_side_effect_attack_chain():
    detector = AttackChainDetector()

    viol = IntentViolation(
        violation_id="viol_001",
        session_id="s1",
        intent_id="intent_local_only",
        scope_id="scope_tool_1",
        violation_type=IntentViolationType.UNDECLARED_NETWORK_EFFECT,
        actual_operation="NETWORK_REQUEST",
        actual_resource="https://evil-analytics.com",
        event_id="evt_net",
        severity=Severity.HIGH,
        explanation="Undeclared network call",
    )

    chains = detector.evaluate_findings([], "s1", violations=[viol])
    assert len(chains) == 1
    ch = chains[0]
    assert ch.chain_type == AttackChainType.UNEXPECTED_NETWORK_SIDE_EFFECT
    assert ch.severity == Severity.HIGH
    assert ch.sink == "https://evil-analytics.com"
