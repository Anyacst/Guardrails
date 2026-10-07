"""Deterministic Security Rules for GuardX Milestone 4.

Defines structured risk rules that map evidence-backed conditions
(classification, representation, destination trust, transformation semantics)
to deterministic security findings.

Key Rule Invariants:
- Raw credential to UNTRUSTED_EXTERNAL -> CRITICAL (Credential Exfiltration)
- Raw credential to EXTERNAL_LLM -> HIGH (Credential Disclosure to External Model)
- Encoded credential to External -> HIGH (Base64/URL encoding is preserving, NOT sanitizing)
- Tokenized credential to EXTERNAL_LLM -> NONE/LOW (Opaque reference, raw secret removed)
- PII to UNTRUSTED_EXTERNAL -> HIGH
- PII to EXTERNAL_LLM -> MEDIUM
- PUBLIC data to any destination -> NONE
- NO PROVEN FLOW -> NO FINDING
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from guardx.lineage.models import DataClassification, DataRepresentation
from guardx.risk.models import FindingCategory, SecurityFinding, Severity
from guardx.trust.models import TrustLevel


@dataclass(frozen=True)
class RiskRule:
    """Configurable risk rule definition separating match conditions from risk result."""
    rule_id: str
    title: str
    category: FindingCategory
    severity: Severity
    description_template: str
    allowed_classifications: Set[str]
    allowed_representations: Set[str]
    allowed_destination_trusts: Set[str]
    requires_proven_flow: bool = True
    min_confidence: float = 0.5


# Default Deterministic Security Ruleset
DEFAULT_SECURITY_RULES: List[RiskRule] = [
    # Rule 1 — Raw Credential to Untrusted External
    RiskRule(
        rule_id="RULE_CREDENTIAL_RAW_TO_UNTRUSTED",
        title="Critical Credential Exfiltration to Untrusted External",
        category=FindingCategory.CREDENTIAL_EXFILTRATION,
        severity=Severity.CRITICAL,
        description_template="Proven RAW credential '{label}' was transmitted to untrusted external destination '{destination}'.",
        allowed_classifications={DataClassification.CREDENTIAL.value, DataClassification.SECRET.value},
        allowed_representations={DataRepresentation.RAW.value},
        allowed_destination_trusts={TrustLevel.UNTRUSTED_EXTERNAL.value, TrustLevel.UNKNOWN.value},
        requires_proven_flow=True,
    ),

    # Rule 2 — Raw Credential to External LLM
    RiskRule(
        rule_id="RULE_CREDENTIAL_RAW_TO_EXTERNAL_LLM",
        title="High Severity Credential Disclosure to External Model",
        category=FindingCategory.CREDENTIAL_DISCLOSURE,
        severity=Severity.HIGH,
        description_template="Proven RAW credential '{label}' was disclosed in prompt to external model provider '{destination}'.",
        allowed_classifications={DataClassification.CREDENTIAL.value, DataClassification.SECRET.value},
        allowed_representations={DataRepresentation.RAW.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value},
        requires_proven_flow=True,
    ),

    # Rule 3 — Encoded Credential to External Destination (Base64 / URL Encoding)
    RiskRule(
        rule_id="RULE_CREDENTIAL_ENCODED_TO_EXTERNAL",
        title="Encoded Credential Disclosure to External Destination",
        category=FindingCategory.ENCODED_SECRET_DISCLOSURE,
        severity=Severity.HIGH,
        description_template="Credential '{label}' was encoded (preserving transformation) and transmitted to external boundary '{destination}'. Encoding does not sanitize secrets.",
        allowed_classifications={DataClassification.CREDENTIAL.value, DataClassification.SECRET.value},
        allowed_representations={DataRepresentation.ENCODED.value, DataRepresentation.DERIVED.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value, TrustLevel.UNTRUSTED_EXTERNAL.value, TrustLevel.UNKNOWN.value},
        requires_proven_flow=True,
    ),

    # Rule 4 — Tokenized Credential Reference to External LLM (Protected Reference)
    RiskRule(
        rule_id="RULE_CREDENTIAL_TOKENIZED_TO_EXTERNAL_LLM",
        title="Sanitized Credential Reference Delivered to External LLM",
        category=FindingCategory.INFORMATIONAL,
        severity=Severity.LOW,  # Or NONE
        description_template="Safe synthetic token reference for '{label}' was delivered to external LLM. The raw credential was protected.",
        allowed_classifications={DataClassification.CREDENTIAL_REFERENCE.value, DataClassification.CREDENTIAL.value, DataClassification.SECRET.value},
        allowed_representations={DataRepresentation.TOKENIZED.value, DataRepresentation.REDACTED.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value, TrustLevel.TRUSTED_EXTERNAL.value},
        requires_proven_flow=True,
    ),

    # Rule 5 — PII to Untrusted External
    RiskRule(
        rule_id="RULE_PII_TO_UNTRUSTED",
        title="Personally Identifiable Information (PII) Exfiltration",
        category=FindingCategory.PII_EXFILTRATION,
        severity=Severity.HIGH,
        description_template="Personally Identifiable Information '{label}' was transmitted to untrusted external destination '{destination}'.",
        allowed_classifications={DataClassification.PII.value},
        allowed_representations={DataRepresentation.RAW.value, DataRepresentation.ENCODED.value},
        allowed_destination_trusts={TrustLevel.UNTRUSTED_EXTERNAL.value, TrustLevel.UNKNOWN.value},
        requires_proven_flow=True,
    ),

    # Rule 6 — PII to External LLM
    RiskRule(
        rule_id="RULE_PII_TO_EXTERNAL_LLM",
        title="Personally Identifiable Information (PII) Disclosed to External Model",
        category=FindingCategory.PII_DISCLOSURE,
        severity=Severity.MEDIUM,
        description_template="PII entity '{label}' was included in request to external model provider '{destination}'.",
        allowed_classifications={DataClassification.PII.value},
        allowed_representations={DataRepresentation.RAW.value, DataRepresentation.ENCODED.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value},
        requires_proven_flow=True,
    ),
]
