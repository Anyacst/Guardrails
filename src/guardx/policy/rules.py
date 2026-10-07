"""Default Policy Rules for GuardX Milestone 5.

Implements policies P1 through P8 as specified in the Milestone 5 roadmap:
- P1: Public Data -> External LLM -> ALLOW
- P2: Raw Credential -> External LLM -> MODIFY (TOKENIZE)
- P3: Tokenized Credential -> External LLM -> ALLOW
- P4: Raw Credential -> Untrusted External -> BLOCK
- P5: Encoded Credential -> External (LLM or untrusted) -> BLOCK
- P6: PII -> External LLM -> MODIFY (TOKENIZE)
- P7: PII -> Untrusted External -> BLOCK
- P8: High-Confidence Intent Violation -> HUMAN_REVIEW
"""

from typing import List
from guardx.lineage.models import DataClassification, DataRepresentation
from guardx.policy.models import DecisionType, PolicyRule
from guardx.trust.models import TrustLevel


DEFAULT_POLICY_RULES: List[PolicyRule] = [
    # P1: Public Data -> External LLM -> ALLOW
    PolicyRule(
        policy_id="P1_PUBLIC_DATA_TO_EXTERNAL_LLM",
        name="Allow Public Data to External LLM",
        description="Public configuration and code may be transmitted to external LLMs without modification.",
        decision=DecisionType.ALLOW,
        priority=10,
        reason="Public information does not require sanitization or protection.",
        allowed_classifications={DataClassification.PUBLIC.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value, TrustLevel.TRUSTED_EXTERNAL.value, TrustLevel.LOCAL.value},
    ),

    # P2: Raw Credential -> External LLM -> MODIFY (TOKENIZE)
    PolicyRule(
        policy_id="P2_RAW_CREDENTIAL_TO_EXTERNAL_LLM",
        name="Modify Raw Credential to External LLM (Tokenize)",
        description="Raw credentials destined for external LLMs must be replaced with ephemeral vault tokens before transmission.",
        decision=DecisionType.MODIFY,
        priority=80,
        modifier="TOKENIZE",
        reason="Raw credential exposure to external LLMs violates zero-leak policy; must tokenize.",
        allowed_classifications={DataClassification.CREDENTIAL.value, DataClassification.SECRET.value},
        allowed_representations={DataRepresentation.RAW.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value},
    ),

    # P3: Tokenized Credential -> External LLM -> ALLOW
    PolicyRule(
        policy_id="P3_TOKENIZED_CREDENTIAL_TO_EXTERNAL_LLM",
        name="Allow Tokenized Credential Reference to External LLM",
        description="Opaque synthetic token references may be delivered to external LLMs because the raw secret is protected.",
        decision=DecisionType.ALLOW,
        priority=20,
        reason="Credential reference is protected by ephemeral vault token.",
        allowed_classifications={
            DataClassification.CREDENTIAL_REFERENCE.value,
            DataClassification.CREDENTIAL.value,
            DataClassification.SECRET.value,
        },
        allowed_representations={DataRepresentation.TOKENIZED.value, DataRepresentation.REDACTED.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value, TrustLevel.TRUSTED_EXTERNAL.value},
    ),

    # P4: Raw Credential -> Untrusted External -> BLOCK
    PolicyRule(
        policy_id="P4_RAW_CREDENTIAL_TO_UNTRUSTED",
        name="Block Raw Credential to Untrusted External",
        description="Direct egress of raw credentials to untrusted external endpoints is strictly forbidden.",
        decision=DecisionType.BLOCK,
        priority=100,
        reason="Critical threat: Raw credential exfiltration to untrusted destination.",
        allowed_classifications={DataClassification.CREDENTIAL.value, DataClassification.SECRET.value},
        allowed_representations={DataRepresentation.RAW.value},
        allowed_destination_trusts={TrustLevel.UNTRUSTED_EXTERNAL.value, TrustLevel.UNKNOWN.value},
    ),

    # P5: Encoded Credential -> External (LLM or untrusted) -> BLOCK
    PolicyRule(
        policy_id="P5_ENCODED_CREDENTIAL_TO_EXTERNAL",
        name="Block Encoded Credential to External Destination",
        description="Preserving encodings (Base64, URL-encode, hex) do not sanitize credentials; egress is blocked.",
        decision=DecisionType.BLOCK,
        priority=95,
        reason="Encoded credentials maintain secret identity without cryptographic protection; blocking exfiltration.",
        allowed_classifications={DataClassification.CREDENTIAL.value, DataClassification.SECRET.value},
        allowed_representations={DataRepresentation.ENCODED.value, DataRepresentation.DERIVED.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value, TrustLevel.UNTRUSTED_EXTERNAL.value, TrustLevel.UNKNOWN.value},
    ),

    # P6: PII -> External LLM -> MODIFY (TOKENIZE)
    PolicyRule(
        policy_id="P6_PII_TO_EXTERNAL_LLM",
        name="Modify PII to External LLM",
        description="Personally identifiable information must be masked or tokenized before transmission to external model.",
        decision=DecisionType.MODIFY,
        priority=70,
        modifier="TOKENIZE",
        reason="PII disclosure to external LLMs must be sanitized.",
        allowed_classifications={DataClassification.PII.value},
        allowed_representations={DataRepresentation.RAW.value, DataRepresentation.ENCODED.value},
        allowed_destination_trusts={TrustLevel.EXTERNAL_LLM.value},
    ),

    # P7: PII -> Untrusted External -> BLOCK
    PolicyRule(
        policy_id="P7_PII_TO_UNTRUSTED",
        name="Block PII to Untrusted External",
        description="Transmission of personally identifiable information to untrusted endpoints is blocked.",
        decision=DecisionType.BLOCK,
        priority=90,
        reason="High threat: Unauthorized PII exfiltration to untrusted boundary.",
        allowed_classifications={DataClassification.PII.value},
        allowed_representations={DataRepresentation.RAW.value, DataRepresentation.ENCODED.value},
        allowed_destination_trusts={TrustLevel.UNTRUSTED_EXTERNAL.value, TrustLevel.UNKNOWN.value},
    ),

    # P8: High-Confidence Intent Violation -> HUMAN_REVIEW
    PolicyRule(
        policy_id="P8_INTENT_VIOLATION_REVIEW",
        name="Require Human Review on Intent Conformance Violation",
        description="When runtime operations deviate from declared task parameters, pause execution for human verification.",
        decision=DecisionType.HUMAN_REVIEW,
        priority=85,
        requires_intent_violation=True,
        reason="Operational intent contract mismatch detected; human operator review required.",
    ),
]
