"""Boundary Entity Extractor for GuardX Milestone 3.

Guarantees:
- Reuses and adapts AgentGuard SecretDetector and PIIDetector when available.
- Boundary extraction: USER_INPUT, FILE_READ, TOOL_RESULT, LLM_RESPONSE, NETWORK_RESPONSE.
- Parses .env configuration files into sensitive (CREDENTIAL/SECRET) and non-sensitive (PUBLIC) entities.
- Recognizes synthetic tokens ({{SECRET_...}}, [MASKED_...], <GUARDX_SECRET_...>).
- Generates keyed HMAC-SHA256 fingerprints using session key.
- INVARIANT INV-001: Zero raw sensitive values persisted in returned entities.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from guardx.core.crypto import compute_keyed_fingerprint
from guardx.core.enums import ProvenanceQuality
from guardx.core.sanitizer import SensitiveContentScanner
from guardx.lineage.models import (
    DataClassification,
    DataEntity,
    DataRepresentation,
)

# Attempt to import AgentGuard detectors
try:
    from agentguard.detectors.secret_detector import SecretDetector as AgentGuardSecretDetector
    from agentguard.detectors.pii_detector import PIIDetector as AgentGuardPIIDetector
    HAS_AGENTGUARD_DETECTORS = True
except ImportError:
    HAS_AGENTGUARD_DETECTORS = False


# Regex for synthetic tokens
SYNTHETIC_TOKEN_PATTERN = re.compile(
    r"(\{\{SECRET_[A-Za-z0-9_\-]+\}\}|\[MASKED_[A-Za-z0-9_\-]+\]|<GUARDX_SECRET_[A-Za-z0-9_\-]+>)"
)

# Regex for .env lines: KEY=VALUE
ENV_LINE_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$",
    re.MULTILINE
)


@dataclass
class DiscoveredBoundaryItem:
    """Transient in-memory structure representing a discovered boundary entity."""

    label: str
    classification: str
    representation: str
    origin_resource_id: str
    discovered_event_id: str
    fingerprint_hmac: str
    synthetic_token: Optional[str]
    confidence: float
    metadata: Dict[str, Any]
    # Transient plaintext used exclusively in-memory for immediate HMAC/tokenization.
    # Discarded immediately, never placed on DataEntity.
    transient_plaintext: Optional[str] = None


class BoundaryEntityExtractor:
    """Extracts DataEntities at observable boundaries without persisting raw secrets."""

    def __init__(self, session_key: str):
        self.session_key = session_key
        self.guardx_scanner = SensitiveContentScanner()
        if HAS_AGENTGUARD_DETECTORS:
            self.ag_secret_detector = AgentGuardSecretDetector()
            self.ag_pii_detector = AgentGuardPIIDetector()
        else:
            self.ag_secret_detector = None
            self.ag_pii_detector = None

    def extract_from_text(
        self,
        text: str,
        resource_id: str,
        event_id: str,
        session_id: str,
        sanitized_entities: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Tuple[DataEntity, Optional[str]]]:
        """Extracts identifiable entities from boundary text.
        
        Returns:
            List of (DataEntity, transient_plaintext) pairs.
            Caller must use transient_plaintext only for in-memory matching and never persist it.
        """
        if not text:
            return []

        results: List[Tuple[DataEntity, Optional[str]]] = []
        seen_fingerprints = set()

        def _resolve_fp(raw_or_masked: str) -> str:
            if sanitized_entities:
                for s in sanitized_entities:
                    fp = s.get("fingerprint_hmac", "")
                    if fp and fp[:8] in raw_or_masked:
                        return fp
            return compute_keyed_fingerprint(raw_or_masked, self.session_key)

        # 1. If resource is a .env file or text looks like an env file, parse KEY=VAL pairs
        is_env_file = resource_id.endswith(".env") or resource_id.endswith(".env.example")
        if is_env_file or ("=" in text and "\n" in text):
            for match in ENV_LINE_PATTERN.finditer(text):
                key = match.group(1).strip()
                val = match.group(2).strip().strip("'\"")

                # Skip comment lines
                if key.startswith("#"):
                    continue

                is_sensitive_key = bool(
                    re.search(r"(?:KEY|SECRET|PASSWORD|PASS|TOKEN|AUTH|CREDENTIAL|PRIVATE)", key, re.IGNORECASE)
                )

                if is_sensitive_key:
                    classification = DataClassification.CREDENTIAL.value
                else:
                    classification = DataClassification.PUBLIC.value

                hmac_fp = _resolve_fp(val)
                if hmac_fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(hmac_fp)

                entity_id = f"entity_{key.lower()}_{uuid.uuid4().hex[:8]}"
                entity = DataEntity(
                    entity_id=entity_id,
                    session_id=session_id,
                    label=key,
                    classification=classification,
                    representation=DataRepresentation.RAW.value,
                    origin_resource_id=resource_id,
                    fingerprint_hmac=hmac_fp,
                    synthetic_token=None,
                    discovered_event_id=event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    metadata={"source": "env_parser", "key_name": key},
                )
                results.append((entity, val))

        # 2. AgentGuard detectors if available
        if self.ag_secret_detector:
            try:
                findings = self.ag_secret_detector.scan(text, source_context=resource_id)
                for f in findings:
                    raw_val = getattr(f, "raw_value", "")
                    if raw_val:
                        hmac_fp = compute_keyed_fingerprint(raw_val, self.session_key)
                        if hmac_fp not in seen_fingerprints:
                            seen_fingerprints.add(hmac_fp)
                            category_str = str(getattr(f, "category", "SECRET")).split(".")[-1]
                            entity_id = f"entity_secret_{uuid.uuid4().hex[:8]}"
                            entity = DataEntity(
                                entity_id=entity_id,
                                session_id=session_id,
                                label=f"SECRET_{category_str}",
                                classification=DataClassification.SECRET.value,
                                representation=DataRepresentation.RAW.value,
                                origin_resource_id=resource_id,
                                fingerprint_hmac=hmac_fp,
                                synthetic_token=None,
                                discovered_event_id=event_id,
                                provenance_quality=ProvenanceQuality.OBSERVED,
                                confidence=1.0,
                                metadata={"detector": "agentguard", "category": category_str},
                            )
                            results.append((entity, raw_val))
            except Exception:
                pass

        # 3. GuardX SensitiveContentScanner
        gx_matches = self.guardx_scanner.scan_string(text)
        for category, raw_match, start, end in gx_matches:
            hmac_fp = compute_keyed_fingerprint(raw_match, self.session_key)
            if hmac_fp not in seen_fingerprints:
                seen_fingerprints.add(hmac_fp)
                classification = (
                    DataClassification.PII.value
                    if category in ("EMAIL", "PHONE")
                    else DataClassification.CREDENTIAL.value
                )
                entity_id = f"entity_{category.lower()}_{uuid.uuid4().hex[:8]}"
                entity = DataEntity(
                    entity_id=entity_id,
                    session_id=session_id,
                    label=category,
                    classification=classification,
                    representation=DataRepresentation.RAW.value,
                    origin_resource_id=resource_id,
                    fingerprint_hmac=hmac_fp,
                    synthetic_token=None,
                    discovered_event_id=event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    metadata={"detector": "guardx_scanner", "category": category},
                )
                results.append((entity, raw_match))

        # 4. Detect synthetic tokens already present in text
        for token_match in SYNTHETIC_TOKEN_PATTERN.finditer(text):
            token_str = token_match.group(1)
            token_fp = compute_keyed_fingerprint(token_str, self.session_key)
            if token_fp not in seen_fingerprints:
                seen_fingerprints.add(token_fp)
                entity_id = f"entity_token_{uuid.uuid4().hex[:8]}"
                entity = DataEntity(
                    entity_id=entity_id,
                    session_id=session_id,
                    label=f"TOKEN_{token_str[:12]}",
                    classification=DataClassification.CREDENTIAL_REFERENCE.value,
                    representation=DataRepresentation.TOKENIZED.value,
                    origin_resource_id=resource_id,
                    fingerprint_hmac=token_fp,
                    synthetic_token=token_str,
                    discovered_event_id=event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    metadata={"token_string": token_str},
                )
                results.append((entity, None))

        return results
