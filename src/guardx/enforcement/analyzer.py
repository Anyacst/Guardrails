"""ProspectiveAnalyzer for GuardX Milestone 5.

Performs prospective analysis of proposed actions before execution occurs.
Reuses M3/M4 extractors, entity store, trust resolver, and intent contracts.
"""

from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from guardx.core.crypto import compute_keyed_fingerprint
from guardx.core.enums import TransformationSecuritySemantics
from guardx.enforcement.models import ActionType, ProspectiveAction
from guardx.intent.models import IntentContract, IntentViolationType
from guardx.lineage.extractors import BoundaryEntityExtractor, SYNTHETIC_TOKEN_PATTERN
from guardx.lineage.models import (
    DataClassification,
    DataEntity,
    DataRepresentation,
)
from guardx.lineage.store import DataLineageStore
from guardx.trust.models import TrustLevel, TrustTier
from guardx.trust.resolver import TrustResolver


@dataclass(frozen=True)
class ProspectiveAnalysisResult:
    """Outcome of prospective inspection of a proposed action."""
    action_id: str
    session_id: str
    detected_entities: List[DataEntity]
    primary_classification: str
    primary_representation: str
    destination: str
    destination_trust: TrustLevel
    transformation_semantics: Optional[str] = None
    has_intent_violation: bool = False
    intent_violation_type: Optional[str] = None
    intent_violation_reason: Optional[str] = None
    risk_finding_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ProspectiveAnalyzer:
    """Analyzes a proposed action before execution by inspecting content and context."""

    def __init__(
        self,
        session_key: str = "guardx_session_key",
        trust_resolver: Optional[TrustResolver] = None,
        lineage_store: Optional[DataLineageStore] = None,
        intent_engine: Optional[Any] = None,
    ):
        self.session_key = session_key
        self.trust_resolver = trust_resolver or TrustResolver()
        self.lineage_store = lineage_store
        self.intent_engine = intent_engine
        self.extractor = BoundaryEntityExtractor(session_key=self.session_key)

    def analyze(
        self,
        action: ProspectiveAction,
        raw_content: Any = None,
        intent_contracts: Optional[List[IntentContract]] = None,
    ) -> ProspectiveAnalysisResult:
        """Deterministically evaluates proposed action parameters and content."""
        # 1. Resolve destination trust
        dest_trust = self.trust_resolver.resolve(action.destination)
        if dest_trust == TrustLevel.UNKNOWN and action.destination_trust:
            dest_trust = action.destination_trust

        # 2. Extract entities from transient raw_content and safe_payload
        entities: List[DataEntity] = []
        transient_raw_values: Dict[str, str] = {}  # entity_id -> raw_val (in-memory only)

        raw_text = self._to_text(raw_content) if raw_content is not None else self._to_text(action.safe_payload)

        # Use BoundaryEntityExtractor for credentials and PII
        if raw_text:
            extracted_pairs: List[Tuple[DataEntity, Optional[str]]] = self.extractor.extract_from_text(
                text=raw_text,
                resource_id=f"prospective:{action.action_id}",
                event_id=action.action_id,
                session_id=action.session_id,
            )
            for entity, transient_plaintext in extracted_pairs:
                entities.append(entity)
                if transient_plaintext:
                    transient_raw_values[entity.entity_id] = transient_plaintext
                    # Attach raw_value to metadata in-memory for modifier use (never persisted)
                    entity.metadata["raw_value"] = transient_plaintext

        # Check existing lineage store for known session entities via HMAC
        if self.lineage_store:
            store_entities = self.lineage_store.get_entities_for_session(action.session_id)
            for se in store_entities:
                if se.fingerprint_hmac and any(se.fingerprint_hmac == e.fingerprint_hmac for e in entities):
                    continue
                # Check if entity's known token is present in the raw text
                if se.synthetic_token and raw_text and se.synthetic_token in raw_text:
                    entities.append(se)

        # Check for encoded credentials (base64, url encoding)
        transformation_semantics: Optional[str] = None
        for ent in entities:
            if ent.representation == DataRepresentation.ENCODED.value:
                transformation_semantics = TransformationSecuritySemantics.PRESERVING.value
                break
            # Check if any encoded pattern is detected in raw_text
            raw_val = transient_raw_values.get(ent.entity_id) or ent.metadata.get("raw_value")
            if raw_val and self._has_encoded_form(raw_val, raw_text):
                transformation_semantics = TransformationSecuritySemantics.PRESERVING.value

        # 3. Determine primary classification and representation
        primary_classification = DataClassification.PUBLIC.value
        primary_representation = DataRepresentation.RAW.value

        # Security hierarchy: CREDENTIAL > SECRET > PII > CREDENTIAL_REFERENCE > PUBLIC
        has_credential_raw = any(
            e.classification in (DataClassification.CREDENTIAL.value, DataClassification.SECRET.value)
            and e.representation == DataRepresentation.RAW.value
            for e in entities
        )
        has_credential_encoded = any(
            e.classification in (DataClassification.CREDENTIAL.value, DataClassification.SECRET.value)
            and e.representation == DataRepresentation.ENCODED.value
            for e in entities
        )
        has_pii = any(
            e.classification == DataClassification.PII.value
            for e in entities
        )
        has_tokenized = any(
            e.representation == DataRepresentation.TOKENIZED.value
            or e.classification == DataClassification.CREDENTIAL_REFERENCE.value
            for e in entities
        )

        if has_credential_raw:
            primary_classification = DataClassification.CREDENTIAL.value
            primary_representation = DataRepresentation.RAW.value
        elif has_credential_encoded:
            primary_classification = DataClassification.CREDENTIAL.value
            primary_representation = DataRepresentation.ENCODED.value
        elif has_pii:
            primary_classification = DataClassification.PII.value
            primary_representation = DataRepresentation.RAW.value
        elif has_tokenized:
            primary_classification = DataClassification.CREDENTIAL_REFERENCE.value
            primary_representation = DataRepresentation.TOKENIZED.value

        # 4. Intent contract evaluation (P8, Experiments D)
        has_intent_violation = False
        intent_violation_type: Optional[str] = None
        intent_violation_reason: Optional[str] = None

        contracts = intent_contracts or []
        if self.intent_engine and hasattr(self.intent_engine, "contracts"):
            contracts = list(self.intent_engine.contracts.values())

        for contract in contracts:
            if contract.session_id == action.session_id:
                # Check resource scope mismatch
                if contract.allowed_resources and action.destination not in contract.allowed_resources:
                    if action.action_type in (ActionType.FILE_WRITE, ActionType.NETWORK_REQUEST):
                        has_intent_violation = True
                        intent_violation_type = IntentViolationType.RESOURCE_SCOPE_MISMATCH.value
                        intent_violation_reason = f"Proposed resource '{action.destination}' is not in declared contract allowed resources: {contract.allowed_resources}"
                        break
                # Check allowed operations
                if contract.allowed_operations and action.operation not in contract.allowed_operations:
                    has_intent_violation = True
                    intent_violation_type = IntentViolationType.OPERATION_NOT_ALLOWED.value
                    intent_violation_reason = f"Proposed operation '{action.operation}' is not in allowed operations: {contract.allowed_operations}"
                    break
                # Check network
                if action.action_type == ActionType.NETWORK_REQUEST:
                    if contract.allowed_network is not None and not any(net in action.destination for net in contract.allowed_network):
                        has_intent_violation = True
                        intent_violation_type = IntentViolationType.UNDECLARED_NETWORK_EFFECT.value
                        intent_violation_reason = f"Proposed network endpoint '{action.destination}' not declared in intent contract"
                        break

        # Check explicit action metadata flag for test simulations
        if action.metadata.get("simulate_intent_violation"):
            has_intent_violation = True
            intent_violation_type = action.metadata.get("violation_type", IntentViolationType.RESOURCE_SCOPE_MISMATCH.value)
            intent_violation_reason = action.metadata.get("violation_reason", "High-confidence intent violation")

        return ProspectiveAnalysisResult(
            action_id=action.action_id,
            session_id=action.session_id,
            detected_entities=entities,
            primary_classification=primary_classification,
            primary_representation=primary_representation,
            destination=action.destination,
            destination_trust=dest_trust,
            transformation_semantics=transformation_semantics,
            has_intent_violation=has_intent_violation,
            intent_violation_type=intent_violation_type,
            intent_violation_reason=intent_violation_reason,
            risk_finding_ids=[],
            metadata={"entity_count": len(entities)},
        )

    def _to_text(self, obj: Any) -> str:
        """Converts arbitrary payload objects to searchable string."""
        if obj is None:
            return ""
        if isinstance(obj, str):
            return obj
        if isinstance(obj, (dict, list)):
            try:
                return json.dumps(obj)
            except Exception:
                return str(obj)
        return str(obj)

    def _has_encoded_form(self, raw_val: str, text: str) -> bool:
        """Checks if a known raw secret has a base64 or url-encoded form in text."""
        if not raw_val or not text:
            return False
        import base64
        import urllib.parse
        b64 = base64.b64encode(raw_val.encode()).decode()
        if b64 in text:
            return True
        url_enc = urllib.parse.quote(raw_val)
        if url_enc != raw_val and url_enc in text:
            return True
        return False
