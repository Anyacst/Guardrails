"""Attack Chain Detector for GuardX Milestone 4.

Synthesizes multi-event attack chains connecting provenance execution events,
deterministic transformations, and proven information-flow traces.
"""

import threading
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from guardx.chains.models import AttackChain, AttackChainType
from guardx.intent.models import IntentViolation, IntentViolationType
from guardx.lineage.models import DataClassification, DataEntity, DataRepresentation
from guardx.lineage.store import DataLineageStore
from guardx.risk.models import FindingCategory, SecurityFinding, Severity
from guardx.trust.models import TrustLevel
from guardx.trust.resolver import TrustResolver


class AttackChainDetector:
    """Detects multi-event causal security patterns from runtime evidence."""

    def __init__(
        self,
        lineage_store: Optional[DataLineageStore] = None,
        trust_resolver: Optional[TrustResolver] = None,
        on_chain_callback: Optional[Callable[[AttackChain], None]] = None,
    ):
        self.lineage_store = lineage_store
        self.trust_resolver = trust_resolver or TrustResolver()
        self.on_chain_callback = on_chain_callback

        self._lock = threading.RLock()
        self._chains: Dict[str, AttackChain] = {}
        self._seen_keys: Set[str] = set()

    def set_lineage_store(self, store: DataLineageStore) -> None:
        self.lineage_store = store

    def evaluate_findings(
        self,
        findings: List[SecurityFinding],
        session_id: str,
        violations: Optional[List[IntentViolation]] = None,
    ) -> List[AttackChain]:
        """Evaluates security findings and intent violations to synthesize attack chains."""
        with self._lock:
            detected: List[AttackChain] = []

            for finding in findings:
                # 1. Pattern: Credential Exfiltration
                if finding.category in (FindingCategory.CREDENTIAL_EXFILTRATION, FindingCategory.CREDENTIAL_DISCLOSURE):
                    chain = self._detect_credential_exfiltration(finding, session_id)
                    if chain:
                        detected.append(chain)

                # 2. Pattern: Encoded Secret Egress
                if finding.category == FindingCategory.ENCODED_SECRET_DISCLOSURE or (
                    finding.representation == DataRepresentation.ENCODED.value
                    and finding.severity in (Severity.HIGH, Severity.CRITICAL)
                ):
                    chain = self._detect_encoded_secret_egress(finding, session_id)
                    if chain:
                        detected.append(chain)

            # 3. Pattern: Unexpected Network Side Effect
            if violations:
                for viol in violations:
                    if viol.violation_type == IntentViolationType.UNDECLARED_NETWORK_EFFECT:
                        chain = self._detect_unexpected_network_effect(viol, session_id)
                        if chain:
                            detected.append(chain)

            return detected

    def _detect_credential_exfiltration(
        self, finding: SecurityFinding, session_id: str
    ) -> Optional[AttackChain]:
        key = f"CHAIN_EXFIL::{finding.source_resource_id}::{finding.destination_id}::{finding.source_entity_id}"
        if key in self._seen_keys:
            return None
        self._seen_keys.add(key)

        ordered_events = list(finding.execution_event_ids or finding.supporting_event_ids)

        chain = AttackChain(
            chain_id=f"chain_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            chain_type=AttackChainType.POTENTIAL_CREDENTIAL_EXFILTRATION,
            severity=finding.severity,
            confidence=finding.confidence,
            ordered_event_ids=ordered_events,
            related_entity_ids=[finding.source_entity_id] if finding.source_entity_id else [],
            source=finding.source_resource_id or "local_file",
            sink=finding.destination_id,
            supporting_findings=[finding.finding_id],
            explanation=(
                f"Multi-event credential exfiltration chain: Credential originated from '{finding.source_resource_id}', "
                f"was observed across runtime boundaries, and was transmitted to '{finding.destination_id}' "
                f"({finding.destination_trust})."
            ),
            raw_value_persisted=False,
            metadata={"finding_id": finding.finding_id, "boundary": finding.boundary_crossing},
        )

        self._chains[chain.chain_id] = chain
        if self.on_chain_callback:
            self.on_chain_callback(chain)
        return chain

    def _detect_encoded_secret_egress(
        self, finding: SecurityFinding, session_id: str
    ) -> Optional[AttackChain]:
        key = f"CHAIN_ENCODED::{finding.source_resource_id}::{finding.destination_id}::{finding.source_entity_id}"
        if key in self._seen_keys:
            return None
        self._seen_keys.add(key)

        ordered_events = list(finding.execution_event_ids or finding.supporting_event_ids)

        chain = AttackChain(
            chain_id=f"chain_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            chain_type=AttackChainType.ENCODED_SECRET_EGRESS,
            severity=finding.severity,
            confidence=finding.confidence,
            ordered_event_ids=ordered_events,
            related_entity_ids=[finding.source_entity_id] if finding.source_entity_id else [],
            source=finding.source_resource_id or "local_file",
            sink=finding.destination_id,
            supporting_findings=[finding.finding_id],
            explanation=(
                f"Multi-event encoded secret egress chain: Sensitive entity from '{finding.source_resource_id}' "
                f"underwent preserving encoding (e.g. Base64) before being delivered to external boundary '{finding.destination_id}'."
            ),
            raw_value_persisted=False,
            metadata={"representation": finding.representation},
        )

        self._chains[chain.chain_id] = chain
        if self.on_chain_callback:
            self.on_chain_callback(chain)
        return chain

    def _detect_unexpected_network_effect(
        self, violation: IntentViolation, session_id: str
    ) -> Optional[AttackChain]:
        key = f"CHAIN_NET_EFFECT::{violation.intent_id}::{violation.actual_resource}"
        if key in self._seen_keys:
            return None
        self._seen_keys.add(key)

        chain = AttackChain(
            chain_id=f"chain_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            chain_type=AttackChainType.UNEXPECTED_NETWORK_SIDE_EFFECT,
            severity=violation.severity,
            confidence=1.0,
            ordered_event_ids=[violation.event_id],
            related_entity_ids=[],
            source="intent_contract",
            sink=violation.actual_resource,
            supporting_findings=[],
            explanation=(
                f"Unexpected network side-effect chain: Task declared local file inspection, "
                f"but runtime observation detected unauthorized external network call to '{violation.actual_resource}'."
            ),
            raw_value_persisted=False,
            metadata={"intent_id": violation.intent_id, "scope_id": violation.scope_id},
        )

        self._chains[chain.chain_id] = chain
        if self.on_chain_callback:
            self.on_chain_callback(chain)
        return chain

    def get_chains(self, session_id: Optional[str] = None) -> List[AttackChain]:
        with self._lock:
            if session_id:
                return [c for c in self._chains.values() if c.session_id == session_id]
            return list(self._chains.values())
