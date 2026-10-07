"""Security Overlay Store for GuardX Milestone 4.

Maintains dedicated storage for Layer 3 Security Intelligence:
- Risk findings (SecurityFinding)
- Trust boundary crossings (TrustBoundaryCrossing)
- Intent violations (IntentViolation)
- Attack chains (AttackChain)

Guarantees:
- Strict isolation from Layer 1 ExecutionGraphStore and Layer 2 DataLineageStore.
- Thread-safe query and retrieval.
- Zero raw plaintext persistence.
"""

from collections import defaultdict
import threading
from typing import Any, Dict, List, Optional

from guardx.chains.models import AttackChain
from guardx.intent.models import IntentContract, IntentViolation
from guardx.risk.models import SecurityFinding
from guardx.trust.models import TrustBoundaryCrossing


class SecurityOverlayStore:
    """Thread-safe store for all Layer 3 security findings and analysis objects."""

    def __init__(self, session_id: str = ""):
        self.session_id = session_id
        self._lock = threading.RLock()
        self._findings: Dict[str, SecurityFinding] = {}
        self._crossings: Dict[str, TrustBoundaryCrossing] = {}
        self._intent_violations: Dict[str, IntentViolation] = {}
        self._intent_contracts: Dict[str, IntentContract] = {}
        self._attack_chains: Dict[str, AttackChain] = {}

    def add_finding(self, finding: SecurityFinding) -> None:
        with self._lock:
            self._findings[finding.finding_id] = finding

    def get_findings(self) -> List[SecurityFinding]:
        with self._lock:
            return list(self._findings.values())

    def get_finding(self, finding_id: str) -> Optional[SecurityFinding]:
        with self._lock:
            return self._findings.get(finding_id)

    def add_crossing(self, crossing: TrustBoundaryCrossing) -> None:
        with self._lock:
            self._crossings[crossing.crossing_id] = crossing

    def get_crossings(self) -> List[TrustBoundaryCrossing]:
        with self._lock:
            return list(self._crossings.values())

    def add_intent_violation(self, violation: IntentViolation) -> None:
        with self._lock:
            self._intent_violations[violation.violation_id] = violation

    def get_intent_violations(self) -> List[IntentViolation]:
        with self._lock:
            return list(self._intent_violations.values())

    def add_intent_contract(self, contract: IntentContract) -> None:
        with self._lock:
            self._intent_contracts[contract.intent_id] = contract

    def get_intent_contracts(self) -> List[IntentContract]:
        with self._lock:
            return list(self._intent_contracts.values())

    def add_attack_chain(self, chain: AttackChain) -> None:
        with self._lock:
            self._attack_chains[chain.chain_id] = chain

    def get_attack_chains(self) -> List[AttackChain]:
        with self._lock:
            return list(self._attack_chains.values())

    def to_dict(self) -> Dict[str, Any]:
        """Sanitized JSON snapshot of all security intelligence in the session."""
        with self._lock:
            return {
                "session_id": self.session_id,
                "findings": [f.to_dict() for f in self._findings.values()],
                "crossings": [c.to_dict() for c in self._crossings.values()],
                "intent_violations": [v.to_dict() for v in self._intent_violations.values()],
                "intent_contracts": [c.to_dict() for c in self._intent_contracts.values()],
                "attack_chains": [ch.to_dict() for ch in self._attack_chains.values()],
                "summary": {
                    "total_findings": len(self._findings),
                    "critical": len([f for f in self._findings.values() if f.severity.value == "CRITICAL"]),
                    "high": len([f for f in self._findings.values() if f.severity.value == "HIGH"]),
                    "medium": len([f for f in self._findings.values() if f.severity.value == "MEDIUM"]),
                    "low": len([f for f in self._findings.values() if f.severity.value == "LOW"]),
                    "crossings": len(self._crossings),
                    "attack_chains": len(self._attack_chains),
                    "intent_violations": len(self._intent_violations),
                }
            }
