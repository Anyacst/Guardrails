"""Risk Path Engine for GuardX Milestone 4.

Evaluates proven information-flow traces, entity classifications,
representation states, and trust boundaries to generate explainable SecurityFindings.

Strict Invariants:
- PROVEN-FLOW REQUIREMENT: Never generates a disclosure finding without an M3 proven lineage path.
- ZERO PLAINTEXT: Findings never contain raw secret plaintext.
- REPRESENTATION AWARE: Differentiates RAW vs TOKENIZED vs ENCODED.
- DEDUPLICATION: Avoids generating duplicate findings for identical paths.
"""

import hashlib
import json
import threading
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from guardx.lineage.models import DataClassification, DataEntity, DataRepresentation, LineageTraceResult
from guardx.lineage.store import DataLineageStore
from guardx.risk.models import FindingCategory, SecurityFinding, Severity
from guardx.risk.path import ExplainableRiskPath
from guardx.risk.rules import DEFAULT_SECURITY_RULES, RiskRule
from guardx.trust.models import TrustBoundaryCrossing, TrustLevel
from guardx.trust.resolver import TrustResolver


def _val(x: Any) -> str:
    if hasattr(x, "value"):
        return str(x.value)
    return str(x)


class RiskPathEngine:
    """Evaluates proven data lineage and trust boundaries to synthesize security findings."""

    def __init__(
        self,
        lineage_store: Optional[DataLineageStore] = None,
        trust_resolver: Optional[TrustResolver] = None,
        rules: Optional[List[RiskRule]] = None,
        on_finding_callback: Optional[Callable[[SecurityFinding], None]] = None,
    ):
        self.lineage_store = lineage_store
        self.trust_resolver = trust_resolver or TrustResolver()
        self.rules = rules or list(DEFAULT_SECURITY_RULES)
        self.on_finding_callback = on_finding_callback

        self._lock = threading.RLock()
        self._findings: Dict[str, SecurityFinding] = {}
        self._seen_keys: Set[str] = set()

    def set_lineage_store(self, store: DataLineageStore) -> None:
        self.lineage_store = store

    def evaluate_entity(self, entity: DataEntity, session_id: str) -> List[SecurityFinding]:
        """Evaluates an entity and all its downstream destinations for security risks."""
        if not self.lineage_store:
            return []

        trace = self.lineage_store.trace_forward(entity.entity_id)
        return self.evaluate_trace(trace, session_id, entity=entity)

    def evaluate_trace(
        self,
        trace: LineageTraceResult,
        session_id: str,
        entity: Optional[DataEntity] = None,
    ) -> List[SecurityFinding]:
        """Evaluates a forward lineage trace against all deterministic security rules."""
        with self._lock:
            # MANDATORY RULE: If there is no proven flow, NEVER generate disclosure findings!
            if not trace.has_proven_flow or not trace.destinations:
                return []

            if not entity and self.lineage_store:
                entity = self.lineage_store.get_entity(trace.entity_or_carrier_id)
                if not entity:
                    # Check if target was canonical node id
                    clean_id = trace.entity_or_carrier_id
                    if clean_id.startswith("entity:"):
                        entity = self.lineage_store.get_entity(clean_id[7:])

            if not entity:
                return []

            # Public data does not generate disclosure findings
            if _val(entity.classification) == _val(DataClassification.PUBLIC):
                return []

            findings_produced: List[SecurityFinding] = []

            for destination_id in trace.destinations:
                source_trust = self.trust_resolver.resolve(entity.origin_resource_id)
                dest_trust = self.trust_resolver.resolve(destination_id)

                for rule in self.rules:
                    if self._matches_rule(rule, entity, dest_trust, trace):
                        finding = self._create_finding(
                            rule=rule,
                            entity=entity,
                            destination_id=destination_id,
                            source_trust=source_trust,
                            dest_trust=dest_trust,
                            trace=trace,
                            session_id=session_id,
                        )
                        if finding:
                            findings_produced.append(finding)

            return findings_produced

    def _matches_rule(
        self,
        rule: RiskRule,
        entity: DataEntity,
        dest_trust: TrustLevel,
        trace: LineageTraceResult,
    ) -> bool:
        # 1. Classification check
        ent_class = _val(entity.classification)
        if ent_class not in rule.allowed_classifications:
            return False

        # 2. Representation check
        ent_repr = _val(entity.representation)
        if ent_repr not in rule.allowed_representations:
            return False

        # 3. Destination trust check
        dt = _val(dest_trust)
        if dt not in rule.allowed_destination_trusts:
            return False

        # 4. Proven flow check
        if rule.requires_proven_flow and not trace.has_proven_flow:
            return False

        return True

    def _create_finding(
        self,
        rule: RiskRule,
        entity: DataEntity,
        destination_id: str,
        source_trust: TrustLevel,
        dest_trust: TrustLevel,
        trace: LineageTraceResult,
        session_id: str,
    ) -> Optional[SecurityFinding]:
        # Deduplication key
        path_repr = f"{entity.entity_id}->{destination_id}->{[h.destination for h in trace.hops]}"
        path_hash = hashlib.sha256(path_repr.encode()).hexdigest()[:16]
        dedup_key = f"{rule.rule_id}::{entity.entity_id}::{destination_id}::{path_hash}"

        if dedup_key in self._seen_keys:
            return None
        self._seen_keys.add(dedup_key)

        supporting_events: List[str] = []
        for hop in trace.hops:
            if hop.event_id and hop.event_id not in supporting_events:
                supporting_events.append(hop.event_id)

        title = f"{rule.title}: {entity.label} -> {destination_id}"
        explanation = (
            f"Rule {rule.rule_id} triggered. Entity '{entity.label}' ({_val(entity.classification)}, {_val(entity.representation)}) "
            f"flowed from {entity.origin_resource_id} ({_val(source_trust)}) to {destination_id} ({_val(dest_trust)}) "
            f"across {len(trace.hops)} verified causal hops."
        )

        finding = SecurityFinding(
            finding_id=f"find_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            rule_id=rule.rule_id,
            title=title,
            category=rule.category,
            severity=rule.severity,
            confidence=entity.confidence,
            source_entity_id=entity.entity_id,
            source_resource_id=entity.origin_resource_id,
            destination_id=destination_id,
            source_trust=_val(source_trust),
            destination_trust=_val(dest_trust),
            boundary_crossing=f"{_val(source_trust)} -> {_val(dest_trust)}",
            representation=_val(entity.representation),
            lineage_path=[h.to_dict() for h in trace.hops],
            execution_event_ids=supporting_events,
            supporting_event_ids=supporting_events,
            explanation=explanation,
            provenance_quality=_val(entity.provenance_quality),
            raw_value_persisted=False,
            metadata={
                "dedup_key": dedup_key,
                "label": entity.label,
                "classification": _val(entity.classification),
                "hops_count": len(trace.hops),
            },
        )

        self._findings[finding.finding_id] = finding

        if self.on_finding_callback:
            self.on_finding_callback(finding)

        return finding

    def get_findings(self, session_id: Optional[str] = None) -> List[SecurityFinding]:
        with self._lock:
            if session_id:
                return [f for f in self._findings.values() if f.session_id == session_id]
            return list(self._findings.values())

    def get_finding(self, finding_id: str) -> Optional[SecurityFinding]:
        with self._lock:
            return self._findings.get(finding_id)
