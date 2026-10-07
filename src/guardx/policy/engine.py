"""Policy Evaluation Engine for GuardX Milestone 5.

Evaluates prospective analysis findings against deterministic policy rules,
enforcing strict conflict resolution order:
BLOCK > HUMAN_REVIEW > MODIFY > ALLOW
"""

import threading
from typing import Any, Dict, List, Optional
from guardx.policy.models import (
    DECISION_PRECEDENCE,
    DecisionType,
    PolicyMatch,
    PolicyRule,
)
from guardx.policy.rules import DEFAULT_POLICY_RULES


class PolicyEngine:
    """Evaluates prospective actions against configured security policies."""

    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self._lock = threading.RLock()
        self._rules: Dict[str, PolicyRule] = {}
        initial_rules = rules if rules is not None else DEFAULT_POLICY_RULES
        for r in initial_rules:
            self._rules[r.policy_id] = r

    def add_rule(self, rule: PolicyRule) -> None:
        """Registers or replaces a policy rule."""
        with self._lock:
            self._rules[rule.policy_id] = rule

    def get_rules(self) -> List[PolicyRule]:
        """Returns all registered policy rules."""
        with self._lock:
            return list(self._rules.values())

    def get_rule(self, policy_id: str) -> Optional[PolicyRule]:
        with self._lock:
            return self._rules.get(policy_id)

    def evaluate(self, analysis: Any) -> Dict[str, Any]:
        """Evaluates a ProspectiveAnalysis instance against all enabled policies.
        
        Deterministic Conflict Resolution:
        1. Evaluates all matching rules.
        2. Sorts matches primarily by DECISION_PRECEDENCE (BLOCK > HUMAN_REVIEW > MODIFY > ALLOW),
           secondarily by rule priority (higher first), and finally by policy_id (alphabetical)
           to ensure exact determinism.
        """
        with self._lock:
            matches: List[PolicyMatch] = []

            for rule in self._rules.values():
                if not rule.enabled:
                    continue
                if self._matches(rule, analysis):
                    matches.append(
                        PolicyMatch(
                            policy_id=rule.policy_id,
                            decision=rule.decision,
                            priority=rule.priority,
                            reason=rule.reason or rule.description,
                            modifier=rule.modifier,
                            rule_name=rule.name,
                        )
                    )

            if not matches:
                # Default fallback policy: if clean, ALLOW; if untrusted destination with no rule, BLOCK
                dest_trust = getattr(analysis, "destination_trust", "UNKNOWN")
                if dest_trust in ("UNTRUSTED_EXTERNAL", "UNKNOWN"):
                    return {
                        "decision": DecisionType.BLOCK,
                        "primary_policy_id": "DEFAULT_UNTRUSTED_BLOCK",
                        "matched_policy_ids": [],
                        "reason": f"No explicit allow policy for untrusted destination '{dest_trust}'.",
                        "modifier": None,
                        "matches": [],
                    }
                return {
                    "decision": DecisionType.ALLOW,
                    "primary_policy_id": "DEFAULT_ALLOW_CLEAN",
                    "matched_policy_ids": [],
                    "reason": "No policy matched; action is clean within trust boundary.",
                    "modifier": None,
                    "matches": [],
                }

            # Sort matches by:
            # 1. Decision precedence (BLOCK=4 > HUMAN_REVIEW=3 > MODIFY=2 > ALLOW=1)
            # 2. Rule priority (descending)
            # 3. Policy ID (ascending for strict tie-breaking determinism)
            def _sort_key(m: PolicyMatch):
                prec = DECISION_PRECEDENCE.get(m.decision, 0)
                return (-prec, -m.priority, m.policy_id)

            sorted_matches = sorted(matches, key=_sort_key)
            winning = sorted_matches[0]

            return {
                "decision": winning.decision,
                "primary_policy_id": winning.policy_id,
                "matched_policy_ids": [m.policy_id for m in sorted_matches],
                "reason": winning.reason,
                "modifier": winning.modifier,
                "matches": sorted_matches,
            }

    def _matches(self, rule: PolicyRule, analysis: Any) -> bool:
        """Determines whether a policy rule matches a prospective analysis."""
        dest_trust = getattr(analysis, "destination_trust", "UNKNOWN")
        has_intent_violation = getattr(analysis, "has_intent_violation", False)
        entities = getattr(analysis, "entities", [])

        # 1. Intent violation check
        if rule.requires_intent_violation is True:
            if not has_intent_violation:
                return False
            return True
        elif rule.requires_intent_violation is False and has_intent_violation:
            return False

        # 2. Destination trust tier check
        if rule.allowed_destination_trusts is not None:
            if dest_trust not in rule.allowed_destination_trusts:
                return False

        # 3. Entity classification & representation checks
        # If the rule specifies allowed_classifications, at least one entity in analysis must match
        if rule.allowed_classifications is not None:
            if not entities:
                return False

            matching_entity = False
            for ent in entities:
                ent_class = getattr(ent, "classification", "")
                ent_repr = getattr(ent, "representation", "")

                if ent_class in rule.allowed_classifications:
                    if rule.allowed_representations is None or ent_repr in rule.allowed_representations:
                        matching_entity = True
                        break

            if not matching_entity:
                return False

        elif rule.allowed_representations is not None:
            if not entities:
                return False
            matching_repr = any(
                getattr(ent, "representation", "") in rule.allowed_representations
                for ent in entities
            )
            if not matching_repr:
                return False

        return True
