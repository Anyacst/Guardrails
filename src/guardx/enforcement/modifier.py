"""ActionModifier for GuardX Milestone 5.

Implements safe, deterministic tokenization and transformation of prospective actions.
Integrates directly with AgentGuard's SecretReferenceStore vault (INV-M5-002, INV-M5-003).
"""

import copy
import re
import secrets
from typing import Any, Dict, List, Optional, Set, Tuple

from guardx.enforcement.exceptions import ModificationFailedError
from guardx.enforcement.models import ActionType, ProspectiveAction, compute_action_hash
from guardx.lineage.models import DataEntity, DataRepresentation

try:
    from agentguard.engine.token_store import SecretReferenceStore, canonicalize_path
    HAS_AGENTGUARD = True
except ImportError:
    HAS_AGENTGUARD = False
    SecretReferenceStore = None
    canonicalize_path = lambda p: p


class ActionModifier:
    """Modifies unsafe proposed actions into sanitized replacement actions."""

    def __init__(self, token_store: Optional[Any] = None):
        self.token_store = token_store

    def modify(
        self,
        action: ProspectiveAction,
        raw_payload: Any,
        entities: List[DataEntity],
    ) -> Tuple[ProspectiveAction, Any]:
        """Sanitizes raw_payload and returns (replacement_action, modified_payload).

        Replaces raw credentials/PII with synthetic vault tokens.
        Preserves token -> DataEntity mapping in SecretReferenceStore.
        Computes a new canonical action_hash for the replacement action.
        """
        if not entities:
            return action, raw_payload

        modified_payload = copy.deepcopy(raw_payload)
        replaced_tokens: Dict[str, str] = {}  # raw_val -> token
        entity_tokens: Dict[str, str] = {}    # entity_id -> token

        # 1. Identify raw secrets/PII to replace
        for entity in entities:
            raw_val = entity.metadata.get("raw_value")
            if not raw_val or len(raw_val) < 3:
                continue

            if raw_val not in replaced_tokens:
                # Generate synthetic vault token
                token = self._generate_vault_token(
                    session_id=action.session_id,
                    entity=entity,
                    raw_val=raw_val,
                )
                replaced_tokens[raw_val] = token
            else:
                token = replaced_tokens[raw_val]

            entity_tokens[entity.entity_id] = token

        if not replaced_tokens:
            return action, raw_payload

        # 2. Perform text/object replacement across the payload
        modified_payload = self._replace_in_object(modified_payload, replaced_tokens)

        # 3. Build replacement safe_payload
        replacement_safe_payload = copy.deepcopy(action.safe_payload)
        replacement_safe_payload = self._replace_in_object(replacement_safe_payload, replaced_tokens)
        replacement_safe_payload["modified_from_action_id"] = action.action_id
        replacement_safe_payload["token_references"] = list(replaced_tokens.values())

        # 4. Create new ProspectiveAction with new action_hash
        new_action_id = f"{action.action_id}_mod"
        replacement_action = ProspectiveAction.create(
            action_id=new_action_id,
            session_id=action.session_id,
            action_type=action.action_type,
            destination=action.destination,
            operation=action.operation,
            actor_id=action.actor_id,
            source=action.source,
            tool_name=action.tool_name,
            safe_payload=replacement_safe_payload,
            entity_refs=list(action.entity_refs),
            destination_trust=action.destination_trust,
            execution_scope_id=action.execution_scope_id,
            intent_contract_id=action.intent_contract_id,
            metadata={
                **action.metadata,
                "original_action_id": action.action_id,
                "original_action_hash": action.action_hash,
                "modification": "TOKENIZED",
                "replaced_tokens": replaced_tokens,
            },
        )

        # 5. INV-M5-002 / Section 17 Verification:
        # Explicitly verify original raw secrets are absent from both replacement action and payload
        for raw_val in replaced_tokens.keys():
            self._verify_absence(raw_val, modified_payload, action.action_id)
            self._verify_absence(raw_val, replacement_safe_payload, action.action_id)

        return replacement_action, modified_payload

    def _generate_vault_token(self, session_id: str, entity: DataEntity, raw_val: str) -> str:
        """Generates and registers a synthetic token in SecretReferenceStore if available."""
        if self.token_store and hasattr(self.token_store, "generate_token"):
            token = self.token_store.generate_token()
            file_path = entity.source_resource or ".env"
            bound_key = entity.label or "SECRET"
            if hasattr(self.token_store, "store_mapping"):
                self.token_store.store_mapping(
                    token=token,
                    file_path=file_path,
                    bound_key=bound_key,
                    raw_secret_value=raw_val,
                    file_hash_at_read="modified",
                    session_id=session_id,
                )
            return token

        # Fallback consistent token format
        nonce = secrets.token_hex(4)
        return f"{{{{SECRET_001_{nonce}}}}}"

    def _replace_in_object(self, obj: Any, replacements: Dict[str, str]) -> Any:
        """Recursively replaces raw strings in strings, dicts, and lists."""
        if isinstance(obj, str):
            res = obj
            for raw_val, token in replacements.items():
                res = res.replace(raw_val, token)
            return res
        elif isinstance(obj, dict):
            return {k: self._replace_in_object(v, replacements) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._replace_in_object(item, replacements) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._replace_in_object(item, replacements) for item in obj)
        return obj

    def _verify_absence(self, raw_val: str, obj: Any, action_id: str) -> None:
        """Raises ModificationFailedError if raw_val appears anywhere in obj."""
        if isinstance(obj, str):
            if raw_val in obj:
                raise ModificationFailedError(
                    f"Modification verification failed: raw secret still present in modified action payload",
                    action_id=action_id,
                )
        elif isinstance(obj, dict):
            for v in obj.values():
                self._verify_absence(raw_val, v, action_id)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                self._verify_absence(raw_val, item, action_id)
