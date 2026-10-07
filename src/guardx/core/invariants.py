"""GuardX Core Domain Invariants & Assertions.

Guarantees:
- INV-001: Zero raw credentials or sensitive PII in event payloads.
- INV-002: Append-only immutability.
- INV-003: Strict monotonic sequence numbers.
- INV-004: Execution scope attribution.
- INV-005: Causal ordering integrity.
- INV-006: Keyed HMAC fingerprint confidentiality.
- INV-007: Resolver idempotency.
"""

from typing import Any, Dict, Optional, Set
from guardx.core.enums import EventType
from guardx.core.models import GuardXEvent
from guardx.core.sanitizer import SensitiveContentScanner


class InvariantViolation(Exception):
    """Raised when an architectural or security invariant is violated."""
    pass


class InvariantValidator:
    """Enforces GuardX domain invariants on events, payloads, and sequences."""

    def __init__(self, scanner: Optional[SensitiveContentScanner] = None):
        self.scanner = scanner or SensitiveContentScanner()
        # Non-operational lifecycle events that do not require an active execution scope
        self.ROOT_LIFECYCLE_EVENTS: Set[EventType] = {
            EventType.SESSION_START,
            EventType.SESSION_END,
            EventType.SCOPE_START,
            EventType.SCOPE_END,
            EventType.USER_INPUT,
        }

    def validate_event(
        self,
        event: GuardXEvent,
        expected_seq: Optional[int] = None,
        known_event_sequences: Optional[Dict[str, int]] = None,
    ) -> None:
        """Validates that a GuardXEvent adheres to all core invariants."""

        # INV-001: Zero Raw Secret Invariant (Deep content check)
        if self.scanner.contains_sensitive_data(event.payload):
            raise InvariantViolation(
                f"[INV-001] Event {event.event_id} ({event.event_type}) contains unmasked "
                f"credentials, secrets, or PII in its payload."
            )

        # INV-003: Strict Sequence Monotonicity
        if expected_seq is not None and event.sequence_number != expected_seq:
            raise InvariantViolation(
                f"[INV-003] Sequence violation for event {event.event_id}. "
                f"Expected monotonic sequence {expected_seq}, but received {event.sequence_number}."
            )

        # INV-004: Scope Attribution
        if event.event_type not in self.ROOT_LIFECYCLE_EVENTS and not event.execution_scope_id:
            raise InvariantViolation(
                f"[INV-004] Operational event {event.event_id} of type {event.event_type} "
                f"is missing mandatory execution_scope_id attribution."
            )

        # INV-005: Causal Integrity
        if event.causal_event_id:
            if known_event_sequences is not None:
                if event.causal_event_id not in known_event_sequences:
                    raise InvariantViolation(
                        f"[INV-005] Event {event.event_id} references causal_event_id "
                        f"'{event.causal_event_id}' which does not exist in session history."
                    )
                causal_seq = known_event_sequences[event.causal_event_id]
                if causal_seq >= event.sequence_number:
                    raise InvariantViolation(
                        f"[INV-005] Causal ordering inverted. Event {event.event_id} (seq {event.sequence_number}) "
                        f"references causal_event_id '{event.causal_event_id}' with equal or later seq {causal_seq}."
                    )

        # Confidence bounds validation
        if not (0.0 <= event.confidence <= 1.0):
            raise InvariantViolation(
                f"Event {event.event_id} has invalid confidence {event.confidence} (must be in [0.0, 1.0])."
            )
