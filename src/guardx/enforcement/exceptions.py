"""Exceptions for GuardX Milestone 5 Runtime Policy Enforcement."""

from typing import Any, Dict, Optional


class EnforcementError(Exception):
    """Base class for all GuardX runtime enforcement errors."""

    def __init__(self, message: str, action_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.action_id = action_id
        self.details = details or {}


class ActionBlockedError(EnforcementError):
    """Raised when an action is strictly blocked by policy (INV-M5-001)."""

    def __init__(self, message: str, action_id: Optional[str] = None, policy_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, action_id=action_id, details=details)
        self.policy_id = policy_id


class ReviewRequiredError(EnforcementError):
    """Raised when an action requires human review and is queued/pending (INV-M5-004)."""

    def __init__(self, message: str, review_id: str, action_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, action_id=action_id, details=details)
        self.review_id = review_id


class ReviewDeniedError(EnforcementError):
    """Raised when human review was denied (INV-M5-005)."""

    def __init__(self, message: str, review_id: str, action_id: Optional[str] = None):
        super().__init__(message, action_id=action_id)
        self.review_id = review_id


class ReviewExpiredError(EnforcementError):
    """Raised when human review timed out/expired (INV-M5-005)."""

    def __init__(self, message: str, review_id: str, action_id: Optional[str] = None):
        super().__init__(message, action_id=action_id)
        self.review_id = review_id


class ModificationFailedError(EnforcementError):
    """Raised when an action modification fails or post-modification re-analysis is unsafe (INV-M5-003)."""


class TOCTOUViolationError(EnforcementError):
    """Raised when action parameters mutated between evaluation and execution (INV-M5-006)."""

    def __init__(self, message: str, expected_hash: str, actual_hash: str, action_id: Optional[str] = None):
        super().__init__(message, action_id=action_id)
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash


class VerificationMismatchError(EnforcementError):
    """Raised when observed runtime behavior does not match authorized prospective action."""
