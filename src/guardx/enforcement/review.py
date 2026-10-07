"""HumanReviewQueue for GuardX Milestone 5.

Implements human-in-the-loop review queue with async and sync resolution futures (INV-M5-004, INV-M5-005).
Zero raw secrets in review requests or notifications.
"""

import asyncio
from datetime import datetime, timezone
import threading
from typing import Any, Callable, Dict, List, Optional
import uuid

from guardx.enforcement.exceptions import ReviewDeniedError, ReviewExpiredError
from guardx.enforcement.models import ProspectiveAction, ReviewRequest, ReviewStatus


class HumanReviewQueue:
    """Thread-safe and asyncio-compatible review queue."""

    def __init__(self, on_review_event: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self._lock = threading.Lock()
        self._reviews: Dict[str, ReviewRequest] = {}
        self._async_futures: Dict[str, asyncio.Future] = {}
        self._sync_events: Dict[str, threading.Event] = {}
        self.on_review_event = on_review_event

    def request_review(
        self,
        action: ProspectiveAction,
        decision_id: str,
        reason: str,
        policy_id: str,
        severity: str = "HIGH",
        entity_classifications: Optional[List[str]] = None,
    ) -> ReviewRequest:
        """Enqueues an action for human review with a safe payload preview (zero raw secrets)."""
        review_id = f"rev_{uuid.uuid4().hex[:12]}"
        
        # Build safe preview (stripping any sensitive keys)
        safe_preview = {
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "destination": action.destination,
            "operation": action.operation,
            "tool_name": action.tool_name,
            "entity_refs": action.entity_refs,
            "safe_payload_keys": list(action.safe_payload.keys()) if isinstance(action.safe_payload, dict) else [],
        }

        req = ReviewRequest(
            review_id=review_id,
            session_id=action.session_id,
            action_id=action.action_id,
            decision_id=decision_id,
            action_hash=action.action_hash,
            reason=reason,
            severity=severity,
            policy_id=policy_id,
            safe_preview=safe_preview,
            entity_classifications=entity_classifications or [],
            destination=action.destination,
            status=ReviewStatus.PENDING,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        with self._lock:
            self._reviews[review_id] = req
            self._sync_events[review_id] = threading.Event()

        if self.on_review_event:
            self.on_review_event("review.requested", req.to_dict())

        return req

    def get_review(self, review_id: str) -> Optional[ReviewRequest]:
        with self._lock:
            return self._reviews.get(review_id)

    def get_reviews_for_session(self, session_id: str) -> List[ReviewRequest]:
        with self._lock:
            return [r for r in self._reviews.values() if r.session_id == session_id]

    def get_pending_reviews(self, session_id: Optional[str] = None) -> List[ReviewRequest]:
        with self._lock:
            return [
                r for r in self._reviews.values()
                if r.status == ReviewStatus.PENDING and (session_id is None or r.session_id == session_id)
            ]

    def approve(self, review_id: str, resolver: str = "human") -> ReviewRequest:
        """Approves a pending review once."""
        with self._lock:
            req = self._reviews.get(review_id)
            if not req:
                raise ValueError(f"Review '{review_id}' not found")
            if req.status != ReviewStatus.PENDING:
                return req
            updated = req.resolve(ReviewStatus.APPROVED, resolver=resolver)
            self._reviews[review_id] = updated
            sync_evt = self._sync_events.get(review_id)
            if sync_evt:
                sync_evt.set()

        # Resolve async future if waiting in an event loop
        fut = self._async_futures.get(review_id)
        if fut and not fut.done():
            fut.get_loop().call_soon_threadsafe(fut.set_result, updated)

        if self.on_review_event:
            self.on_review_event("review.resolved", updated.to_dict())

        return updated

    def deny(self, review_id: str, resolver: str = "human") -> ReviewRequest:
        """Denies a pending review."""
        with self._lock:
            req = self._reviews.get(review_id)
            if not req:
                raise ValueError(f"Review '{review_id}' not found")
            if req.status != ReviewStatus.PENDING:
                return req
            updated = req.resolve(ReviewStatus.DENIED, resolver=resolver)
            self._reviews[review_id] = updated
            sync_evt = self._sync_events.get(review_id)
            if sync_evt:
                sync_evt.set()

        fut = self._async_futures.get(review_id)
        if fut and not fut.done():
            fut.get_loop().call_soon_threadsafe(fut.set_result, updated)

        if self.on_review_event:
            self.on_review_event("review.resolved", updated.to_dict())

        return updated

    def expire(self, review_id: str) -> ReviewRequest:
        """Marks a pending review as expired (timeout)."""
        with self._lock:
            req = self._reviews.get(review_id)
            if not req:
                raise ValueError(f"Review '{review_id}' not found")
            if req.status != ReviewStatus.PENDING:
                return req
            updated = req.resolve(ReviewStatus.EXPIRED, resolver="system_timeout")
            self._reviews[review_id] = updated
            sync_evt = self._sync_events.get(review_id)
            if sync_evt:
                sync_evt.set()

        fut = self._async_futures.get(review_id)
        if fut and not fut.done():
            fut.get_loop().call_soon_threadsafe(fut.set_result, updated)

        if self.on_review_event:
            self.on_review_event("review.resolved", updated.to_dict())

        return updated

    async def wait_for_review(self, review_id: str, timeout: float = 30.0) -> ReviewRequest:
        """Async waiting for human review resolution without blocking the event loop."""
        loop = asyncio.get_running_loop()
        with self._lock:
            req = self._reviews.get(review_id)
            if not req:
                raise ValueError(f"Review '{review_id}' not found")
            if req.status != ReviewStatus.PENDING:
                if req.status == ReviewStatus.APPROVED:
                    return req
                elif req.status == ReviewStatus.DENIED:
                    raise ReviewDeniedError("Human review denied action", review_id=review_id)
                else:
                    raise ReviewExpiredError("Human review expired", review_id=review_id)

            fut = loop.create_future()
            self._async_futures[review_id] = fut

        try:
            resolved: ReviewRequest = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            resolved = self.expire(review_id)
            raise ReviewExpiredError(f"Human review timed out after {timeout}s", review_id=review_id)
        finally:
            self._async_futures.pop(review_id, None)

        if resolved.status == ReviewStatus.DENIED:
            raise ReviewDeniedError("Human review denied proposed action", review_id=review_id)
        if resolved.status == ReviewStatus.EXPIRED:
            raise ReviewExpiredError("Human review expired before approval", review_id=review_id)

        return resolved

    def wait_for_review_sync(self, review_id: str, timeout: float = 30.0) -> ReviewRequest:
        """Sync waiting for human review resolution using threading.Event."""
        with self._lock:
            req = self._reviews.get(review_id)
            if not req:
                raise ValueError(f"Review '{review_id}' not found")
            if req.status != ReviewStatus.PENDING:
                if req.status == ReviewStatus.APPROVED:
                    return req
                elif req.status == ReviewStatus.DENIED:
                    raise ReviewDeniedError("Human review denied action", review_id=review_id)
                else:
                    raise ReviewExpiredError("Human review expired", review_id=review_id)
            sync_evt = self._sync_events.get(review_id)

        if sync_evt:
            signaled = sync_evt.wait(timeout=timeout)
            if not signaled:
                self.expire(review_id)
                raise ReviewExpiredError(f"Human review timed out after {timeout}s", review_id=review_id)

        req = self.get_review(review_id)
        if not req or req.status == ReviewStatus.DENIED:
            raise ReviewDeniedError("Human review denied proposed action", review_id=review_id)
        if req.status == ReviewStatus.EXPIRED:
            raise ReviewExpiredError("Human review expired before approval", review_id=review_id)

        return req
