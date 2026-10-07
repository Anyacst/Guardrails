"""Async-Safe Execution Context Management via contextvars.

Guarantees:
- ContextVar isolation across concurrent tasks, asyncio coroutines, and threads.
- Hierarchical ExecutionScope parent-child propagation.
- Seamless interop with FastAPI, WebSockets, and parallel tool dispatches.
"""

from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from guardx.core.enums import ScopeStatus
from guardx.core.models import (
    Actor,
    ScopeProjection,
    Session,
)

# ContextVars for active context
_CURRENT_SESSION: ContextVar[Optional[Session]] = ContextVar("guardx_current_session", default=None)
_CURRENT_SCOPE: ContextVar[Optional[ScopeProjection]] = ContextVar("guardx_current_scope", default=None)
_CURRENT_ACTOR: ContextVar[Optional[Actor]] = ContextVar("guardx_current_actor", default=None)


def get_current_session() -> Optional[Session]:
    """Returns currently active Session in context."""
    return _CURRENT_SESSION.get()


def get_current_scope() -> Optional[ScopeProjection]:
    """Returns currently active ExecutionScope projection in context."""
    return _CURRENT_SCOPE.get()


def get_current_actor() -> Optional[Actor]:
    """Returns currently active Actor in context."""
    return _CURRENT_ACTOR.get()


def set_current_session(session: Optional[Session]) -> Token:
    """Sets active session in ContextVar."""
    return _CURRENT_SESSION.set(session)


def set_current_actor(actor: Optional[Actor]) -> Token:
    """Sets active actor in ContextVar."""
    return _CURRENT_ACTOR.set(actor)


class ScopeContext:
    """Context manager for an execution scope (supporting both sync and async)."""

    def __init__(
        self,
        manager: "ScopeManager",
        scope_name: str,
        actor: Optional[Actor] = None,
        originating_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.manager = manager
        self.scope_name = scope_name
        self.actor = actor
        self.originating_event_id = originating_event_id
        self.metadata = metadata or {}
        self.scope: Optional[ScopeProjection] = None
        self._token: Optional[Token] = None
        self._actor_token: Optional[Token] = None

    def __enter__(self) -> ScopeProjection:
        session = get_current_session()
        session_id = session.session_id if session else "default_session"
        parent_scope = get_current_scope()
        parent_scope_id = parent_scope.scope_id if parent_scope else None

        active_actor = self.actor or get_current_actor()
        actor_id = active_actor.actor_id if active_actor else "agent:default"

        scope_id = f"scope_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        self.scope = ScopeProjection(
            scope_id=scope_id,
            session_id=session_id,
            parent_scope_id=parent_scope_id,
            actor_id=actor_id,
            originating_event_id=self.originating_event_id,
            scope_name=self.scope_name,
            start_time=now,
            status=ScopeStatus.ACTIVE,
            metadata=self.metadata,
        )

        self.manager.register_scope_start(self.scope)
        self._token = _CURRENT_SCOPE.set(self.scope)
        if self.actor:
            self._actor_token = _CURRENT_ACTOR.set(self.actor)

        return self.scope

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.scope:
            now = datetime.now(timezone.utc)
            final_status = ScopeStatus.FAILED if exc_type else ScopeStatus.COMPLETED
            self.scope.close(now, final_status)
            self.manager.register_scope_end(self.scope)

        if self._token:
            _CURRENT_SCOPE.reset(self._token)
        if self._actor_token:
            _CURRENT_ACTOR.reset(self._actor_token)

    async def __aenter__(self) -> ScopeProjection:
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


class ScopeManager:
    """Manages ExecutionScope lifecycle and projections across async execution contexts."""

    def __init__(self, recorder: Optional[Any] = None):
        self.recorder = recorder
        self._scopes_by_id: Dict[str, ScopeProjection] = {}

    def scope(
        self,
        scope_name: str,
        actor: Optional[Actor] = None,
        originating_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScopeContext:
        """Creates an ExecutionScope context manager."""
        return ScopeContext(
            manager=self,
            scope_name=scope_name,
            actor=actor,
            originating_event_id=originating_event_id,
            metadata=metadata,
        )

    def register_scope_start(self, scope: ScopeProjection) -> None:
        """Stores scope projection and triggers SCOPE_START event via recorder if present."""
        self._scopes_by_id[scope.scope_id] = scope
        if self.recorder and hasattr(self.recorder, "record_scope_start"):
            self.recorder.record_scope_start(scope)

    def register_scope_end(self, scope: ScopeProjection) -> None:
        """Updates scope projection and triggers SCOPE_END event via recorder if present."""
        self._scopes_by_id[scope.scope_id] = scope
        if self.recorder and hasattr(self.recorder, "record_scope_end"):
            self.recorder.record_scope_end(scope)

    def get_scope(self, scope_id: str) -> Optional[ScopeProjection]:
        """Retrieves projection by ID."""
        return self._scopes_by_id.get(scope_id)
