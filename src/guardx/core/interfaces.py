"""Core abstract interfaces for GuardX."""

from abc import ABC, abstractmethod
from typing import Optional
from guardx.core.models import (
    GuardXEvent,
    Actor,
    Resource,
    Session,
)


class EventSubscriber(ABC):
    """Observer receiving immutable GuardX events."""

    @abstractmethod
    def on_event(self, event: GuardXEvent) -> None:
        """Invoked when an immutable event is published."""
        pass


class EventBus(ABC):
    """Publish-subscribe bus for distributing immutable GuardX events."""

    @abstractmethod
    def publish(self, event: GuardXEvent) -> None:
        """Publish an immutable event to all registered subscribers."""
        pass

    @abstractmethod
    def subscribe(self, subscriber: EventSubscriber) -> None:
        """Register a subscriber."""
        pass

    @abstractmethod
    def unsubscribe(self, subscriber: EventSubscriber) -> None:
        """Deregister a subscriber."""
        pass


class ResourceResolver(ABC):
    """Canonicalization engine converting raw resource strings into canonical Resource objects."""

    @abstractmethod
    def resolve_file(self, raw_path: str, workspace_root: str) -> Resource:
        """Resolves file path to canonical real path relative to workspace."""
        pass

    @abstractmethod
    def resolve_network(self, host: str, port: Optional[int] = None) -> Resource:
        """Resolves destination host/port to canonical network endpoint with default trust level."""
        pass

    @abstractmethod
    def resolve_tool(self, tool_name: str) -> Resource:
        """Resolves tool name to canonical tool resource."""
        pass

    @abstractmethod
    def resolve_process(self, command: str) -> Resource:
        """Resolves process or executable command to canonical process resource."""
        pass


class ActorResolver(ABC):
    """Canonicalization engine converting raw actor strings into canonical Actor objects."""

    @abstractmethod
    def resolve_agent(self, agent_id: str, display_name: Optional[str] = None) -> Actor:
        """Resolves an agent instance to canonical Actor."""
        pass

    @abstractmethod
    def resolve_user(self, user_id: str, display_name: Optional[str] = None) -> Actor:
        """Resolves a user identity to canonical Actor."""
        pass

    @abstractmethod
    def resolve_tool(self, tool_name: str) -> Actor:
        """Resolves a tool acting on behalf of execution to canonical Actor."""
        pass

    @abstractmethod
    def resolve_subprocess(self, command: str) -> Actor:
        """Resolves a spawned subprocess to canonical Actor."""
        pass


class RuntimeTelemetryProvider(ABC):
    """Pluggable telemetry provider interface for host/runtime observation."""

    @abstractmethod
    def provider_name(self) -> str:
        """Name of the telemetry provider."""
        pass

    @abstractmethod
    def start_collection(self, session: Session) -> None:
        """Initialize telemetry collection for the session."""
        pass

    @abstractmethod
    def stop_collection(self, session: Session) -> None:
        """Terminate telemetry collection for the session."""
        pass
