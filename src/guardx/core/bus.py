"""Thread-safe In-Memory EventBus for GuardX."""

import inspect
import threading
from typing import List, Set
from guardx.core.interfaces import EventBus, EventSubscriber
from guardx.core.models import GuardXEvent


class InMemoryEventBus(EventBus):
    """Concurrency-safe pub-sub event bus distributing immutable GuardX events."""

    def __init__(self):
        self._lock = threading.RLock()
        self._subscribers: List[EventSubscriber] = []

    def subscribe(self, subscriber: EventSubscriber) -> None:
        """Registers an event subscriber."""
        with self._lock:
            if subscriber not in self._subscribers:
                self._subscribers.append(subscriber)

    def unsubscribe(self, subscriber: EventSubscriber) -> None:
        """Deregisters an event subscriber."""
        with self._lock:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)

    def publish(self, event: GuardXEvent) -> None:
        """Distributes an immutable event to all registered subscribers."""
        with self._lock:
            current_subscribers = list(self._subscribers)

        for subscriber in current_subscribers:
            try:
                subscriber.on_event(event)
            except Exception as e:
                # Log or handle subscriber error without halting bus broadcast
                # (In production, subscribers shouldn't crash the bus)
                pass

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)
