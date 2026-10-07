"""Pytest configuration and common fixtures for GuardX."""

import sys
from pathlib import Path
import pytest

# Ensure GuardX and Unique are in sys.path
TOOL_SRC = Path(__file__).resolve().parent.parent / "src"
UNIQUE_SRC = Path("/Users/neerajkahal/Documents/Unique/src")
UNIQUE_ROOT = Path("/Users/neerajkahal/Documents/Unique")

for p in (TOOL_SRC, UNIQUE_SRC, UNIQUE_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from guardx.core.bus import InMemoryEventBus
from guardx.core.crypto import generate_session_key
from guardx.core.models import Session
from guardx.core.recorder import EventRecorder
from guardx.core.resolvers import DefaultActorResolver, DefaultResourceResolver
from guardx.core.sanitizer import SafePayloadBuilder


try:
    from agentguard.engine.token_store import global_token_store
except ImportError:
    global_token_store = None


@pytest.fixture(autouse=True)
def clean_token_store():
    if global_token_store is not None:
        global_token_store.clear()
    yield
    if global_token_store is not None:
        global_token_store.clear()


@pytest.fixture
def session():
    return Session(
        session_id="test_session_001",
        agent_name="opencode_test_agent",
        workspace_root="/tmp/test_workspace",
        hmac_key=generate_session_key(),
    )


@pytest.fixture
def event_bus():
    return InMemoryEventBus()


@pytest.fixture
def actor_resolver():
    return DefaultActorResolver()


@pytest.fixture
def resource_resolver():
    return DefaultResourceResolver()


@pytest.fixture
def safe_payload_builder():
    return SafePayloadBuilder()


@pytest.fixture
def recorder(session, event_bus, actor_resolver, resource_resolver, safe_payload_builder):
    return EventRecorder(
        session=session,
        event_bus=event_bus,
        actor_resolver=actor_resolver,
        resource_resolver=resource_resolver,
        safe_payload_builder=safe_payload_builder,
    )
