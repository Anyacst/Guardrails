"""Unit tests for async-safe contextvars and ScopeManager."""

import asyncio
import pytest

from guardx.core.context import (
    ScopeManager,
    get_current_actor,
    get_current_scope,
    get_current_session,
    set_current_session,
)
from guardx.core.enums import ActorType, ScopeStatus
from guardx.core.models import Actor, Session


def test_sync_scope_enter_exit_lifecycle(session):
    set_current_session(session)
    manager = ScopeManager()

    assert get_current_scope() is None

    with manager.scope("root_task") as root_scope:
        assert get_current_scope() is not None
        assert get_current_scope().scope_id == root_scope.scope_id
        assert root_scope.status == ScopeStatus.ACTIVE
        assert root_scope.end_time is None

        # Nested scope
        with manager.scope("child_tool") as child_scope:
            assert get_current_scope().scope_id == child_scope.scope_id
            assert child_scope.parent_scope_id == root_scope.scope_id

        # Returned to root scope
        assert get_current_scope().scope_id == root_scope.scope_id
        assert child_scope.status == ScopeStatus.COMPLETED
        assert child_scope.end_time is not None

    # Exited all scopes
    assert get_current_scope() is None
    assert root_scope.status == ScopeStatus.COMPLETED
    assert root_scope.end_time is not None


def test_scope_failure_status(session):
    set_current_session(session)
    manager = ScopeManager()

    with pytest.raises(RuntimeError):
        with manager.scope("failing_task") as scope:
            assert scope.status == ScopeStatus.ACTIVE
            raise RuntimeError("Simulation failure")

    assert scope.status == ScopeStatus.FAILED
    assert scope.end_time is not None


def test_async_concurrent_scope_isolation(session):
    set_current_session(session)
    manager = ScopeManager()

    async def worker(task_name: str, delay: float):
        actor = Actor(actor_id=f"agent:{task_name}", actor_type=ActorType.AGENT, display_name=task_name)
        async with manager.scope(task_name, actor=actor) as sc:
            # Verify context belongs to this task
            assert get_current_scope().scope_name == task_name
            assert get_current_actor().actor_id == f"agent:{task_name}"
            await asyncio.sleep(delay)
            assert get_current_scope().scope_name == task_name
            return sc.scope_id

    async def main():
        return await asyncio.gather(
            worker("task_alpha", 0.05),
            worker("task_beta", 0.02),
        )

    res1, res2 = asyncio.run(main())

    assert res1 != res2
    assert get_current_scope() is None
