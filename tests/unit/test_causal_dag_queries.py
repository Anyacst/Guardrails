"""Unit tests for Causal DAG queries ("Why did this action happen?")."""

from guardx.collectors.network_collector import NetworkCollector
from guardx.collectors.process_collector import ProcessCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.enums import EventType
from guardx.core.models import RawObservation
from guardx.graph.engine import ProvenanceEngine
from guardx.graph.store import InMemoryGraphStore


def test_explain_causality_network_request(recorder, event_bus):
    store = InMemoryGraphStore()
    engine = ProvenanceEngine(store=store)
    event_bus.subscribe(engine)

    tool_col = ToolCollector(recorder)
    proc_col = ProcessCollector(recorder)
    net_col = NetworkCollector(recorder)

    # 1. User prompts agent
    user_evt = recorder.record(RawObservation(
        event_type=EventType.USER_INPUT,
        raw_payload={"query": "Deploy the update to remote server"},
        actor_id="user:alice",
    ))

    # 2. Agent invokes tool
    tool_evt = tool_col.record_tool_call(
        tool_name="bash",
        arguments={"command": "curl -X POST https://api.deploy.internal"},
        actor_id="agent:opencode",
        causal_event_id=user_evt.event_id,
    )

    # 3. Tool spawns subprocess
    proc_evt = proc_col.record_process_exec(
        command="curl -X POST https://api.deploy.internal",
        pid=54321,
        actor_id="subproc:curl",
        causal_event_id=tool_evt.event_id,
    )

    # 4. Process makes network request
    net_evt = net_col.record_request(
        url="https://api.deploy.internal:443",
        method="POST",
        actor_id="subproc:curl",
        causal_event_id=proc_evt.event_id,
    )

    # Query: What caused this network request?
    endpoint_node_id = net_evt.destination.resource_id
    causal_ancestors = engine.explain_causality(endpoint_node_id)
    ancestor_ids = {n.node_id for n in causal_ancestors}

    # Verify causal chain
    assert "agent:opencode" in ancestor_ids
    assert "tool:bash" in ancestor_ids
    assert "proc:curl" in ancestor_ids
    assert endpoint_node_id in ancestor_ids
