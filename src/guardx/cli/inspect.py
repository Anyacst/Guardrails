"""GuardX CLI & Debug Inspection Utilities."""

import sys
from typing import Optional
from guardx.graph.engine import ProvenanceEngine
from guardx.graph.formatter import GraphFormatter


def inspect_session(
    engine: ProvenanceEngine,
    session_id: str,
    as_json: bool = False,
) -> str:
    """Inspects a session graph and returns formatted tree or JSON."""
    graph = engine.store.get_session_graph(session_id)
    if as_json:
        return GraphFormatter.to_json(graph)
    return GraphFormatter.to_tree(graph)


def print_session_graph(engine: ProvenanceEngine, session_id: str, as_json: bool = False) -> None:
    """Prints session graph to stdout."""
    output = inspect_session(engine, session_id, as_json=as_json)
    print(output)
