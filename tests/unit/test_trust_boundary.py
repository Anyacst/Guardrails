"""Unit tests for GuardX Milestone 4 Trust Resolver & Trust Boundary Engine."""

import pytest

from guardx.trust.engine import TrustBoundaryEngine
from guardx.trust.models import TrustBoundaryCrossing, TrustLevel
from guardx.trust.resolver import TrustResolver


def test_trust_resolver_classifications():
    resolver = TrustResolver()

    # Local resources
    assert resolver.resolve("file:.env") == TrustLevel.LOCAL
    assert resolver.resolve("/workspace/src/main.py") == TrustLevel.LOCAL
    assert resolver.resolve("proc:psutil") == TrustLevel.LOCAL
    assert resolver.resolve("user:alice") == TrustLevel.LOCAL
    assert resolver.resolve("tool:read_file") == TrustLevel.LOCAL
    assert resolver.resolve("127.0.0.1:8080") == TrustLevel.LOCAL
    assert resolver.resolve("http://localhost:3000") == TrustLevel.LOCAL

    # External LLMs
    assert resolver.resolve("llm:groq/llama-3.3-70b") == TrustLevel.EXTERNAL_LLM
    assert resolver.resolve("llm:openai/gpt-4o") == TrustLevel.EXTERNAL_LLM
    assert resolver.resolve("OpenRouter API") == TrustLevel.EXTERNAL_LLM
    assert resolver.resolve("groq") == TrustLevel.EXTERNAL_LLM

    # Trusted Internal
    assert resolver.resolve("db.corp.internal") == TrustLevel.TRUSTED_INTERNAL
    assert resolver.resolve("https://internal-vault.company.net") == TrustLevel.TRUSTED_INTERNAL

    # Trusted External
    assert resolver.resolve("api.github.com") == TrustLevel.TRUSTED_EXTERNAL
    assert resolver.resolve("https://pypi.org/simple") == TrustLevel.TRUSTED_EXTERNAL

    # Untrusted External
    assert resolver.resolve("https://evil-attacker.com") == TrustLevel.UNTRUSTED_EXTERNAL
    assert resolver.resolve("https://webhook.site/xyz") == TrustLevel.UNTRUSTED_EXTERNAL
    assert resolver.resolve("net:198.51.100.22") == TrustLevel.UNTRUSTED_EXTERNAL


def test_trust_boundary_crossing_detection():
    resolver = TrustResolver()
    crossings_observed = []

    def on_crossing(c):
        crossings_observed.append(c)

    engine = TrustBoundaryEngine(resolver=resolver, on_crossing_callback=on_crossing)

    # 1. Local to External LLM
    c1 = engine.evaluate_hop(
        session_id="sess_1",
        source_id="file:.env",
        destination_id="llm:groq/llama-3.3",
        entity_id="ent_secret_1",
        supporting_event_id="evt_llm_req",
    )
    assert c1 is not None
    assert c1.source_trust == TrustLevel.LOCAL
    assert c1.destination_trust == TrustLevel.EXTERNAL_LLM
    assert c1.boundary_name == "LOCAL -> EXTERNAL_LLM"
    assert len(crossings_observed) == 1

    # 2. Local to Local (NO boundary crossing)
    c2 = engine.evaluate_hop(
        session_id="sess_1",
        source_id="file:.env",
        destination_id="tool:read_file",
    )
    assert c2 is None
    assert len(crossings_observed) == 1

    # 3. Local to Untrusted External
    c3 = engine.evaluate_hop(
        session_id="sess_1",
        source_id="tool:curl",
        destination_id="https://evil-attacker.com",
    )
    assert c3 is not None
    assert c3.source_trust == TrustLevel.LOCAL
    assert c3.destination_trust == TrustLevel.UNTRUSTED_EXTERNAL
    assert len(crossings_observed) == 2
