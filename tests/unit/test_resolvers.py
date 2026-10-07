"""Unit tests for canonical ActorResolver and ResourceResolver (INV-007)."""

import os
from guardx.core.enums import ActorType, ResourceType, TrustLevel
from guardx.core.resolvers import DefaultActorResolver, DefaultResourceResolver


def test_resource_resolver_file_idempotency(tmp_path):
    resolver = DefaultResourceResolver()
    workspace = str(tmp_path)
    sub = tmp_path / "sub"
    sub.mkdir()
    target = sub / "test.env"
    target.write_text("DEBUG=true\n")

    # Various raw representations of the same target file
    res1 = resolver.resolve_file("sub/test.env", workspace)
    res2 = resolver.resolve_file("./sub/test.env", workspace)
    res3 = resolver.resolve_file(f"{workspace}/sub/test.env", workspace)
    res4 = resolver.resolve_file(f"sub/../sub/test.env", workspace)

    assert res1.resource_id == res2.resource_id == res3.resource_id == res4.resource_id
    assert res1.resource_id == "file:sub/test.env"
    assert res1.resource_type == ResourceType.FILE
    assert res1.trust_level == TrustLevel.LOCAL


def test_resource_resolver_network():
    resolver = DefaultResourceResolver()

    # Localhost
    local_res = resolver.resolve_network("127.0.0.1", 8000)
    assert local_res.trust_level == TrustLevel.LOCAL
    assert local_res.resource_id == "net:127.0.0.1:8000"

    # External LLM
    llm_res = resolver.resolve_network("https://api.openai.com/v1/chat")
    assert llm_res.trust_level == TrustLevel.EXTERNAL_LLM
    assert llm_res.resource_id == "net:api.openai.com:443"

    # Untrusted Metadata IP
    meta_res = resolver.resolve_network("169.254.169.254", 80)
    assert meta_res.trust_level == TrustLevel.UNTRUSTED_EXTERNAL
    assert meta_res.resource_id == "net:169.254.169.254:80"


def test_actor_resolver():
    resolver = DefaultActorResolver()

    a1 = resolver.resolve_agent("opencode", "OpenCode Assistant")
    assert a1.actor_id == "agent:opencode"
    assert a1.actor_type == ActorType.AGENT
    assert a1.display_name == "OpenCode Assistant"

    u1 = resolver.resolve_user("alice")
    assert u1.actor_id == "user:alice"
    assert u1.actor_type == ActorType.USER

    t1 = resolver.resolve_tool("agentguard_read")
    assert t1.actor_id == "tool:agentguard_read"
    assert t1.actor_type == ActorType.TOOL
