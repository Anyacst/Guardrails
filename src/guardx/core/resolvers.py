"""Canonical Identity Resolvers for Resources and Actors.

Guarantees:
- INV-007: Idempotent canonicalization (relative paths, symlinks, host variations map to stable IDs)
- Eliminates duplicate graph nodes.
"""

import os
from typing import Optional
from urllib.parse import urlparse

from guardx.core.enums import ActorType, ResourceType, TrustLevel
from guardx.core.interfaces import ActorResolver, ResourceResolver
from guardx.core.models import Actor, Resource


class DefaultResourceResolver(ResourceResolver):
    """Canonical resolver for files, network endpoints, tools, and processes."""

    def resolve_file(self, raw_path: str, workspace_root: str) -> Resource:
        """Resolves file path to canonical relative URI and LOCAL trust level."""
        # Expand user and realpath
        abs_workspace = os.path.realpath(os.path.abspath(workspace_root))
        
        # If relative, join with workspace
        if not os.path.isabs(raw_path):
            target_abs = os.path.realpath(os.path.abspath(os.path.join(abs_workspace, raw_path)))
        else:
            target_abs = os.path.realpath(os.path.abspath(raw_path))

        # Check if inside workspace
        try:
            rel_path = os.path.relpath(target_abs, abs_workspace)
            if not rel_path.startswith(".."):
                uri = f"file://{rel_path.replace(os.sep, '/')}"
                resource_id = f"file:{rel_path.replace(os.sep, '/')}"
                return Resource(
                    resource_id=resource_id,
                    resource_type=ResourceType.FILE,
                    uri=uri,
                    trust_level=TrustLevel.LOCAL,
                    metadata={"abs_path": target_abs, "is_workspace_local": True},
                )
        except ValueError:
            pass

        # Outside workspace
        uri = f"file://{target_abs.replace(os.sep, '/')}"
        resource_id = f"file:{target_abs.replace(os.sep, '/')}"
        return Resource(
            resource_id=resource_id,
            resource_type=ResourceType.FILE,
            uri=uri,
            trust_level=TrustLevel.LOCAL,
            metadata={"abs_path": target_abs, "is_workspace_local": False},
        )

    def resolve_network(self, host: str, port: Optional[int] = None) -> Resource:
        """Resolves host/port or URL into canonical network endpoint resource."""
        clean_host = host.strip().lower()
        if clean_host.startswith(("http://", "https://")):
            parsed = urlparse(clean_host)
            net_host = parsed.hostname or clean_host
            net_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        else:
            if ":" in clean_host and not clean_host.startswith("["):
                parts = clean_host.split(":", 1)
                net_host = parts[0]
                try:
                    net_port = int(parts[1])
                except ValueError:
                    net_port = port or 80
            else:
                net_host = clean_host
                net_port = port or 443

        # Default trust evaluation
        if net_host in ("127.0.0.1", "localhost", "::1"):
            trust = TrustLevel.LOCAL
        elif net_host.endswith((".internal", ".corp", ".local")):
            trust = TrustLevel.TRUSTED_INTERNAL
        elif "api.openai.com" in net_host or "api.anthropic.com" in net_host or "openrouter.ai" in net_host:
            trust = TrustLevel.EXTERNAL_LLM
        elif net_host in ("169.254.169.254", "metadata.google.internal"):
            trust = TrustLevel.UNTRUSTED_EXTERNAL
        else:
            trust = TrustLevel.UNTRUSTED_EXTERNAL

        resource_id = f"net:{net_host}:{net_port}"
        uri = f"https://{net_host}:{net_port}" if net_port == 443 else f"tcp://{net_host}:{net_port}"

        return Resource(
            resource_id=resource_id,
            resource_type=ResourceType.NETWORK_ENDPOINT,
            uri=uri,
            trust_level=trust,
            metadata={"host": net_host, "port": net_port},
        )

    def resolve_tool(self, tool_name: str) -> Resource:
        """Resolves tool name to canonical tool resource."""
        canonical_name = tool_name.strip().lower().replace("-", "_")
        return Resource(
            resource_id=f"tool:{canonical_name}",
            resource_type=ResourceType.TOOL,
            uri=f"tool://{canonical_name}",
            trust_level=TrustLevel.LOCAL,
            metadata={"tool_name": canonical_name},
        )

    def resolve_process(self, command: str) -> Resource:
        """Resolves process command to canonical process resource."""
        clean_cmd = command.strip().split()[0] if command.strip() else "unknown"
        base_cmd = os.path.basename(clean_cmd).lower()
        return Resource(
            resource_id=f"proc:{base_cmd}",
            resource_type=ResourceType.PROCESS,
            uri=f"process://{base_cmd}",
            trust_level=TrustLevel.LOCAL,
            metadata={"command": command},
        )


class DefaultActorResolver(ActorResolver):
    """Canonical resolver for users, agents, tools, and subprocesses."""

    def resolve_agent(self, agent_id: str, display_name: Optional[str] = None) -> Actor:
        canonical_id = f"agent:{agent_id.strip().lower()}"
        if display_name:
            name = display_name
        elif canonical_id == "agent:opencode":
            name = "OpenCode"
        else:
            name = agent_id.capitalize()
        return Actor(
            actor_id=canonical_id,
            actor_type=ActorType.AGENT,
            display_name=name,
        )

    def resolve_user(self, user_id: str, display_name: Optional[str] = None) -> Actor:
        canonical_id = f"user:{user_id.strip().lower()}"
        name = display_name or user_id
        return Actor(
            actor_id=canonical_id,
            actor_type=ActorType.USER,
            display_name=name,
        )

    def resolve_tool(self, tool_name: str) -> Actor:
        canonical_id = f"tool:{tool_name.strip().lower()}"
        return Actor(
            actor_id=canonical_id,
            actor_type=ActorType.TOOL,
            display_name=tool_name,
        )

    def resolve_subprocess(self, command: str) -> Actor:
        clean = command.strip().split()[0] if command.strip() else "unknown"
        base = os.path.basename(clean).lower()
        return Actor(
            actor_id=f"subproc:{base}",
            actor_type=ActorType.SUBPROCESS,
            display_name=base,
            metadata={"full_command": command},
        )
