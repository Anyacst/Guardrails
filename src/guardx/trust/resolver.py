"""Configurable TrustResolver for GuardX Milestone 4.

Maps resources, actors, files, process commands, network endpoints,
and LLM models/providers into concrete TrustLevel classifications.
"""

import fnmatch
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from guardx.trust.models import TrustLevel


class TrustResolver:
    """Resolves arbitrary resources, endpoints, and actors to their TrustLevel."""

    def __init__(
        self,
        trusted_internal_patterns: Optional[List[str]] = None,
        trusted_external_patterns: Optional[List[str]] = None,
        untrusted_external_patterns: Optional[List[str]] = None,
        workspace_root: str = "/workspace",
    ):
        self.workspace_root = workspace_root
        self.trusted_internal_patterns = trusted_internal_patterns or [
            "*.internal",
            "*.corp.internal",
            "*.company.net",
            "internal-vault.*",
            "10.*",
            "172.16.*",
            "192.168.*",
        ]
        self.trusted_external_patterns = trusted_external_patterns or [
            "api.github.com",
            "github.com",
            "registry.npmjs.org",
            "pypi.org",
        ]
        self.untrusted_external_patterns = untrusted_external_patterns or [
            "*evil*",
            "*attacker*",
            "*pastebin.com*",
            "*webhook.site*",
        ]

    def resolve(self, identifier: str) -> TrustLevel:
        """Determines the TrustLevel for an identifier (resource, actor, URL, LLM, or file)."""
        if not identifier:
            return TrustLevel.UNKNOWN

        clean_id = str(identifier).strip()

        # 1. LLM Models & Providers
        if clean_id.startswith("llm:") or any(
            p in clean_id.lower()
            for p in ("groq", "openai", "anthropic", "openrouter", "deepseek", "together", "ollama")
        ):
            # If specifically configured local model (e.g. ollama on localhost)
            if "localhost" in clean_id.lower() or "127.0.0.1" in clean_id.lower():
                return TrustLevel.LOCAL
            return TrustLevel.EXTERNAL_LLM

        # 2. Local Files & Process execution
        if clean_id.startswith("file:") or clean_id.startswith("/") or clean_id.startswith("./") or clean_id.startswith("."):
            return TrustLevel.LOCAL

        if clean_id.startswith("proc:") or clean_id.startswith("process:"):
            return TrustLevel.LOCAL

        if clean_id.startswith("user:") or clean_id.startswith("agent:") or clean_id.startswith("tool:"):
            return TrustLevel.LOCAL

        # 3. Local Network / Loopback
        for loopback in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
            if loopback in clean_id:
                return TrustLevel.LOCAL

        # 4. Extract hostname if network endpoint
        host = self._extract_host(clean_id)

        # 5. Check explicitly untrusted patterns
        for pattern in self.untrusted_external_patterns:
            if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(clean_id, pattern):
                return TrustLevel.UNTRUSTED_EXTERNAL

        # 6. Check trusted internal patterns
        for pattern in self.trusted_internal_patterns:
            if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(clean_id, pattern):
                return TrustLevel.TRUSTED_INTERNAL

        # 7. Check trusted external patterns
        for pattern in self.trusted_external_patterns:
            if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(clean_id, pattern):
                return TrustLevel.TRUSTED_EXTERNAL

        # 8. Network endpoint fallback
        if clean_id.startswith("net:") or clean_id.startswith("http://") or clean_id.startswith("https://") or "://" in clean_id:
            return TrustLevel.UNTRUSTED_EXTERNAL

        return TrustLevel.UNKNOWN

    def _extract_host(self, identifier: str) -> str:
        s = identifier
        if s.startswith("net:"):
            s = s[4:]
        if "://" not in s:
            s = f"http://{s}"
        try:
            parsed = urlparse(s)
            host = parsed.hostname or parsed.netloc or identifier
            return host.lower()
        except Exception:
            return identifier.lower()
