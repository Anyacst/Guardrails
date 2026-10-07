"""LLM Collector for GuardX Runtime Observation.

Captures:
- LLM_REQUEST
- LLM_RESPONSE
Attribution:
- Provenance Quality: OBSERVED
- Model, provider, destination, execution scope, causal linkage.
- Guarantees: Raw prompts and completions containing sensitive credentials pass through SafePayloadBuilder.
"""

from typing import Any, Dict, Optional
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import GuardXEvent
from guardx.collectors.base import BaseCollector


class LLMCollector(BaseCollector):
    """Observes LLM requests and completions."""

    @property
    def collector_name(self) -> str:
        return "llm_collector"

    def record_request(
        self,
        provider: str,
        model: str,
        prompt_preview: str,
        destination_endpoint: Optional[str] = None,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records an LLM_REQUEST observation."""
        meta = metadata or {}
        meta["provider"] = provider
        meta["model"] = model

        endpoint = destination_endpoint or f"https://api.{provider.lower()}.com/v1"

        payload = {
            "provider": provider,
            "model": model,
            "prompt_preview": prompt_preview[:1500],
            "endpoint": endpoint,
        }

        return self.emit_observation(
            event_type=EventType.LLM_REQUEST,
            raw_payload=payload,
            actor_id=actor_id,
            destination_raw=endpoint,
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )

    def record_response(
        self,
        provider: str,
        model: str,
        completion_preview: str,
        tokens_used: Optional[int] = None,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records an LLM_RESPONSE observation."""
        meta = metadata or {}
        meta["provider"] = provider
        meta["model"] = model
        if tokens_used is not None:
            meta["tokens_used"] = tokens_used

        endpoint = f"https://api.{provider.lower()}.com/v1"

        payload = {
            "provider": provider,
            "model": model,
            "completion_preview": completion_preview[:1500],
            "tokens_used": tokens_used,
        }

        return self.emit_observation(
            event_type=EventType.LLM_RESPONSE,
            raw_payload=payload,
            actor_id=actor_id,
            source_raw=endpoint,
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )
