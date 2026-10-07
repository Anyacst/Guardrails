"""Network Collector for GuardX Runtime Observation.

Captures:
- NETWORK_REQUEST
- NETWORK_RESPONSE
Attribution:
- Provenance Quality: OBSERVED
- Destination URL/host, port, HTTP method, status code.
- Guarantees: Authorization headers, cookies, tokens sanitized via SafePayloadBuilder.
"""

from typing import Any, Dict, Optional
from urllib.parse import urlparse
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import GuardXEvent
from guardx.collectors.base import BaseCollector


class NetworkCollector(BaseCollector):
    """Observes outbound HTTP requests and network transmissions."""

    @property
    def collector_name(self) -> str:
        return "network_collector"

    def record_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body_preview: Optional[str] = None,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a NETWORK_REQUEST observation.
        
        All headers and body preview pass through the SafePayloadBuilder boundary.
        """
        parsed = urlparse(url)
        host = parsed.netloc or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        meta = metadata or {}
        meta["host"] = host
        meta["port"] = port
        meta["method"] = method.upper()

        payload = {
            "url": url,
            "host": host,
            "port": port,
            "method": method.upper(),
        }
        if headers:
            payload["headers"] = headers
        if body_preview:
            payload["body_preview"] = body_preview[:1000]

        return self.emit_observation(
            event_type=EventType.NETWORK_REQUEST,
            raw_payload=payload,
            actor_id=actor_id,
            destination_raw=f"net:{host}:{port}",
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )

    def record_response(
        self,
        url: str,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        response_preview: Optional[str] = None,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a NETWORK_RESPONSE observation."""
        parsed = urlparse(url)
        host = parsed.netloc or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        meta = metadata or {}
        meta["host"] = host
        meta["status_code"] = status_code

        payload = {
            "url": url,
            "host": host,
            "status_code": status_code,
        }
        if headers:
            payload["headers"] = headers
        if response_preview:
            payload["response_preview"] = response_preview[:1000]

        return self.emit_observation(
            event_type=EventType.NETWORK_RESPONSE,
            raw_payload=payload,
            actor_id=actor_id,
            source_raw=f"net:{host}:{port}",
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )
