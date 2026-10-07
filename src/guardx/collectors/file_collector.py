"""File Collector for GuardX Runtime Observation.

Captures:
- FILE_READ
- FILE_WRITE
Attribution:
- Provenance Quality: OBSERVED
- Canonical resource path, execution scope, causal linkage.
"""

from typing import Any, Dict, Optional
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import GuardXEvent
from guardx.collectors.base import BaseCollector


class FileCollector(BaseCollector):
    """Observes filesystem read and write actions."""

    @property
    def collector_name(self) -> str:
        return "file_collector"

    def record_file_read(
        self,
        file_path: str,
        content: Optional[str] = None,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a FILE_READ observation.
        
        NOTE: Any raw content passed is automatically passed through SafePayloadBuilder
        inside EventRecorder before persistence. Raw secrets are NEVER persisted.
        """
        meta = metadata or {}
        meta["operation"] = "READ"

        payload = {
            "file_path": file_path,
            "operation": "READ",
        }
        if content is not None:
            # Safe snippet preview
            payload["content"] = content[:1000] if len(content) > 1000 else content
            payload["size_bytes"] = len(content.encode("utf-8"))

        return self.emit_observation(
            event_type=EventType.FILE_READ,
            raw_payload=payload,
            actor_id=actor_id,
            source_raw=file_path,
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )

    def record_file_write(
        self,
        file_path: str,
        content: Optional[str] = None,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a FILE_WRITE observation."""
        meta = metadata or {}
        meta["operation"] = "WRITE"

        payload = {
            "file_path": file_path,
            "operation": "WRITE",
        }
        if content is not None:
            payload["content"] = content[:1000] if len(content) > 1000 else content
            payload["size_bytes"] = len(content.encode("utf-8"))

        return self.emit_observation(
            event_type=EventType.FILE_WRITE,
            raw_payload=payload,
            actor_id=actor_id,
            destination_raw=file_path,
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )
