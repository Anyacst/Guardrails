"""Tool Collector for GuardX Runtime Observation.

Captures:
- TOOL_CALL
- TOOL_RESULT
Attribution:
- Provenance Quality: OBSERVED (direct tool interception)
- Tool name, execution scope, causal linkage.
"""

from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import GuardXEvent
from guardx.collectors.base import BaseCollector


class ToolCollector(BaseCollector):
    """Observes tool calls and results, piping RawObservations into EventRecorder."""

    @property
    def collector_name(self) -> str:
        return "tool_collector"

    def record_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a TOOL_CALL observation."""
        meta = metadata or {}
        meta["tool_name"] = tool_name

        payload = {
            "tool_name": tool_name,
            "arguments": arguments,
        }

        return self.emit_observation(
            event_type=EventType.TOOL_CALL,
            raw_payload=payload,
            actor_id=actor_id,
            destination_raw=f"tool:{tool_name}",
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )

    def record_tool_result(
        self,
        tool_name: str,
        result_data: Any,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
        is_error: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a TOOL_RESULT observation."""
        meta = metadata or {}
        meta["tool_name"] = tool_name
        meta["is_error"] = is_error

        payload = {
            "tool_name": tool_name,
            "result": result_data,
            "is_error": is_error,
        }

        return self.emit_observation(
            event_type=EventType.TOOL_RESULT,
            raw_payload=payload,
            actor_id=f"tool:{tool_name}",
            source_raw=f"tool:{tool_name}",
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )

    @contextmanager
    def observe_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
    ) -> Iterator[GuardXEvent]:
        """Context manager wrapping a tool call and automatically recording TOOL_CALL and TOOL_RESULT."""
        call_event = self.record_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            actor_id=actor_id,
            causal_event_id=causal_event_id,
        )
        try:
            yield call_event
        except Exception as exc:
            self.record_tool_result(
                tool_name=tool_name,
                result_data={"error": str(exc)},
                actor_id=actor_id,
                causal_event_id=call_event.event_id,
                is_error=True,
            )
            raise
        else:
            self.record_tool_result(
                tool_name=tool_name,
                result_data={"status": "success"},
                actor_id=actor_id,
                causal_event_id=call_event.event_id,
                is_error=False,
            )
