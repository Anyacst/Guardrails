"""GuardX OpenCode Reference Integration Adapter.

Bridges OpenCode agent tool calls to GuardX collectors and ProvenanceEngine
while strictly preserving AgentGuard's existing tokenization and sensitive file protections.

Pipeline:
OpenCode
   ↓
agentguard_read(".env")
   ↓ (Scope: tool:agentguard_read)
TOOL_CALL
   ↓
FILE_READ (tokenized/safe)
   ↓
TOOL_RESULT (returned to OpenCode context)
"""

import os
from typing import Any, Dict, Optional

from guardx.collectors.file_collector import FileCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.context import ScopeManager
from guardx.core.models import Session
from guardx.core.recorder import EventRecorder

# Import AgentGuard FileInterceptor if available
try:
    from agentguard.engine.token_store import canonicalize_path
    from agentguard.interceptors.file_interceptor import FileInterceptor, global_file_interceptor
    HAS_AGENTGUARD = True
except ImportError:
    HAS_AGENTGUARD = False
    global_file_interceptor = None


class OpenCodeGuardXAdapter:
    """Thin non-invasive adapter capturing OpenCode tool actions into GuardX execution provenance."""

    def __init__(
        self,
        recorder: EventRecorder,
        scope_manager: Optional[ScopeManager] = None,
        file_interceptor: Optional[Any] = None,
    ):
        self.recorder = recorder
        self.scope_manager = scope_manager or ScopeManager(recorder=recorder)
        self.tool_collector = ToolCollector(recorder=recorder)
        self.file_collector = FileCollector(recorder=recorder)
        self.file_interceptor = file_interceptor or (global_file_interceptor if HAS_AGENTGUARD else None)

    def execute_agentguard_read(
        self,
        file_path: str,
        actor_id: str = "agent:opencode",
        causal_event_id: Optional[str] = None,
    ) -> str:
        """Executes secure file read with full GuardX provenance tracking.
        
        Preserves AgentGuard tokenization while emitting:
        - SCOPE_START(tool:agentguard_read)
        - TOOL_CALL(agentguard_read)
        - FILE_READ(file_path)
        - TOOL_RESULT(tokenized_content)
        - SCOPE_END(tool:agentguard_read)
        """
        # 1. Open Tool Execution Scope
        with self.scope_manager.scope(
            scope_name="tool:agentguard_read",
            originating_event_id=causal_event_id,
        ) as scope:

            # 2. Record TOOL_CALL
            tool_call_evt = self.tool_collector.record_tool_call(
                tool_name="agentguard_read",
                arguments={"path": file_path},
                actor_id=actor_id,
                causal_event_id=causal_event_id,
            )

            # 3. Perform reading (using AgentGuard interceptor if present, else safe local read)
            if self.file_interceptor:
                canon_path = os.path.realpath(os.path.abspath(file_path))
                protected = self.file_interceptor.intercept_read(
                    canon_path, session_id=self.recorder.session.session_id
                )
                safe_content = protected.content
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    safe_content = f.read()

            # 4. Record FILE_READ observation
            file_read_evt = self.file_collector.record_file_read(
                file_path=file_path,
                content=safe_content,
                actor_id="tool:agentguard_read",
                causal_event_id=tool_call_evt.event_id,
            )

            # 5. Record TOOL_RESULT observation
            self.tool_collector.record_tool_result(
                tool_name="agentguard_read",
                result_data={"content": safe_content, "file_path": file_path},
                actor_id="tool:agentguard_read",
                causal_event_id=file_read_evt.event_id,
            )

            return safe_content
