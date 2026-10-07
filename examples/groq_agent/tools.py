"""Tool definitions and implementations for the Groq Demo Agent.

Tools:
- list_files(path=".")
- read_file(path)
- write_file(path, content)

Instrumented via GuardX ToolCollector and FileCollector.
Strictly confined by WorkspaceSandbox.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardx.collectors.file_collector import FileCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.context import ScopeManager
from examples.groq_agent.sandbox import SandboxSecurityError, WorkspaceSandbox


GROQ_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "Lists all files and subdirectories in the specified workspace directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative directory path within workspace (default: '.')"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Reads the plain text contents of a file inside the workspace sandbox.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path of the file to read (e.g. 'config.py', '.env')"
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Writes text contents to a file inside the workspace sandbox.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path of the file to write (e.g. 'summary.txt')"
                    },
                    "content": {
                        "type": "string",
                        "description": "The exact text contents to write into the file"
                    }
                },
                "required": ["path", "content"]
            }
        }
    }
]


class AgentToolExecutor:
    """Executes agent tools safely within the sandbox while capturing GuardX provenance."""

    def __init__(
        self,
        sandbox: WorkspaceSandbox,
        tool_collector: ToolCollector,
        file_collector: FileCollector,
        scope_manager: ScopeManager,
        agent_id: str = "agent:groq_agent",
        enforcement_gateway: Optional[Any] = None,
        session_id: str = "groq_agent_live_session",
    ):
        self.sandbox = sandbox
        self.tool_collector = tool_collector
        self.file_collector = file_collector
        self.scope_manager = scope_manager
        self.agent_id = agent_id
        self.enforcement_gateway = enforcement_gateway
        self.session_id = session_id

    def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        causal_event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes a tool within a dedicated execution scope and records all provenance."""
        scope_name = f"tool:{tool_name}"
        actor_tool_id = f"tool:{tool_name}"

        with self.scope_manager.scope(scope_name, originating_event_id=causal_event_id):
            # 1. Record TOOL_CALL
            tool_call_evt = self.tool_collector.record_tool_call(
                tool_name=tool_name,
                arguments=arguments,
                actor_id=self.agent_id,
                causal_event_id=causal_event_id,
            )

            result: Dict[str, Any] = {}
            try:
                if tool_name == "list_files":
                    raw_path = arguments.get("path", ".")
                    result = self._list_files(raw_path)

                elif tool_name == "read_file":
                    raw_path = arguments.get("path", "")
                    result = self._read_file(raw_path, tool_call_evt_id=tool_call_evt.event_id)

                elif tool_name == "write_file":
                    raw_path = arguments.get("path", "")
                    content = arguments.get("content", "")
                    result = self._write_file(raw_path, content, tool_call_evt_id=tool_call_evt.event_id)

                else:
                    result = {"error": f"Unknown tool: {tool_name}"}

            except SandboxSecurityError as sec_err:
                result = {"error": f"Security violation: {str(sec_err)}"}
            except Exception as ex:
                result = {"error": f"Tool execution failed: {str(ex)}"}

            # 2. Record TOOL_RESULT
            self.tool_collector.record_tool_result(
                tool_name=tool_name,
                result_data=result,
                actor_id=actor_tool_id,
                causal_event_id=tool_call_evt.event_id,
            )

            return result

    def _list_files(self, rel_path: str) -> Dict[str, Any]:
        safe_dir = self.sandbox.resolve_safe_path(rel_path)
        if not safe_dir.exists() or not safe_dir.is_dir():
            return {"error": f"Directory not found: {rel_path}"}

        entries = []
        for item in sorted(safe_dir.iterdir()):
            entries.append({
                "name": item.name,
                "is_dir": item.is_dir(),
                "size_bytes": item.stat().st_size if item.is_file() else 0,
            })
        return {"directory": self.sandbox.relative_display_path(safe_dir), "items": entries}

    def _read_file(self, rel_path: str, tool_call_evt_id: str) -> Dict[str, Any]:
        safe_file = self.sandbox.resolve_safe_path(rel_path)
        if not safe_file.exists():
            return {"error": f"File does not exist: {rel_path}"}
        if safe_file.is_dir():
            return {"error": f"Path is a directory, not a file: {rel_path}"}

        content = safe_file.read_text(encoding="utf-8", errors="replace")
        disp_path = self.sandbox.relative_display_path(safe_file)

        # Record FILE_READ observation
        self.file_collector.record_file_read(
            file_path=disp_path,
            content=content,
            actor_id=f"tool:read_file",
            causal_event_id=tool_call_evt_id,
        )

        return {"path": disp_path, "content": content}

    def _write_file(self, rel_path: str, content: str, tool_call_evt_id: str) -> Dict[str, Any]:
        safe_file = self.sandbox.resolve_safe_path(rel_path)
        if safe_file.exists() and safe_file.is_dir():
            return {"error": f"Cannot overwrite directory with file: {rel_path}"}

        disp_path = self.sandbox.relative_display_path(safe_file)

        # Prospective enforcement before filesystem modification (INV-M5-001, Section 25)
        if self.enforcement_gateway:
            from guardx.enforcement.models import ActionType, ProspectiveAction
            from guardx.trust.models import TrustTier

            prospective_action = ProspectiveAction.create(
                session_id=self.session_id,
                action_type=ActionType.FILE_WRITE,
                destination=disp_path,
                operation="write_file",
                actor_id=self.agent_id,
                source=self.agent_id,
                tool_name="write_file",
                safe_payload={"path": disp_path, "bytes_count": len(content.encode("utf-8"))},
                destination_trust=TrustTier.LOCAL,
                execution_scope_id=self.scope_manager.current_scope_id,
            )

            def filesystem_write_executor(sanitized_content=None):
                content_to_write = sanitized_content if sanitized_content is not None else content
                safe_file.parent.mkdir(parents=True, exist_ok=True)
                safe_file.write_text(content_to_write, encoding="utf-8")
                return content_to_write

            # If blocked: ActionBlockedError raised here, write_text NEVER called
            actual_content = self.enforcement_gateway.execute(
                action=prospective_action,
                executor=filesystem_write_executor,
                raw_content=content,
            )
        else:
            safe_file.parent.mkdir(parents=True, exist_ok=True)
            safe_file.write_text(content, encoding="utf-8")
            actual_content = content

        # Record FILE_WRITE observation after actual execution
        self.file_collector.record_file_write(
            file_path=disp_path,
            content=actual_content,
            actor_id=f"tool:write_file",
            causal_event_id=tool_call_evt_id,
        )

        return {"path": disp_path, "status": "written", "bytes_written": len(actual_content.encode("utf-8"))}
