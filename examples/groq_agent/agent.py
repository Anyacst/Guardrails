"""Groq Tool-Calling AI Demo Agent for GuardX Investigation Console.

This agent is a standalone test harness to generate real LLM and tool operations.
All activity is observed via GuardX collectors and captured into the Live Provenance DAG.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from guardx.collectors.file_collector import FileCollector
from guardx.collectors.llm_collector import LLMCollector
from guardx.collectors.tool_collector import ToolCollector
from guardx.core.enums import EventType
from guardx.core.models import RawObservation
from guardx.server.session_registry import SessionContext, global_session_registry
from examples.groq_agent.sandbox import WorkspaceSandbox
from examples.groq_agent.tools import AgentToolExecutor, GROQ_TOOL_DEFINITIONS


DEFAULT_MODEL = "openai/gpt-oss-120b"
MAX_TOOL_ROUNDS = 10
AGENT_ACTOR_ID = "agent:groq_agent"


def get_default_workspace_dir() -> Path:
    """Returns the absolute path to the sandbox workspace."""
    return Path(__file__).resolve().parent / "workspace"


def load_project_groq_api_key() -> Optional[str]:
    """Loads GROQ_API_KEY from os.environ or project root .env without exposing it."""
    # 1. Check environment variable
    key = os.getenv("GROQ_API_KEY")
    if key and key.strip():
        return key.strip()

    # 2. Check project root .env
    project_env = Path(__file__).resolve().parent.parent.parent / ".env"
    if project_env.exists():
        try:
            with open(project_env, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("GROQ_API_KEY=") and not line.startswith("#"):
                        val = line.split("=", 1)[1].strip().strip("'\"")
                        if val:
                            return val
        except Exception:
            pass

    return None


class GroqAgent:
    """Minimal tool-calling agent observed by GuardX."""

    def __init__(
        self,
        session_context: Optional[SessionContext] = None,
        workspace_dir: Optional[Union[str, Path]] = None,
        model: str = DEFAULT_MODEL,
        groq_client: Optional[Any] = None,
        api_key: Optional[str] = None,
    ):
        self.workspace_dir = Path(workspace_dir or get_default_workspace_dir()).resolve()
        self.sandbox = WorkspaceSandbox(self.workspace_dir)
        self.model = model

        # Attach to or create session context
        if session_context:
            self.session_ctx = session_context
        else:
            self.session_ctx = global_session_registry.create_session(
                session_id="groq_agent_live_session",
                agent_name="GroqAgent",
                workspace_root=str(self.workspace_dir),
            )

        # Wire GuardX collectors
        self.recorder = self.session_ctx.recorder
        self.scope_manager = self.session_ctx.scope_manager
        self.tool_collector = ToolCollector(self.recorder)
        self.file_collector = FileCollector(self.recorder)
        self.llm_collector = LLMCollector(self.recorder)

        # Wire tool executor
        self.executor = AgentToolExecutor(
            sandbox=self.sandbox,
            tool_collector=self.tool_collector,
            file_collector=self.file_collector,
            scope_manager=self.scope_manager,
            agent_id=AGENT_ACTOR_ID,
            enforcement_gateway=getattr(self.session_ctx, "enforcement_gateway", None),
            session_id=self.session_ctx.session.session_id,
        )

        # Groq client initialization
        if groq_client:
            self.client = groq_client
        else:
            resolved_key = api_key or load_project_groq_api_key()
            if resolved_key:
                from groq import Groq
                self.client = Groq(api_key=resolved_key)
            else:
                self.client = None

    def run(self, user_prompt: str) -> Dict[str, Any]:
        """Runs the complete agent task loop with hierarchical GuardX scopes."""
        # 1. Record USER_INPUT
        user_evt = self.recorder.record(RawObservation(
            event_type=EventType.USER_INPUT,
            raw_payload={"prompt": user_prompt},
            actor_id="user:operator",
        ))

        chat_messages: List[Dict[str, Any]] = [
            {
                "role": "system",
                "content": (
                    "You are a helpful coding assistant running in a sandboxed workspace. "
                    "You have tools: list_files, read_file, and write_file. "
                    "Inspect files as needed and summarize your findings."
                ),
            },
            {"role": "user", "content": user_prompt},
        ]

        last_causal_id = user_evt.event_id
        final_answer = ""
        rounds_executed = 0

        # 2. Open root agent_task scope
        with self.scope_manager.scope("agent_task", originating_event_id=user_evt.event_id):
            while rounds_executed < MAX_TOOL_ROUNDS:
                rounds_executed += 1
                round_scope_name = f"llm_round_{rounds_executed}"

                with self.scope_manager.scope(round_scope_name, originating_event_id=last_causal_id):
                    # Record LLM_REQUEST
                    prompt_summary = f"Messages: {len(chat_messages)}, Last: {chat_messages[-1]['role']}"
                    llm_req_evt = self.llm_collector.record_request(
                        provider="Groq",
                        model=self.model,
                        prompt_preview=prompt_summary,
                        actor_id=AGENT_ACTOR_ID,
                        causal_event_id=last_causal_id,
                    )

                    # Execute Groq LLM completion
                    response_obj = self._call_groq(chat_messages)

                    # Extract completion details safely
                    usage_obj = getattr(response_obj, "usage", None)
                    if usage_obj is not None:
                        tokens_used = getattr(usage_obj, "total_tokens", None) or (usage_obj.get("total_tokens", 100) if isinstance(usage_obj, dict) else 100)
                    else:
                        tokens_used = 100
                    choice = response_obj.choices[0]
                    message = choice.message
                    completion_text = message.content or ""
                    tool_calls = getattr(message, "tool_calls", None) or []

                    completion_summary = completion_text[:200] if completion_text else f"Requested {len(tool_calls)} tool calls"

                    # Record LLM_RESPONSE
                    llm_resp_evt = self.llm_collector.record_response(
                        provider="Groq",
                        model=self.model,
                        completion_preview=completion_summary,
                        tokens_used=tokens_used,
                        actor_id=AGENT_ACTOR_ID,
                        causal_event_id=llm_req_evt.event_id,
                    )
                    last_causal_id = llm_resp_evt.event_id

                    # If model returned no tool calls, task is finished
                    if not tool_calls:
                        final_answer = completion_text
                        break

                    # Append assistant message with tool calls to conversation history
                    assistant_msg: Dict[str, Any] = {
                        "role": "assistant",
                        "content": completion_text,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            }
                            for tc in tool_calls
                        ],
                    }
                    chat_messages.append(assistant_msg)

                    # Execute each tool call within its own execution scope
                    for tc in tool_calls:
                        tool_name = tc.function.name
                        try:
                            tool_args = json.loads(tc.function.arguments) if isinstance(tc.function.arguments, str) else tc.function.arguments
                        except Exception:
                            tool_args = {}

                        tool_res = self.executor.execute_tool(
                            tool_name=tool_name,
                            arguments=tool_args,
                            causal_event_id=llm_resp_evt.event_id,
                        )

                        chat_messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "name": tool_name,
                            "content": json.dumps(tool_res),
                        })

        return {
            "status": "completed",
            "session_id": self.session_ctx.session.session_id,
            "rounds": rounds_executed,
            "final_answer": final_answer,
            "event_count": len(self.recorder.get_history()),
        }

    def _call_groq(self, messages: List[Dict[str, Any]]) -> Any:
        """Invokes Groq API through EnforcementGateway prospective guardrail."""
        if not self.client:
            raise RuntimeError(
                "Groq client is not initialized. Please configure GROQ_API_KEY in .env or pass a mock client."
            )

        if hasattr(self.session_ctx, "enforcement_gateway") and self.session_ctx.enforcement_gateway:
            from guardx.enforcement.models import ActionType, ProspectiveAction
            from guardx.trust.models import TrustTier

            prospective_action = ProspectiveAction.create(
                session_id=self.session_ctx.session.session_id,
                action_type=ActionType.LLM_REQUEST,
                destination=f"groq:{self.model}",
                operation="chat.completions.create",
                actor_id=AGENT_ACTOR_ID,
                source=AGENT_ACTOR_ID,
                tool_name=None,
                safe_payload={
                    "model": self.model,
                    "messages_count": len(messages),
                    "last_role": messages[-1]["role"] if messages else "",
                },
                destination_trust=TrustTier.EXTERNAL_LLM,
                execution_scope_id=self.scope_manager.current_scope_id,
            )

            def groq_executor(sanitized_messages=None):
                msgs_to_send = sanitized_messages if sanitized_messages is not None else messages
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=msgs_to_send,
                    tools=GROQ_TOOL_DEFINITIONS,
                    tool_choice="auto",
                )

            return self.session_ctx.enforcement_gateway.execute(
                action=prospective_action,
                executor=groq_executor,
                raw_content=messages,
            )

        return self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=GROQ_TOOL_DEFINITIONS,
            tool_choice="auto",
        )
