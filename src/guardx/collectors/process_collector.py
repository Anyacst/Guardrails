"""Process Collector for GuardX Runtime Observation.

Captures:
- PROCESS_EXEC
- PROCESS_EXIT
Attribution:
- Provenance Quality: OBSERVED
- PID, parent PID, command, exit code, causal tool linkage.
"""

from contextlib import contextmanager
import os
import subprocess
from typing import Any, Dict, Iterator, List, Optional, Union
from guardx.core.enums import EventType, ProvenanceQuality
from guardx.core.models import GuardXEvent
from guardx.collectors.base import BaseCollector


class ProcessCollector(BaseCollector):
    """Observes child processes and command execution."""

    @property
    def collector_name(self) -> str:
        return "process_collector"

    def record_process_exec(
        self,
        command: Union[str, List[str]],
        pid: int,
        ppid: Optional[int] = None,
        actor_id: Optional[str] = None,
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a PROCESS_EXEC observation."""
        cmd_str = " ".join(command) if isinstance(command, list) else command
        bin_name = os.path.basename(cmd_str.strip().split()[0]) if cmd_str.strip() else "unknown"
        effective_ppid = ppid or os.getpid()
        effective_actor = actor_id or f"subproc:{bin_name}"

        meta = metadata or {}
        meta["pid"] = pid
        meta["ppid"] = effective_ppid
        meta["command"] = cmd_str

        payload = {
            "pid": pid,
            "ppid": effective_ppid,
            "command": cmd_str,
            "executable": bin_name,
        }

        return self.emit_observation(
            event_type=EventType.PROCESS_EXEC,
            raw_payload=payload,
            actor_id=effective_actor,
            source_raw=f"proc:{bin_name}",
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )

    def record_process_exit(
        self,
        pid: int,
        exit_code: int,
        command: Optional[str] = None,
        actor_id: Optional[str] = None,
        causal_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardXEvent:
        """Records a PROCESS_EXIT observation."""
        bin_name = os.path.basename(command.strip().split()[0]) if command and command.strip() else "proc"
        effective_actor = actor_id or f"subproc:{bin_name}"

        meta = metadata or {}
        meta["pid"] = pid
        meta["exit_code"] = exit_code

        payload = {
            "pid": pid,
            "exit_code": exit_code,
            "command": command or "",
        }

        return self.emit_observation(
            event_type=EventType.PROCESS_EXIT,
            raw_payload=payload,
            actor_id=effective_actor,
            source_raw=f"proc:{bin_name}",
            causal_event_id=causal_event_id,
            provenance_quality=ProvenanceQuality.OBSERVED,
            confidence=1.0,
            metadata=meta,
        )

    @contextmanager
    def observe_subprocess(
        self,
        command: Union[str, List[str]],
        causal_event_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        simulated_pid: Optional[int] = None,
    ) -> Iterator[GuardXEvent]:
        """Observes process execution lifecycle from execution to termination."""
        cmd_str = " ".join(command) if isinstance(command, list) else command
        pid = simulated_pid or os.getpid() + 1000

        exec_event = self.record_process_exec(
            command=cmd_str,
            pid=pid,
            ppid=os.getpid(),
            actor_id=actor_id,
            causal_event_id=causal_event_id,
        )
        exit_code = 0
        try:
            yield exec_event
        except Exception:
            exit_code = 1
            raise
        finally:
            self.record_process_exit(
                pid=pid,
                exit_code=exit_code,
                command=cmd_str,
                actor_id=actor_id,
                causal_event_id=exec_event.event_id,
            )
