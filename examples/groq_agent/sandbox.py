"""Workspace Sandbox Confinement for GuardX Groq Demo Agent.

Guarantees:
- Strict confinement to examples/groq_agent/workspace/.
- Rejection of path traversal (../), absolute paths outside sandbox, and symlink escapes.
- Absolute prevention of accessing the project root .env or any host files.
"""

from pathlib import Path
from typing import Union


class SandboxSecurityError(PermissionError):
    """Raised when an operation violates workspace sandbox boundary."""
    pass


class WorkspaceSandbox:
    """Enforces strict path confinement within the designated workspace directory."""

    def __init__(self, workspace_root: Union[str, Path]):
        self.workspace_root = Path(workspace_root).resolve()
        if not self.workspace_root.exists():
            self.workspace_root.mkdir(parents=True, exist_ok=True)

    def resolve_safe_path(self, user_path: Union[str, Path]) -> Path:
        """Resolves user-supplied path and verifies it strictly resides within workspace.
        
        Raises:
            SandboxSecurityError: If path attempts to escape via .., absolute path, or symlink.
        """
        raw_str = str(user_path).strip()
        if not raw_str:
            return self.workspace_root

        # Reject obvious traversal attempts upfront
        if ".." in raw_str.split("/") or ".." in raw_str.split("\\"):
            raise SandboxSecurityError(
                f"Path traversal detected: '{user_path}' attempts to use '..' to escape sandbox"
            )

        p = Path(raw_str)

        # If user passed an absolute path, verify it is within workspace root
        if p.is_absolute():
            resolved = p.resolve()
        else:
            resolved = (self.workspace_root / p).resolve()

        # Strict containment check
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError:
            raise SandboxSecurityError(
                f"Sandbox violation: Resolved path '{resolved}' escapes workspace '{self.workspace_root}'"
            )

        # Check symlink destination if file exists
        if resolved.is_symlink():
            real_target = resolved.resolve()
            try:
                real_target.relative_to(self.workspace_root)
            except ValueError:
                raise SandboxSecurityError(
                    f"Symlink escape detected: Symlink '{resolved}' points outside workspace to '{real_target}'"
                )

        return resolved

    def relative_display_path(self, safe_path: Path) -> str:
        """Returns relative path string suitable for GuardX event tracking and display."""
        try:
            return str(safe_path.relative_to(self.workspace_root))
        except ValueError:
            return safe_path.name
