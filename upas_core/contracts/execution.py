"""
UPAS Execution Contracts.
Safe subprocess execution specifications and result models.
Explicitly prohibits shell execution (shell=False invariant).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from upas_core.contracts.enums import ExecutionStatus


@dataclass(frozen=True)
class CommandSpec:
    """
    Specification for safe subprocess execution.
    argv MUST be a list of string arguments (no shell injection, no raw shell string).
    """
    argv: List[str]
    timeout_seconds: int
    cwd: Optional[str] = None
    env: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if not isinstance(self.argv, list):
            raise TypeError("CommandSpec.argv must be a list of strings, not a raw string or shell command")
        if not self.argv:
            raise ValueError("CommandSpec.argv cannot be empty")
        for i, arg in enumerate(self.argv):
            if not isinstance(arg, str):
                raise TypeError(f"CommandSpec.argv[{i}] must be a str, got {type(arg).__name__}")
        if self.timeout_seconds <= 0:
            raise ValueError("CommandSpec.timeout_seconds must be a positive integer > 0")


@dataclass(frozen=True)
class ExecutionResult:
    """Structured result of a subprocess command execution."""
    status: ExecutionStatus
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    command: List[str]

    @property
    def is_success(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS and self.exit_code == 0

    @property
    def is_timeout(self) -> bool:
        return self.status == ExecutionStatus.TIMEOUT

    @property
    def is_unknown_remote_state(self) -> bool:
        return self.status == ExecutionStatus.UNKNOWN_REMOTE_STATE
