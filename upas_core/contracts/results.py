"""
UPAS Operation Result Models.
Explicit structured return types for all major runtime primitives (no ambiguous booleans).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from upas_core.contracts.enums import ExitCode, StepStatus


@dataclass(frozen=True)
class StepResult:
    """Standard execution result for individual lifecycle steps."""
    name: str
    status: StepStatus
    exit_code: int
    duration_ms: int
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == StepStatus.PASS and self.exit_code == 0


@dataclass(frozen=True)
class LockHandle:
    """Handle representing an acquired host lock."""
    lock_path: str
    owner_pid: int
    kernel_timestamp: str
    timeout_seconds: int


@dataclass(frozen=True)
class LockResult:
    """Structured result of host lock acquisition attempt."""
    acquired: bool
    lock_path: str
    owner_pid: int
    kernel_timestamp: str
    timeout_seconds: int
    stale_reclaimed: bool = False
    handle: Optional[LockHandle] = None
    error_message: Optional[str] = None
    exit_code: ExitCode = ExitCode.SUCCESS

    def __post_init__(self):
        if self.acquired:
            if self.exit_code != ExitCode.SUCCESS:
                raise ValueError("LockResult cannot be acquired with non-zero exit code")
            if not self.handle:
                raise ValueError("LockResult acquired must provide a LockHandle")
        else:
            if self.exit_code == ExitCode.SUCCESS:
                raise ValueError("LockResult not acquired cannot have ExitCode.SUCCESS")
            if not self.error_message:
                raise ValueError("LockResult failure must provide an error_message")


@dataclass(frozen=True)
class PreflightResult:
    """Result of pre-flight host resource gate inspection."""
    passed: bool
    ram_free_mb: float
    swap_usage_pct: float
    load_1m: float
    disk_free_gb: float
    missing_containers: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    exit_code: ExitCode = ExitCode.SUCCESS

    def __post_init__(self):
        if self.passed and self.exit_code != ExitCode.SUCCESS:
            raise ValueError("PreflightResult cannot be passed with non-zero exit code")
        if not self.passed and self.exit_code == ExitCode.SUCCESS:
            raise ValueError("PreflightResult failed cannot have ExitCode.SUCCESS")


@dataclass(frozen=True)
class GuardResult:
    """Result of infrastructure boundary guard check."""
    allowed: bool
    target_resource: str
    access_mode: str
    violation_type: Optional[str] = None
    error_message: Optional[str] = None
    exit_code: ExitCode = ExitCode.SUCCESS

    def __post_init__(self):
        if self.allowed and self.exit_code != ExitCode.SUCCESS:
            raise ValueError("GuardResult allowed cannot have non-zero exit code")
        if not self.allowed and self.exit_code == ExitCode.SUCCESS:
            raise ValueError("GuardResult blocked cannot have ExitCode.SUCCESS")


@dataclass(frozen=True)
class CompatibilityResult:
    """Result of Core/Adapter version compatibility evaluation."""
    compatible: bool
    core_version: str
    target_constraint: str
    error_message: Optional[str] = None
    exit_code: ExitCode = ExitCode.SUCCESS

    def __post_init__(self):
        if self.compatible and self.exit_code != ExitCode.SUCCESS:
            raise ValueError("CompatibilityResult compatible cannot have non-zero exit code")
        if not self.compatible and self.exit_code == ExitCode.SUCCESS:
            raise ValueError("CompatibilityResult incompatible cannot have ExitCode.SUCCESS")
