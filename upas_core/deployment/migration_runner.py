"""
UPAS Safe Migration Runner.
Implements the MigrationOrchestrator protocol.
Enforces Invariant 4: Two-Phase Database Migration Protocol & Fail-Closed Safety (Exit Code 70).
"""

import os
import shlex
import time
from typing import List, Optional
from upas_core.contracts.enums import MigrationClassification, StepStatus
from upas_core.contracts.errors import MigrationError
from upas_core.contracts.execution import CommandSpec
from upas_core.contracts.interfaces import CommandRunner, MigrationOrchestrator
from upas_core.contracts.migrations import MigrationResult, MigrationSpec
from upas_core.execution.runner import SafeCommandRunner


def _safe_split_command(command_str: str) -> List[str]:
    """Safely splits a command string into argv list across Windows and POSIX."""
    if not command_str or not isinstance(command_str, str):
        return []
    is_posix = (os.name != "nt")
    tokens = shlex.split(command_str.strip(), posix=is_posix)
    if not is_posix:
        cleaned = []
        for t in tokens:
            if len(t) >= 2 and ((t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'"))):
                cleaned.append(t[1:-1])
            else:
                cleaned.append(t)
        return cleaned
    return tokens


class SafeMigrationRunner(MigrationOrchestrator):
    """
    Executes database migration hooks using SafeCommandRunner without shell injection.
    Supports pre-deploy and post-deploy finalize phases.
    """

    def __init__(self, runner: Optional[CommandRunner] = None, timeout_seconds: int = 120):
        self.runner = runner or SafeCommandRunner()
        self.timeout_seconds = timeout_seconds

    def _execute_hook(self, hook: Optional[str], phase_name: str) -> MigrationResult:
        if not hook or not hook.strip():
            return MigrationResult(
                phase=phase_name,
                status=StepStatus.PASS,
                exit_code=0,
                duration_ms=0,
            )

        # Parse command safely into argument list
        try:
            argv = _safe_split_command(hook)
        except Exception as exc:
            return MigrationResult(
                phase=phase_name,
                status=StepStatus.FAIL,
                exit_code=70,
                duration_ms=0,
                error_message=f"Failed to parse migration hook command '{hook}': {exc}",
            )

        spec = CommandSpec(argv=argv, timeout_seconds=self.timeout_seconds)
        start = time.monotonic()
        exec_res = self.runner.run(spec)
        duration_ms = int((time.monotonic() - start) * 1000)

        if not exec_res.is_success:
            err_msg = (
                f"Migration {phase_name} hook failed (exit {exec_res.exit_code}): "
                f"{exec_res.stderr or exec_res.stdout}"
            )
            return MigrationResult(
                phase=phase_name,
                status=StepStatus.FAIL,
                exit_code=70,
                duration_ms=duration_ms,
                error_message=err_msg,
            )

        return MigrationResult(
            phase=phase_name,
            status=StepStatus.PASS,
            exit_code=0,
            duration_ms=duration_ms,
        )

    def execute_pre_deploy(self, spec: MigrationSpec) -> MigrationResult:
        """Executes pre-deploy migration phase hook."""
        if not spec or not isinstance(spec, MigrationSpec):
            return MigrationResult(
                phase="pre_deploy",
                status=StepStatus.FAIL,
                exit_code=70,
                duration_ms=0,
                error_message="Invalid or missing MigrationSpec",
            )

        if spec.classification == MigrationClassification.NONE:
            return MigrationResult(
                phase="pre_deploy",
                status=StepStatus.PASS,
                exit_code=0,
                duration_ms=0,
            )

        return self._execute_hook(spec.pre_deploy_hook, "pre_deploy")

    def execute_post_deploy(self, spec: MigrationSpec) -> MigrationResult:
        """Executes post-deploy finalization phase hook."""
        if not spec or not isinstance(spec, MigrationSpec):
            return MigrationResult(
                phase="post_deploy_finalize",
                status=StepStatus.FAIL,
                exit_code=70,
                duration_ms=0,
                error_message="Invalid or missing MigrationSpec",
            )

        if spec.classification == MigrationClassification.NONE:
            return MigrationResult(
                phase="post_deploy_finalize",
                status=StepStatus.PASS,
                exit_code=0,
                duration_ms=0,
            )

        return self._execute_hook(spec.post_deploy_finalize_hook, "post_deploy_finalize")
