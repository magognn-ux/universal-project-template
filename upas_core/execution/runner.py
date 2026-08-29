"""
UPAS Safe Subprocess Runner.
Enforces Invariant 9: Safe Subprocess Execution.
Guarantees argument vector execution (no shell=True), strict timeout enforcement,
and complete recursive process-tree termination upon timeout.
"""

import os
import signal
import subprocess
import sys
import time
from typing import List, Optional
import psutil

from upas_core.contracts.enums import ExecutionStatus, ExitCode
from upas_core.contracts.execution import CommandSpec, ExecutionResult
from upas_core.contracts.interfaces import CommandRunner


def _kill_process_tree(pid: int) -> None:
    """
    Recursively terminates and kills all child processes of the given PID.
    Uses psutil with OS-specific fallbacks (taskkill on Windows, killpg on POSIX).
    """
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        try:
            parent.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    # Fallback cleanup
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass
    else:
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass


class SafeCommandRunner(CommandRunner):
    """
    Authoritative UPAS Subprocess Execution Engine.
    Executes commands safely using strict argv vectors with no shell interpolation.
    """

    def run(self, spec: CommandSpec) -> ExecutionResult:
        """
        Executes a subprocess specified by CommandSpec.
        Enforces timeout and returns structured ExecutionResult.
        """
        if not isinstance(spec, CommandSpec):
            raise TypeError(f"Expected CommandSpec, got {type(spec).__name__}")

        start_time = time.perf_counter()

        # Build execution environment if provided
        exec_env = os.environ.copy()
        if spec.env:
            exec_env.update(spec.env)

        popen_kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": spec.cwd,
            "env": exec_env,
            "shell": False,  # Strict invariant: no shell execution
        }

        # Process group isolation on POSIX
        if sys.platform != "win32":
            popen_kwargs["preexec_fn"] = os.setsid
        else:
            # On Windows: create separate process group if possible
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(spec.argv, **popen_kwargs)
        except FileNotFoundError as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ExecutionResult(
                status=ExecutionStatus.COMMAND_FAILED,
                exit_code=127,  # Standard command not found code
                stdout="",
                stderr=f"Executable not found: {exc}",
                duration_ms=duration_ms,
                command=list(spec.argv),
            )
        except PermissionError as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ExecutionResult(
                status=ExecutionStatus.COMMAND_FAILED,
                exit_code=126,  # Permission denied code
                stdout="",
                stderr=f"Permission denied: {exc}",
                duration_ms=duration_ms,
                command=list(spec.argv),
            )
        except Exception as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ExecutionResult(
                status=ExecutionStatus.COMMAND_FAILED,
                exit_code=1,
                stdout="",
                stderr=f"Failed to start process: {exc}",
                duration_ms=duration_ms,
                command=list(spec.argv),
            )

        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=spec.timeout_seconds)
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr_str = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
            exit_code = proc.returncode

            status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.COMMAND_FAILED
            return ExecutionResult(
                status=status,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_ms=duration_ms,
                command=list(spec.argv),
            )

        except subprocess.TimeoutExpired:
            # 1. Kill entire process tree
            _kill_process_tree(proc.pid)
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=2)
            except Exception:
                stdout_bytes, stderr_bytes = b"", b""

            duration_ms = int((time.perf_counter() - start_time) * 1000)
            stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr_str = (
                f"Command timed out after {spec.timeout_seconds}s. Process tree terminated.\n"
                + (stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else "")
            )

            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                exit_code=ExitCode.EXECUTION_TIMEOUT,  # Authoritative exit code 124
                stdout=stdout_str,
                stderr=stderr_str.strip(),
                duration_ms=duration_ms,
                command=list(spec.argv),
            )


def run_command(argv: List[str], timeout_seconds: int = 60, cwd: Optional[str] = None, env: Optional[dict] = None) -> ExecutionResult:
    """Convenience functional interface for safe command execution."""
    spec = CommandSpec(argv=argv, timeout_seconds=timeout_seconds, cwd=cwd, env=env)
    runner = SafeCommandRunner()
    return runner.run(spec)
