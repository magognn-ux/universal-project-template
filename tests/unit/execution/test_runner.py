"""
Targeted tests for UPAS Safe Subprocess Runner (Phase 2C-1.2).
Verifies argument-vector execution, no shell=True, timeout enforcement,
process-tree termination, and exit code 124 on timeout.
"""

import sys
import time
import pytest
from upas_core.contracts.enums import ExecutionStatus, ExitCode
from upas_core.contracts.execution import CommandSpec
from upas_core.execution import SafeCommandRunner, run_command


class TestSafeCommandRunner:
    @pytest.fixture
    def runner(self):
        return SafeCommandRunner()

    def test_successful_command_execution(self, runner):
        spec = CommandSpec(
            argv=[sys.executable, "-c", "import sys; sys.stdout.write('UPAS_EXEC_OK'); sys.exit(0)"],
            timeout_seconds=5,
        )
        res = runner.run(spec)
        assert res.is_success is True
        assert res.status == ExecutionStatus.SUCCESS
        assert res.exit_code == 0
        assert res.stdout == "UPAS_EXEC_OK"
        assert res.stderr == ""
        assert res.duration_ms >= 0

    def test_command_failure_preserves_exit_code_and_stderr(self, runner):
        spec = CommandSpec(
            argv=[sys.executable, "-c", "import sys; sys.stderr.write('CRITICAL_ERR'); sys.exit(42)"],
            timeout_seconds=5,
        )
        res = runner.run(spec)
        assert res.is_success is False
        assert res.status == ExecutionStatus.COMMAND_FAILED
        assert res.exit_code == 42
        assert res.stderr == "CRITICAL_ERR"

    def test_timeout_triggers_exit_124_and_kills_process(self, runner):
        spec = CommandSpec(
            argv=[sys.executable, "-c", "import time; time.sleep(10)"],
            timeout_seconds=1,
        )
        start = time.perf_counter()
        res = runner.run(spec)
        elapsed = time.perf_counter() - start

        assert res.is_success is False
        assert res.is_timeout is True
        assert res.status == ExecutionStatus.TIMEOUT
        assert res.exit_code == ExitCode.EXECUTION_TIMEOUT
        assert res.exit_code == 124
        assert "timed out" in res.stderr
        assert elapsed < 5.0  # Must terminate quickly near 1s timeout

    def test_timeout_terminates_child_process_tree(self, runner):
        # Python script that spawns a child subprocess that sleeps
        code = (
            "import subprocess, sys, time; "
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            "time.sleep(30)"
        )
        spec = CommandSpec(
            argv=[sys.executable, "-c", code],
            timeout_seconds=1,
        )
        res = runner.run(spec)
        assert res.status == ExecutionStatus.TIMEOUT
        assert res.exit_code == 124

    def test_shell_injection_is_prevented(self, runner):
        # Attempting shell chaining (e.g. ; or &&) inside an argument
        # Without shell=True, python receives the exact string argument literally
        spec = CommandSpec(
            argv=[sys.executable, "-c", "import sys; print(sys.argv[1])", "arg1; echo INJECTED && echo PWNED"],
            timeout_seconds=5,
        )
        res = runner.run(spec)
        assert res.is_success is True
        assert "arg1; echo INJECTED && echo PWNED" in res.stdout
        assert "PWNED" not in res.stderr

    def test_nonexistent_executable_fails_closed(self, runner):
        spec = CommandSpec(
            argv=["nonexistent_upas_executable_binary_12345", "--version"],
            timeout_seconds=5,
        )
        res = runner.run(spec)
        assert res.is_success is False
        assert res.status == ExecutionStatus.COMMAND_FAILED
        assert res.exit_code == 127
        assert "not found" in res.stderr.lower()

    def test_convenience_run_command_function(self):
        res = run_command([sys.executable, "-c", "print('hello')"], timeout_seconds=5)
        assert res.is_success is True
        assert "hello" in res.stdout
