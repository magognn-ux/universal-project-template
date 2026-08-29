"""
Adversarial Concurrency Tests for UPAS Atomic Host Lock.
Covers threat models P-S:
  P. Concurrent host lock acquisition (mutual exclusion)
  Q. Stale lock with dead PID (safe reclamation)
  R. Active PID must never be reclaimed
  S. Lock timeout exhaustion (exit code 75)
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
import pytest

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import ConcurrencyBlockedError
from upas_core.locking.host_lock import AtomicHostLock, acquire_host_lock


# P. Concurrent host lock acquisition
def test_adversarial_P_concurrent_acquisition_mutual_exclusion():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = os.path.join(tmpdir, "concurrent_test.lock")
        locker = AtomicHostLock()

        results = []

        def attempt():
            # Zero timeout to prevent waiting
            return locker.acquire(lock_path, timeout_seconds=0)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(attempt) for _ in range(20)]
            results = [f.result() for f in futures]

        acquired_results = [r for r in results if r.acquired]
        blocked_results = [r for r in results if not r.acquired]

        # Exactly 1 thread must acquire the lock
        assert len(acquired_results) == 1
        assert len(blocked_results) == 19
        assert all(r.exit_code == ExitCode.BLOCKED_CONCURRENCY for r in blocked_results)


# Q. Stale lock with dead PID
def test_adversarial_Q_stale_lock_with_dead_pid_is_reclaimed():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = os.path.join(tmpdir, "stale.lock")
        locker = AtomicHostLock()

        # Write a simulated lock belonging to a dead PID (e.g. 999999999)
        dead_pid = 999999999
        # Double check this PID is indeed dead
        assert locker.check_liveness(dead_pid) is False

        stale_data = {
            "owner_pid": dead_pid,
            "kernel_timestamp": "2020-01-01T00:00:00Z",
            "timeout_seconds": 30,
            "hostname": "test-host",
        }
        with open(lock_path, "w", encoding="utf-8") as f:
            json.dump(stale_data, f)

        # Acquire lock: should detect dead PID, reclaim stale lock, and succeed
        result = locker.acquire(lock_path, timeout_seconds=1)
        assert result.acquired is True
        assert result.stale_reclaimed is True
        assert result.exit_code == ExitCode.SUCCESS
        assert result.owner_pid == os.getpid()


# R. Active PID must never be reclaimed
def test_adversarial_R_active_pid_must_never_be_reclaimed():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = os.path.join(tmpdir, "active_holder.lock")
        locker = AtomicHostLock()

        # Spawn a background subprocess that holds an active PID and sleeps
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            active_pid = proc.pid
            assert locker.check_liveness(active_pid) is True

            # Write lock file representing this active process
            lock_data = {
                "owner_pid": active_pid,
                "kernel_timestamp": "2026-08-28T12:00:00Z",
                "timeout_seconds": 30,
                "hostname": "active-host",
            }
            with open(lock_path, "w", encoding="utf-8") as f:
                json.dump(lock_data, f)

            # Attempt to acquire lock with 0-second timeout: MUST FAIL
            result = locker.acquire(lock_path, timeout_seconds=0)
            assert result.acquired is False
            assert result.exit_code == ExitCode.BLOCKED_CONCURRENCY
            assert "actively held by running process" in result.error_message
            assert str(active_pid) in result.error_message

        finally:
            proc.terminate()
            proc.wait()


# S. Lock timeout exhaustion
def test_adversarial_S_lock_timeout_exhaustion():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = os.path.join(tmpdir, "timeout.lock")
        locker = AtomicHostLock()

        # First locker acquires lock
        res1 = locker.acquire(lock_path, timeout_seconds=5)
        assert res1.acquired is True

        # Second acquisition attempt with short timeout (0.2s) must fail with exit code 75
        start = time.monotonic()
        res2 = locker.acquire(lock_path, timeout_seconds=1)
        elapsed = time.monotonic() - start

        assert elapsed >= 0.8
        assert res2.acquired is False
        assert res2.exit_code == ExitCode.BLOCKED_CONCURRENCY

        # acquire_host_lock gate function raises ConcurrencyBlockedError
        with pytest.raises(ConcurrencyBlockedError) as exc_info:
            acquire_host_lock(lock_path, timeout_seconds=1, locker=locker)
        assert exc_info.value.exit_code == ExitCode.BLOCKED_CONCURRENCY

        # Release first lock cleanly
        assert locker.release(res1.handle) is True
