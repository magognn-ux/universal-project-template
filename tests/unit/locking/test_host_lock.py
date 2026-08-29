"""
Unit tests for UPAS Atomic Host Lock.
Tests atomic acquisition, safe release, PID validation, and handle verification.
"""

import os
import tempfile
import pytest

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import ConcurrencyBlockedError
from upas_core.contracts.results import LockHandle
from upas_core.locking.host_lock import AtomicHostLock, acquire_host_lock


@pytest.fixture
def temp_lock_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = os.path.join(tmpdir, "upas-deploy.lock")
        yield lock_path


def test_acquire_and_release_lock_succeeds(temp_lock_path):
    locker = AtomicHostLock()

    # Acquire
    result = locker.acquire(temp_lock_path, timeout_seconds=2)
    assert result.acquired is True
    assert result.exit_code == ExitCode.SUCCESS
    assert result.owner_pid == os.getpid()
    assert result.handle is not None
    assert os.path.exists(temp_lock_path)

    # Release
    released = locker.release(result.handle)
    assert released is True
    assert not os.path.exists(temp_lock_path)


def test_release_with_invalid_handle_fails(temp_lock_path):
    locker = AtomicHostLock()
    result = locker.acquire(temp_lock_path, timeout_seconds=2)
    assert result.acquired is True

    # Fake handle with wrong PID
    fake_handle = LockHandle(
        lock_path=temp_lock_path,
        owner_pid=999999,
        kernel_timestamp=result.kernel_timestamp,
        timeout_seconds=2,
    )
    assert locker.release(fake_handle) is False
    assert os.path.exists(temp_lock_path)

    # Clean release
    assert locker.release(result.handle) is True


def test_check_liveness_current_process():
    locker = AtomicHostLock()
    assert locker.check_liveness(os.getpid()) is True
    assert locker.check_liveness(-1) is False
    assert locker.check_liveness(0) is False
    assert locker.check_liveness(None) is False


def test_acquire_host_lock_convenience_function(temp_lock_path):
    locker = AtomicHostLock()
    handle = acquire_host_lock(temp_lock_path, timeout_seconds=1, locker=locker)
    assert handle.owner_pid == os.getpid()
    assert handle.lock_path == temp_lock_path
    assert locker.release(handle) is True
