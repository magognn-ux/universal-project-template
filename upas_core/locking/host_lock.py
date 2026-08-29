"""
UPAS Host Deployment Mutual Exclusion Lock.
Implements the HostLock protocol using OS-level atomic file creation semantics.
Enforces Invariant 2: Single Active Mutation per Host (Exit Code 75).
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import ConcurrencyBlockedError
from upas_core.contracts.interfaces import HostLock
from upas_core.contracts.results import LockHandle, LockResult


def _is_pid_alive_windows(pid: int) -> bool:
    """Windows implementation of PID liveness verification."""
    if pid <= 0:
        return False
    try:
        import ctypes
        import ctypes.wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        SYNCHRONIZE = 0x00100000
        STILL_ACTIVE = 259

        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid
        )
        if not handle:
            err = ctypes.GetLastError()
            # ERROR_ACCESS_DENIED = 5 means process exists but belongs to another security context
            return err == 5
        try:
            exit_code = ctypes.wintypes.DWORD()
            if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return exit_code.value == STILL_ACTIVE
            return False
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return False


def _is_pid_alive_posix(pid: int) -> bool:
    """POSIX implementation of PID liveness verification."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but belongs to different user -> process is active!
        return True
    except OSError:
        return False


class AtomicHostLock(HostLock):
    """
    OS-level atomic mutual exclusion deployment lock.
    Guarantees that at most one deployment or lifecycle mutation process
    can execute on the target host simultaneously.
    """

    def __init__(self):
        pass

    def check_liveness(self, pid: int) -> bool:
        """
        Determines whether the process with the given PID is actively running.
        Cross-platform implementation supporting Windows and POSIX.
        """
        if pid is None or not isinstance(pid, int) or pid <= 0:
            return False

        if os.name == "nt":
            return _is_pid_alive_windows(pid)
        else:
            return _is_pid_alive_posix(pid)

    def _read_lock_data(self, lock_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Safely reads and parses lock metadata JSON."""
        try:
            if not os.path.exists(lock_path):
                return None, "Lock file does not exist"
            with open(lock_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return None, "Lock file is empty"
            data = json.loads(content)
            if not isinstance(data, dict):
                return None, "Lock file content is not a JSON object"
            return data, None
        except Exception as exc:
            return None, f"Failed to read lock file: {exc}"

    def acquire(self, lock_path: str, timeout_seconds: int = 30) -> LockResult:
        """
        Acquires an atomic host lock with configurable timeout and stale PID reclamation.
        Returns LockResult with ExitCode.SUCCESS on acquisition, or ExitCode.BLOCKED_CONCURRENCY on failure.
        """
        if not lock_path or not isinstance(lock_path, str) or not lock_path.strip():
            return LockResult(
                acquired=False,
                lock_path=str(lock_path),
                owner_pid=-1,
                kernel_timestamp="",
                timeout_seconds=timeout_seconds,
                error_message="Lock path cannot be empty",
                exit_code=ExitCode.BLOCKED_CONCURRENCY,
            )

        if timeout_seconds is None or timeout_seconds < 0:
            timeout_seconds = 0

        abs_lock_path = os.path.abspath(lock_path)
        lock_dir = os.path.dirname(abs_lock_path)
        if lock_dir:
            os.makedirs(lock_dir, exist_ok=True)

        start_time = time.monotonic()
        deadline = start_time + timeout_seconds
        stale_reclaimed = False
        last_owner_pid = -1
        last_timestamp = ""

        while True:
            # 1. Attempt atomic creation using OS flags O_CREAT | O_EXCL
            try:
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                fd = os.open(abs_lock_path, flags)
                # Lock successfully created atomically!
                current_pid = os.getpid()
                now_iso = datetime.now(timezone.utc).isoformat()
                payload = {
                    "owner_pid": current_pid,
                    "kernel_timestamp": now_iso,
                    "timeout_seconds": timeout_seconds,
                    "hostname": socket.gethostname(),
                    "platform": sys.platform,
                    "created_at_epoch": time.time(),
                }
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)

                handle = LockHandle(
                    lock_path=abs_lock_path,
                    owner_pid=current_pid,
                    kernel_timestamp=now_iso,
                    timeout_seconds=timeout_seconds,
                )
                return LockResult(
                    acquired=True,
                    lock_path=abs_lock_path,
                    owner_pid=current_pid,
                    kernel_timestamp=now_iso,
                    timeout_seconds=timeout_seconds,
                    stale_reclaimed=stale_reclaimed,
                    handle=handle,
                    exit_code=ExitCode.SUCCESS,
                )
            except FileExistsError:
                pass  # Lock exists, proceed to inspection
            except Exception as exc:
                return LockResult(
                    acquired=False,
                    lock_path=abs_lock_path,
                    owner_pid=-1,
                    kernel_timestamp="",
                    timeout_seconds=timeout_seconds,
                    error_message=f"OS lock creation failed: {exc}",
                    exit_code=ExitCode.BLOCKED_CONCURRENCY,
                )

            # 2. Inspect existing lock file
            data, err = self._read_lock_data(abs_lock_path)
            if data is not None:
                existing_pid = data.get("owner_pid")
                existing_ts = data.get("kernel_timestamp", "")
                last_owner_pid = existing_pid if isinstance(existing_pid, int) else -1
                last_timestamp = str(existing_ts)

                # 3. Verify owner process liveness
                if isinstance(existing_pid, int) and self.check_liveness(existing_pid):
                    # Owner process is actively alive!
                    # Do NOT reclaim under any circumstances!
                    if time.monotonic() >= deadline:
                        return LockResult(
                            acquired=False,
                            lock_path=abs_lock_path,
                            owner_pid=existing_pid,
                            kernel_timestamp=last_timestamp,
                            timeout_seconds=timeout_seconds,
                            error_message=(
                                f"Host lock '{abs_lock_path}' is actively held by running process (PID {existing_pid})"
                            ),
                            exit_code=ExitCode.BLOCKED_CONCURRENCY,
                        )
                    time.sleep(0.1)
                    continue
                else:
                    # Stale lock detected: owner PID is dead or invalid
                    try:
                        os.remove(abs_lock_path)
                        stale_reclaimed = True
                        continue  # Retry atomic acquisition immediately
                    except (FileNotFoundError, PermissionError):
                        pass
            else:
                # File may be in mid-write by concurrent process; wait briefly
                if time.monotonic() >= deadline:
                    return LockResult(
                        acquired=False,
                        lock_path=abs_lock_path,
                        owner_pid=last_owner_pid,
                        kernel_timestamp=last_timestamp,
                        timeout_seconds=timeout_seconds,
                        error_message=(
                            f"Host lock '{abs_lock_path}' is held by another process: {err}"
                        ),
                        exit_code=ExitCode.BLOCKED_CONCURRENCY,
                    )
                time.sleep(0.05)

            if time.monotonic() >= deadline:
                break

        return LockResult(
            acquired=False,
            lock_path=abs_lock_path,
            owner_pid=last_owner_pid,
            kernel_timestamp=last_timestamp,
            timeout_seconds=timeout_seconds,
            error_message=(
                f"Failed to acquire host lock '{abs_lock_path}' within timeout ({timeout_seconds}s)"
            ),
            exit_code=ExitCode.BLOCKED_CONCURRENCY,
        )

    def release(self, handle: LockHandle) -> bool:
        """
        Safely releases an acquired host lock.
        Verifies ownership (PID and timestamp) before unlinking.
        """
        if not handle or not isinstance(handle, LockHandle):
            return False

        abs_lock_path = os.path.abspath(handle.lock_path)
        if not os.path.exists(abs_lock_path):
            return False

        data, _ = self._read_lock_data(abs_lock_path)
        if not data:
            return False

        # Verify that the release request matches the lock ownership
        if (
            data.get("owner_pid") == handle.owner_pid
            and data.get("kernel_timestamp") == handle.kernel_timestamp
        ):
            try:
                os.remove(abs_lock_path)
                return True
            except OSError:
                return False

        return False


def acquire_host_lock(
    lock_path: str,
    timeout_seconds: int = 30,
    locker: Optional[HostLock] = None,
) -> LockHandle:
    """
    Fail-closed gate function for host locking.
    Returns LockHandle on success, raises ConcurrencyBlockedError (exit code 75) on failure.
    """
    locker = locker or AtomicHostLock()
    result = locker.acquire(lock_path, timeout_seconds=timeout_seconds)
    if not result.acquired or not result.handle:
        raise ConcurrencyBlockedError(result.error_message or "Failed to acquire host lock")
    return result.handle
