"""
UPAS Deployment Mutual Exclusion Module.
Provides atomic host-level locking and stale process detection.
"""

from upas_core.locking.host_lock import AtomicHostLock, acquire_host_lock

__all__ = [
    "AtomicHostLock",
    "acquire_host_lock",
]
