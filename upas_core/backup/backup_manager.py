"""
UPAS Pre-Deploy Backup Manager.
Enforces Invariant 2: Mandatory Pre-Deploy Backup Gate (Exit Code 78).
Guarantees that a production mutation cannot proceed without a cryptographically verified backup artifact.
"""

import hashlib
import os
import shlex
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import BackupFailedError
from upas_core.contracts.execution import CommandSpec
from upas_core.contracts.interfaces import CommandRunner
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


@dataclass(frozen=True)
class BackupRecord:
    """
    Cryptographically verified pre-deploy backup audit record.
    Proves that a verified backup was created prior to mutation.
    """
    backup_id: str
    service_name: str
    artifact_path: str
    checksum_sha256: str
    size_bytes: int
    created_at: str
    created_at_epoch: float
    verified: bool

    def __post_init__(self):
        if not self.backup_id:
            raise ValueError("BackupRecord.backup_id cannot be empty")
        if not self.service_name:
            raise ValueError("BackupRecord.service_name cannot be empty")
        if not self.artifact_path:
            raise ValueError("BackupRecord.artifact_path cannot be empty")
        if not self.checksum_sha256 or len(self.checksum_sha256) != 64:
            raise ValueError("BackupRecord.checksum_sha256 must be a 64-char hex string")
        if self.size_bytes <= 0:
            raise ValueError("BackupRecord.size_bytes must be > 0 (non-empty artifact)")
        if not self.verified:
            raise ValueError("BackupRecord cannot be constructed with verified=False")


def compute_file_sha256(file_path: str) -> str:
    """Computes SHA256 checksum of the file at the given path."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class PreDeployBackupManager:
    """
    Executes and cryptographically validates pre-deploy backup hooks.
    Fails closed if the hook fails, output file is missing, empty, or unverified.
    """

    def __init__(
        self,
        runner: Optional[CommandRunner] = None,
        max_stale_age_seconds: int = 300,
    ):
        self.runner = runner or SafeCommandRunner()
        self.max_stale_age_seconds = max_stale_age_seconds

    def execute_backup(
        self,
        service_name: str,
        backup_hook: str,
        target_output_file: str,
        timeout_seconds: int = 180,
    ) -> BackupRecord:
        """
        Executes backup hook and verifies output file presence and integrity.
        Raises BackupFailedError (exit code 78) if any condition is unmet.
        """
        if not service_name or not isinstance(service_name, str) or not service_name.strip():
            raise BackupFailedError("Invalid service_name for backup")
        if not backup_hook or not isinstance(backup_hook, str) or not backup_hook.strip():
            raise BackupFailedError("Missing or empty backup_hook command")
        if not target_output_file or not isinstance(target_output_file, str) or not target_output_file.strip():
            raise BackupFailedError("Missing target_output_file path for backup")

        # 1. Parse command safely
        try:
            argv = _safe_split_command(backup_hook)
        except Exception as exc:
            raise BackupFailedError(f"Failed to parse backup hook command '{backup_hook}': {exc}")

        cmd_spec = CommandSpec(argv=argv, timeout_seconds=timeout_seconds)
        start_epoch = time.time()
        exec_res = self.runner.run(cmd_spec)

        if not exec_res.is_success:
            raise BackupFailedError(
                f"Backup hook execution failed with exit code {exec_res.exit_code}: "
                f"{exec_res.stderr or exec_res.stdout}"
            )

        # 2. Verify artifact existence on disk
        abs_path = os.path.abspath(target_output_file)
        if not os.path.exists(abs_path):
            raise BackupFailedError(
                f"Backup command succeeded but expected artifact was not created at '{abs_path}'"
            )

        # 3. Verify non-empty size
        try:
            stat = os.stat(abs_path)
            size_bytes = stat.st_size
        except OSError as exc:
            raise BackupFailedError(f"Failed to stat backup artifact '{abs_path}': {exc}")

        if size_bytes <= 0:
            raise BackupFailedError(
                f"Backup artifact at '{abs_path}' is empty (0 bytes). Corrupted or incomplete backup."
            )

        # 4. Compute cryptographic SHA256 checksum
        try:
            checksum = compute_file_sha256(abs_path)
        except Exception as exc:
            raise BackupFailedError(f"Failed to compute SHA256 checksum for '{abs_path}': {exc}")

        # 5. Construct verified record
        backup_id = f"bak_{service_name}_{int(start_epoch)}_{checksum[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        record = BackupRecord(
            backup_id=backup_id,
            service_name=service_name,
            artifact_path=abs_path,
            checksum_sha256=checksum,
            size_bytes=size_bytes,
            created_at=now_iso,
            created_at_epoch=start_epoch,
            verified=True,
        )

        return record

    def validate_record(self, record: BackupRecord) -> bool:
        """
        Validates that a previously created BackupRecord remains valid,
        file still exists, checksum still matches, and is not stale.
        """
        if not record or not isinstance(record, BackupRecord):
            return False

        if not record.verified:
            return False

        # Freshness check
        age = time.time() - record.created_at_epoch
        if age > self.max_stale_age_seconds:
            return False

        # File existence & checksum
        if not os.path.exists(record.artifact_path):
            return False

        try:
            current_checksum = compute_file_sha256(record.artifact_path)
            return current_checksum == record.checksum_sha256
        except Exception:
            return False


def verify_pre_deploy_backup(
    service_name: str,
    backup_hook: str,
    target_output_file: str,
    manager: Optional[PreDeployBackupManager] = None,
    timeout_seconds: int = 180,
) -> BackupRecord:
    """Convenience functional gate for pre-deploy backup."""
    mgr = manager or PreDeployBackupManager()
    return mgr.execute_backup(
        service_name=service_name,
        backup_hook=backup_hook,
        target_output_file=target_output_file,
        timeout_seconds=timeout_seconds,
    )
