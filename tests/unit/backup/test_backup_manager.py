"""
Unit tests for UPAS Pre-Deploy Backup Manager.
Tests backup execution, artifact presence, checksum calculation, and stale backup rejection.
"""

import os
import sys
import tempfile
import time
import pytest

from upas_core.backup.backup_manager import (
    BackupRecord,
    PreDeployBackupManager,
    compute_file_sha256,
    verify_pre_deploy_backup,
)
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import BackupFailedError


def test_backup_execution_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = os.path.join(tmpdir, "backup.sql")
        hook = f"{sys.executable} -c \"with open(r'{target_file}', 'w') as f: f.write('BACKUP DUMP DATA')\""

        manager = PreDeployBackupManager()
        record = manager.execute_backup(
            service_name="support_bot",
            backup_hook=hook,
            target_output_file=target_file,
        )

        assert record.service_name == "support_bot"
        assert record.verified is True
        assert record.size_bytes > 0
        assert len(record.checksum_sha256) == 64
        assert os.path.exists(record.artifact_path)
        assert manager.validate_record(record) is True


def test_backup_execution_failed_hook():
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = os.path.join(tmpdir, "failed_backup.sql")
        hook = f"{sys.executable} -c \"import sys; sys.exit(2)\""

        manager = PreDeployBackupManager()
        with pytest.raises(BackupFailedError) as exc_info:
            manager.execute_backup(
                service_name="support_bot",
                backup_hook=hook,
                target_output_file=target_file,
            )
        assert exc_info.value.exit_code == ExitCode.FAILED_BACKUP


def test_backup_execution_missing_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = os.path.join(tmpdir, "nonexistent.sql")
        # Command exits 0 but creates nothing
        hook = f"{sys.executable} -c \"pass\""

        manager = PreDeployBackupManager()
        with pytest.raises(BackupFailedError) as exc_info:
            manager.execute_backup(
                service_name="support_bot",
                backup_hook=hook,
                target_output_file=target_file,
            )
        assert exc_info.value.exit_code == ExitCode.FAILED_BACKUP
        assert "expected artifact was not created" in str(exc_info.value)


def test_backup_execution_empty_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = os.path.join(tmpdir, "empty.sql")
        # Command creates 0-byte file
        hook = f"{sys.executable} -c \"with open(r'{target_file}', 'w') as f: pass\""

        manager = PreDeployBackupManager()
        with pytest.raises(BackupFailedError) as exc_info:
            manager.execute_backup(
                service_name="support_bot",
                backup_hook=hook,
                target_output_file=target_file,
            )
        assert exc_info.value.exit_code == ExitCode.FAILED_BACKUP
        assert "empty (0 bytes)" in str(exc_info.value)


def test_backup_stale_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = os.path.join(tmpdir, "stale.sql")
        with open(target_file, "w") as f:
            f.write("DUMP")

        checksum = compute_file_sha256(target_file)
        # Record created 1000 seconds ago
        stale_record = BackupRecord(
            backup_id="bak_stale",
            service_name="support_bot",
            artifact_path=target_file,
            checksum_sha256=checksum,
            size_bytes=len("DUMP"),
            created_at="2020-01-01T00:00:00Z",
            created_at_epoch=time.time() - 1000,
            verified=True,
        )

        manager = PreDeployBackupManager(max_stale_age_seconds=60)
        assert manager.validate_record(stale_record) is False
