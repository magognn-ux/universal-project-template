"""
UPAS Backup Management Module.
Enforces pre-deployment backup execution and cryptographic integrity verification.
"""

from upas_core.backup.backup_manager import (
    BackupRecord,
    PreDeployBackupManager,
    verify_pre_deploy_backup,
)

__all__ = [
    "BackupRecord",
    "PreDeployBackupManager",
    "verify_pre_deploy_backup",
]
