"""
UPAS Core Contract Exceptions.
Typed domain exceptions mapping directly to authoritative UPAS Exit Codes.
"""

from typing import Optional
from upas_core.contracts.enums import ExitCode


class UPASError(Exception):
    """Base exception for all UPAS errors. Carries an authoritative exit code."""

    def __init__(self, message: str, exit_code: ExitCode = ExitCode.TESTS_FAILED):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code

    def __str__(self) -> str:
        return f"[{self.exit_code.name} (exit {self.exit_code.value})] {self.message}"


class IncompatibleVersionError(UPASError):
    """Raised when Core version does not satisfy Adapter version constraint."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.INCOMPATIBLE_VERSION_ERROR)


class ProductionAuthError(UPASError):
    """Raised when production OIDC authentication or claim verification fails."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.PROD_AUTH_FAILED)


class ApprovalDeniedError(UPASError):
    """Raised when human approval is rejected or missing."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.APPROVAL_DENIED)


class ConcurrencyBlockedError(UPASError):
    """Raised when host lock cannot be acquired or concurrent deploy is active."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.BLOCKED_CONCURRENCY)


class DigestMismatchError(UPASError):
    """Raised when pulled or running container digest does not match approved digest."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.DIGEST_MISMATCH)


class PullFailedError(UPASError):
    """Raised when artifact cannot be pulled from registry."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.FAILED_PULL)


class MigrationError(UPASError):
    """Raised when database migration execution fails."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.MIGRATION_FAILED)


class EmergencyHaltError(UPASError):
    """Raised when an incompatible state prevents safe automated rollback."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.EMERGENCY_HALT)


class CommandTimeoutError(UPASError):
    """Raised when safe subprocess execution exceeds its strict timeout."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.EXECUTION_TIMEOUT)


class UnknownRemoteStateError(UPASError):
    """Raised when a remote connection drops during mutation and state cannot be verified."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.UNKNOWN_REMOTE_STATE)


class TestExecutionError(UPASError):
    """Raised when automated test execution fails."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.TESTS_FAILED)


class EscalationViolationError(UPASError):
    """Raised when an attempt is made to downgrade a mandatory test level."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.ESCALATION_VIOLATION)


class CapabilityMismatchError(UPASError):
    """Raised when manifest capabilities do not match executable CLI capabilities."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.CAPABILITY_MISMATCH)


class SharedInfraViolationError(UPASError):
    """Raised when an application attempts to modify or manage external shared infrastructure."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.SHARED_INFRA_VIOLATION)


class InvalidEvidenceError(UPASError):
    """Raised when generated evidence is structurally invalid or contains contradictory states."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.INVALID_EVIDENCE_STATE)


class PreflightFailedError(UPASError):
    """Raised when pre-flight host resource checks fail."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.FAILED_PREFLIGHT)


class BackupFailedError(UPASError):
    """Raised when pre-deploy backup hook fails."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.FAILED_BACKUP)


class InvalidStateTransitionError(UPASError):
    """Raised when an invalid lifecycle state transition is attempted."""

    def __init__(self, current_state: str, target_state: str, lifecycle: str):
        message = (
            f"Invalid transition in {lifecycle}: "
            f"cannot transition from '{current_state}' to '{target_state}'"
        )
        super().__init__(message, exit_code=ExitCode.TESTS_FAILED)


class InvalidArtifactError(UPASError):
    """Raised when an artifact reference violates strict immutability rules."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.DIGEST_MISMATCH)
