"""
UPAS Core Contract Enums.
Strict typed enumerations matching the frozen UPAS JSON Schemas and architecture invariants.
"""

from enum import Enum, IntEnum


class ExitCode(IntEnum):
    """
    Authoritative machine-readable UPAS Exit Codes.
    Non-zero exit codes represent explicit, deterministic fail-closed states.
    """
    SUCCESS = 0
    TESTS_FAILED = 1
    CAPABILITY_MISMATCH = 2
    INVALID_EVIDENCE_STATE = 3
    APPROVAL_DENIED = 42
    PROD_AUTH_FAILED = 43
    DIGEST_MISMATCH = 65
    FAILED_PULL = 66
    MIGRATION_FAILED = 70
    BLOCKED_CONCURRENCY = 75
    SHARED_INFRA_VIOLATION = 77
    FAILED_BACKUP = 78
    FAILED_PREFLIGHT = 79
    ESCALATION_VIOLATION = 80
    EMERGENCY_HALT = 81
    EXECUTION_TIMEOUT = 124
    UNKNOWN_REMOTE_STATE = 125
    INCOMPATIBLE_VERSION_ERROR = 126


class EvidenceType(str, Enum):
    """Evidence record types matching evidence.schema.json."""
    DEPLOYMENT_AUDIT_RECORD = "deployment_audit_record"
    RELEASE_PRECHECK_RECORD = "release_precheck_record"
    ROLLBACK_AUDIT_RECORD = "rollback_audit_record"
    VERIFICATION_AUDIT_RECORD = "verification_audit_record"


class FinalVerdictState(str, Enum):
    """Final verdict states matching evidence.schema.json."""
    VERIFIED = "VERIFIED"
    ROLLED_BACK = "ROLLED_BACK"
    EMERGENCY_HALT = "EMERGENCY_HALT"
    FAILED_PREFLIGHT = "FAILED_PREFLIGHT"
    FAILED_BACKUP = "FAILED_BACKUP"
    FAILED_PULL = "FAILED_PULL"
    BLOCKED_CONCURRENCY = "BLOCKED_CONCURRENCY"
    MIGRATION_FAILED = "MIGRATION_FAILED"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    PROD_AUTH_FAILED = "PROD_AUTH_FAILED"
    UNKNOWN_REMOTE_STATE = "UNKNOWN_REMOTE_STATE"
    CANCELLED = "CANCELLED"


class MigrationClassification(str, Enum):
    """Database migration classifications matching upas.adapter.schema.json."""
    NONE = "NONE"
    ADDITIVE_COMPATIBLE = "ADDITIVE_COMPATIBLE"
    POTENTIALLY_INCOMPATIBLE = "POTENTIALLY_INCOMPATIBLE"
    DESTRUCTIVE_IRREVERSIBLE = "DESTRUCTIVE_IRREVERSIBLE"


class MigrationPolicy(str, Enum):
    """Database migration policy matching upas.adapter.schema.json."""
    EXPLICIT_MANIFEST = "explicit_manifest"
    AUTO_ANALYZER = "auto_analyzer"


class ArtifactType(str, Enum):
    """Physical artifact classifications matching artifact.schema.json."""
    CONTAINER_IMAGE = "container_image"
    S3_ARCHIVE = "s3_archive"
    STANDALONE_BINARY = "standalone_binary"
    STATIC_BUNDLE = "static_bundle"


class TestLevel(IntEnum):
    """
    Tiered test levels (L0-L5) matching upas.adapter.schema.json.
    Non-lowerable ordering: L0 < L1 < L2 < L3 < L4 < L5.
    """
    __test__ = False

    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4
    L5 = 5


class RiskLevel(str, Enum):
    """Zone risk levels matching upas.adapter.schema.json."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InfraType(str, Enum):
    """Infrastructure dependency type (must be external)."""
    EXTERNAL = "external"


class InfraAccess(str, Enum):
    """Infrastructure dependency access (must be readonly_consumer)."""
    READONLY_CONSUMER = "readonly_consumer"


class AuthPolicy(str, Enum):
    """Authorization policy matching evidence.schema.json and upas.adapter.schema.json."""
    GITHUB_ENVIRONMENT_OIDC = "github_environment_oidc"
    EMERGENCY_MANUAL_TOKEN = "emergency_manual_token"


class StepStatus(str, Enum):
    """Lifecycle step execution status."""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


class ExecutionStatus(str, Enum):
    """Subprocess command execution status."""
    SUCCESS = "SUCCESS"
    COMMAND_FAILED = "COMMAND_FAILED"
    TIMEOUT = "TIMEOUT"
    UNKNOWN_REMOTE_STATE = "UNKNOWN_REMOTE_STATE"
