"""
UPAS Evidence Audit Record Contracts.
Defines machine-readable immutable audit models matching evidence.schema.json.
Validates authoritative source hierarchies and rejects contradictory states.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from upas_core.contracts.enums import EvidenceType, FinalVerdictState
from upas_core.contracts.errors import InvalidEvidenceError

_OPERATION_ID_REGEX = re.compile(r"^op_[a-zA-Z0-9_\-\.]+$")
_CORRELATION_ID_REGEX = re.compile(r"^rel_[a-zA-Z0-9_\-\.]+$")
_PROJECT_NAME_REGEX = re.compile(r"^[a-z0-9_\-]+$")
_COMMIT_SHA_REGEX = re.compile(r"^[a-f0-9]{40}$")
_CANONICAL_REF_REGEX = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
_DIGEST_REGEX = re.compile(r"^sha256:[a-f0-9]{64}$")


@dataclass(frozen=True)
class GitDagRecord:
    """Authoritative Git DAG state."""
    commit_sha: str
    branch: str
    dirty_tree: bool

    def __post_init__(self):
        if not _COMMIT_SHA_REGEX.match(self.commit_sha):
            raise InvalidEvidenceError(f"Invalid Git DAG commit SHA: {self.commit_sha}")
        if not self.branch:
            raise InvalidEvidenceError("Git DAG branch cannot be empty")


@dataclass(frozen=True)
class CiExecutionRecord:
    """Authoritative CI Execution provenance."""
    provider: str
    run_id: str
    conclusion: str
    workflow_ref: Optional[str] = None

    def __post_init__(self):
        if self.provider != "github_actions":
            raise InvalidEvidenceError(f"Invalid CI provider: {self.provider}")
        if self.conclusion not in ("success", "failure", "cancelled"):
            raise InvalidEvidenceError(f"Invalid CI conclusion: {self.conclusion}")


@dataclass(frozen=True)
class ArtifactProvenanceRecord:
    """Authoritative Artifact provenance and verification state."""
    immutable_digest: str
    canonical_reference: str
    verified_running_digest: str

    def __post_init__(self):
        if not _DIGEST_REGEX.match(self.immutable_digest):
            raise InvalidEvidenceError(f"Invalid immutable_digest: {self.immutable_digest}")
        if not _CANONICAL_REF_REGEX.match(self.canonical_reference):
            raise InvalidEvidenceError(f"Invalid canonical_reference: {self.canonical_reference}")
        if not _DIGEST_REGEX.match(self.verified_running_digest):
            raise InvalidEvidenceError(f"Invalid verified_running_digest: {self.verified_running_digest}")


@dataclass(frozen=True)
class ProductionAuthorizationRecord:
    """Authoritative Production Authorization record."""
    policy: str
    actor: str
    run_id: str
    environment: str
    approval_timestamp: str
    oidc_claims: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.policy not in ("github_environment_oidc", "emergency_manual_token"):
            raise InvalidEvidenceError(f"Invalid authorization policy: {self.policy}")
        if not self.actor or not self.run_id or not self.environment or not self.approval_timestamp:
            raise InvalidEvidenceError("ProductionAuthorizationRecord required fields cannot be empty")


@dataclass(frozen=True)
class HostLockStateRecord:
    """Host deployment lock state."""
    lock_acquired: bool
    lock_path: str
    lock_owner_pid: int

    def __post_init__(self):
        if not self.lock_path.startswith("/"):
            raise InvalidEvidenceError(f"Host lock path must be absolute: {self.lock_path}")
        if self.lock_owner_pid < 1:
            raise InvalidEvidenceError(f"Invalid lock owner PID: {self.lock_owner_pid}")


@dataclass(frozen=True)
class HostRuntimeRecord:
    """Authoritative Host Runtime state."""
    host_identity: str
    kernel_timestamp: str
    lock_state: HostLockStateRecord

    def __post_init__(self):
        if not self.host_identity or not self.kernel_timestamp:
            raise InvalidEvidenceError("HostRuntimeRecord required fields cannot be empty")


@dataclass(frozen=True)
class AuthoritativeSourcesRecord:
    """Container for all authoritative sources of truth."""
    git_dag: GitDagRecord
    ci_execution: CiExecutionRecord
    artifact_provenance: ArtifactProvenanceRecord
    production_authorization: ProductionAuthorizationRecord
    host_runtime: HostRuntimeRecord


@dataclass(frozen=True)
class ProjectRecord:
    """Project metadata."""
    name: str
    type: str
    adapter_version: str

    def __post_init__(self):
        if not _PROJECT_NAME_REGEX.match(self.name):
            raise InvalidEvidenceError(f"Invalid project name: {self.name}")
        if self.type not in ("application", "library", "infrastructure"):
            raise InvalidEvidenceError(f"Invalid project type: {self.type}")


@dataclass(frozen=True)
class StepEvidenceRecord:
    """Audit record for individual executed step."""
    name: str
    status: str
    exit_code: int
    duration_ms: int
    details: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.status not in ("PASS", "FAIL", "SKIPPED"):
            raise InvalidEvidenceError(f"Invalid step status: {self.status}")
        if self.duration_ms < 0:
            raise InvalidEvidenceError(f"Invalid duration: {self.duration_ms}")


@dataclass(frozen=True)
class FinalVerdictRecord:
    """Final verdict and completion state."""
    state: FinalVerdictState
    exit_code: int
    completed_at: str
    total_duration_ms: int
    summary: Optional[str] = None

    def __post_init__(self):
        if self.total_duration_ms < 0:
            raise InvalidEvidenceError(f"Invalid total duration: {self.total_duration_ms}")
        # Invariant: VERIFIED must have exit_code 0
        if self.state == FinalVerdictState.VERIFIED and self.exit_code != 0:
            raise InvalidEvidenceError("Verdict state 'VERIFIED' cannot have non-zero exit code")
        # Invariant: Failure states cannot have exit_code 0
        if self.state != FinalVerdictState.VERIFIED and self.exit_code == 0:
            raise InvalidEvidenceError(f"Verdict state '{self.state.value}' cannot have exit code 0")


@dataclass(frozen=True)
class EvidenceRecord:
    """
    Top-level Evidence Audit Record matching evidence.schema.json.
    """
    evidence_type: EvidenceType
    operation_id: str
    correlation_id: str
    project: ProjectRecord
    authoritative_sources: AuthoritativeSourcesRecord
    steps: List[StepEvidenceRecord]
    final_verdict: FinalVerdictRecord
    schema_version: str = "1.0.0"

    def __post_init__(self):
        if self.schema_version != "1.0.0":
            raise InvalidEvidenceError(f"Invalid evidence schema_version: {self.schema_version}")
        if not _OPERATION_ID_REGEX.match(self.operation_id):
            raise InvalidEvidenceError(f"Invalid operation_id: {self.operation_id}")
        if not _CORRELATION_ID_REGEX.match(self.correlation_id):
            raise InvalidEvidenceError(f"Invalid correlation_id: {self.correlation_id}")
        if not self.steps:
            raise InvalidEvidenceError("EvidenceRecord steps list cannot be empty")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary matching evidence.schema.json."""
        steps_serialized = []
        for s in self.steps:
            item: Dict[str, Any] = {
                "name": s.name,
                "status": s.status,
                "exit_code": s.exit_code,
                "duration_ms": s.duration_ms,
            }
            if s.details is not None:
                item["details"] = s.details
            steps_serialized.append(item)

        prod_auth: Dict[str, Any] = {
            "policy": self.authoritative_sources.production_authorization.policy,
            "actor": self.authoritative_sources.production_authorization.actor,
            "run_id": self.authoritative_sources.production_authorization.run_id,
            "environment": self.authoritative_sources.production_authorization.environment,
            "approval_timestamp": self.authoritative_sources.production_authorization.approval_timestamp,
        }
        if self.authoritative_sources.production_authorization.oidc_claims is not None:
            prod_auth["oidc_claims"] = self.authoritative_sources.production_authorization.oidc_claims

        ci_exec: Dict[str, Any] = {
            "provider": self.authoritative_sources.ci_execution.provider,
            "run_id": self.authoritative_sources.ci_execution.run_id,
            "conclusion": self.authoritative_sources.ci_execution.conclusion,
        }
        if self.authoritative_sources.ci_execution.workflow_ref is not None:
            ci_exec["workflow_ref"] = self.authoritative_sources.ci_execution.workflow_ref

        verdict: Dict[str, Any] = {
            "state": self.final_verdict.state.value,
            "exit_code": self.final_verdict.exit_code,
            "completed_at": self.final_verdict.completed_at,
            "total_duration_ms": self.final_verdict.total_duration_ms,
        }
        if self.final_verdict.summary is not None:
            verdict["summary"] = self.final_verdict.summary

        return {
            "schema_version": self.schema_version,
            "evidence_type": self.evidence_type.value,
            "operation_id": self.operation_id,
            "correlation_id": self.correlation_id,
            "project": {
                "name": self.project.name,
                "type": self.project.type,
                "adapter_version": self.project.adapter_version,
            },
            "authoritative_sources": {
                "git_dag": {
                    "commit_sha": self.authoritative_sources.git_dag.commit_sha,
                    "branch": self.authoritative_sources.git_dag.branch,
                    "dirty_tree": self.authoritative_sources.git_dag.dirty_tree,
                },
                "ci_execution": ci_exec,
                "artifact_provenance": {
                    "immutable_digest": self.authoritative_sources.artifact_provenance.immutable_digest,
                    "canonical_reference": self.authoritative_sources.artifact_provenance.canonical_reference,
                    "verified_running_digest": self.authoritative_sources.artifact_provenance.verified_running_digest,
                },
                "production_authorization": prod_auth,
                "host_runtime": {
                    "host_identity": self.authoritative_sources.host_runtime.host_identity,
                    "kernel_timestamp": self.authoritative_sources.host_runtime.kernel_timestamp,
                    "lock_state": {
                        "lock_acquired": self.authoritative_sources.host_runtime.lock_state.lock_acquired,
                        "lock_path": self.authoritative_sources.host_runtime.lock_state.lock_path,
                        "lock_owner_pid": self.authoritative_sources.host_runtime.lock_state.lock_owner_pid,
                    },
                },
            },
            "steps": steps_serialized,
            "final_verdict": verdict,
        }
