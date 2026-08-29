"""
UPAS Evidence Collector & Audit Chain Generator.
Implements the EvidenceGenerator protocol.
Collects authoritative sources, maintains the cryptographic hash chain, and builds valid EvidenceRecords.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from upas_core.contracts.enums import EvidenceType, FinalVerdictState
from upas_core.contracts.errors import InvalidEvidenceError
from upas_core.contracts.evidence import (
    ArtifactProvenanceRecord,
    AuthoritativeSourcesRecord,
    CiExecutionRecord,
    EvidenceRecord,
    FinalVerdictRecord,
    GitDagRecord,
    HostLockStateRecord,
    HostRuntimeRecord,
    ProductionAuthorizationRecord,
    ProjectRecord,
    StepEvidenceRecord,
)
from upas_core.contracts.interfaces import EvidenceGenerator
from upas_core.evidence.model import AuditEvent, SecretRedactor, to_canonical_json


class EvidenceCollector(EvidenceGenerator):
    """
    Stateful collector accumulating authoritative audit records and steps
    during a release or deployment lifecycle execution.
    Maintains an unbroken SHA-256 event hash chain across all lifecycle states.
    """

    GENESIS_HASH: str = "0" * 64

    def __init__(
        self,
        project_name: str = "default_project",
        project_type: str = "application",
        adapter_version: str = "1.0.0",
        correlation_id: Optional[str] = None,
        evidence_type: EvidenceType = EvidenceType.DEPLOYMENT_AUDIT_RECORD,
    ):
        self.project_name = project_name
        self.project_type = project_type
        self.adapter_version = adapter_version
        self.evidence_type = evidence_type
        self.start_time = time.monotonic()
        self.start_epoch = time.time()

        now_id_part = int(self.start_epoch)
        self.correlation_id = correlation_id or f"rel_{project_name}_{now_id_part}"
        self.operation_id = f"op_{project_name}_{now_id_part}"

        # Hash chain
        self._audit_events: List[AuditEvent] = []
        self._last_event_hash: str = self.GENESIS_HASH

        # Steps
        self._steps: List[StepEvidenceRecord] = []

        # Authoritative sources
        self._git_dag: Optional[GitDagRecord] = None
        self._ci_execution: Optional[CiExecutionRecord] = None
        self._artifact_provenance: Optional[ArtifactProvenanceRecord] = None
        self._production_authorization: Optional[ProductionAuthorizationRecord] = None
        self._host_runtime: Optional[HostRuntimeRecord] = None

    @property
    def audit_events(self) -> List[AuditEvent]:
        return list(self._audit_events)

    def record_event(self, state: str, payload: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """
        Records a lifecycle transition in the cryptographic hash chain.
        Each event links to the preceding event's SHA-256 hash.
        """
        seq = len(self._audit_events)
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_payload = SecretRedactor.redact_object(payload or {})

        event = AuditEvent(
            sequence=seq,
            state=state,
            timestamp=now_iso,
            previous_hash=self._last_event_hash,
            payload=clean_payload,
        )

        self._audit_events.append(event)
        self._last_event_hash = event.event_hash
        return event

    def record_step(
        self,
        name: str,
        status: str,
        exit_code: int,
        duration_ms: int,
        details: Optional[Dict[str, Any]] = None,
    ) -> StepEvidenceRecord:
        """Records an executed step in the audit trail."""
        clean_details = SecretRedactor.redact_object(details) if details is not None else None
        step = StepEvidenceRecord(
            name=name,
            status=status,
            exit_code=exit_code,
            duration_ms=max(0, duration_ms),
            details=clean_details,
        )
        self._steps.append(step)
        return step

    def set_git_dag(
        self,
        commit_sha: str,
        branch: str,
        dirty_tree: bool = False,
    ) -> None:
        """Sets the authoritative Git DAG state."""
        self._git_dag = GitDagRecord(
            commit_sha=commit_sha,
            branch=branch,
            dirty_tree=dirty_tree,
        )

    def set_ci_execution(
        self,
        provider: str = "github_actions",
        run_id: str = "1",
        conclusion: str = "success",
        workflow_ref: Optional[str] = None,
    ) -> None:
        """Sets authoritative CI execution provenance."""
        self._ci_execution = CiExecutionRecord(
            provider=provider,
            run_id=run_id,
            conclusion=conclusion,
            workflow_ref=workflow_ref,
        )

    def set_artifact_provenance(
        self,
        immutable_digest: str,
        canonical_reference: str,
        verified_running_digest: str,
    ) -> None:
        """Sets authoritative artifact provenance."""
        self._artifact_provenance = ArtifactProvenanceRecord(
            immutable_digest=immutable_digest,
            canonical_reference=canonical_reference,
            verified_running_digest=verified_running_digest,
        )

    def set_production_authorization(
        self,
        policy: str,
        actor: str,
        run_id: str,
        environment: str,
        approval_timestamp: str,
        oidc_claims: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Sets authoritative production authorization record (secrets automatically redacted)."""
        clean_claims = SecretRedactor.redact_object(oidc_claims) if oidc_claims is not None else None
        self._production_authorization = ProductionAuthorizationRecord(
            policy=policy,
            actor=actor,
            run_id=run_id,
            environment=environment,
            approval_timestamp=approval_timestamp,
            oidc_claims=clean_claims,
        )

    def set_host_runtime(
        self,
        host_identity: str,
        kernel_timestamp: str,
        lock_acquired: bool,
        lock_path: str,
        lock_owner_pid: int,
    ) -> None:
        """Sets authoritative host runtime state."""
        norm_path = lock_path.replace("\\", "/")
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path.lstrip("/")

        lock_state = HostLockStateRecord(
            lock_acquired=lock_acquired,
            lock_path=norm_path,
            lock_owner_pid=lock_owner_pid,
        )
        self._host_runtime = HostRuntimeRecord(
            host_identity=host_identity,
            kernel_timestamp=kernel_timestamp,
            lock_state=lock_state,
        )

    def verify_hash_chain(self) -> bool:
        """
        Cryptographically verifies the unbroken integrity of the audit event chain.
        Returns False if any event has been tampered with, deleted, or reordered.
        """
        expected_prev = self.GENESIS_HASH
        for i, event in enumerate(self._audit_events):
            if event.sequence != i:
                return False
            if event.previous_hash != expected_prev:
                return False
            if event.calculate_hash() != event.event_hash:
                return False
            expected_prev = event.event_hash
        return True

    def finalize_evidence(
        self,
        final_state: FinalVerdictState,
        exit_code: int,
        summary: Optional[str] = None,
    ) -> EvidenceRecord:
        """
        Constructs and validates the complete immutable EvidenceRecord.
        Fails closed if any mandatory authoritative source is missing.
        """
        if not self._git_dag:
            raise InvalidEvidenceError("Missing mandatory authoritative source: git_dag")
        if not self._ci_execution:
            raise InvalidEvidenceError("Missing mandatory authoritative source: ci_execution")
        if not self._artifact_provenance:
            raise InvalidEvidenceError("Missing mandatory authoritative source: artifact_provenance")
        if not self._production_authorization:
            raise InvalidEvidenceError("Missing mandatory authoritative source: production_authorization")
        if not self._host_runtime:
            raise InvalidEvidenceError("Missing mandatory authoritative source: host_runtime")

        if not self._steps:
            # Fallback step if none recorded
            self.record_step(
                name="lifecycle_execution",
                status="PASS" if exit_code == 0 else "FAIL",
                exit_code=exit_code,
                duration_ms=int((time.monotonic() - self.start_time) * 1000),
            )

        # Record final event in chain
        self.record_event(
            state=final_state.value,
            payload={"final_exit_code": exit_code, "summary": summary},
        )

        total_duration_ms = int((time.monotonic() - self.start_time) * 1000)
        now_iso = datetime.now(timezone.utc).isoformat()

        final_verdict = FinalVerdictRecord(
            state=final_state,
            exit_code=exit_code,
            completed_at=now_iso,
            total_duration_ms=max(0, total_duration_ms),
            summary=summary,
        )

        project_rec = ProjectRecord(
            name=self.project_name,
            type=self.project_type,
            adapter_version=self.adapter_version,
        )

        auth_sources = AuthoritativeSourcesRecord(
            git_dag=self._git_dag,
            ci_execution=self._ci_execution,
            artifact_provenance=self._artifact_provenance,
            production_authorization=self._production_authorization,
            host_runtime=self._host_runtime,
        )

        record = EvidenceRecord(
            evidence_type=self.evidence_type,
            operation_id=self.operation_id,
            correlation_id=self.correlation_id,
            project=project_rec,
            authoritative_sources=auth_sources,
            steps=list(self._steps),
            final_verdict=final_verdict,
            schema_version="1.0.0",
        )

        return record

    def build_evidence(self, record: EvidenceRecord) -> Dict[str, Any]:
        """
        Implementation of EvidenceGenerator protocol.
        Serializes and returns dictionary representation of EvidenceRecord.
        """
        if not record or not isinstance(record, EvidenceRecord):
            raise InvalidEvidenceError("Invalid EvidenceRecord instance provided to build_evidence")
        return record.to_dict()
