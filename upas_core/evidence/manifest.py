"""
UPAS Cryptographic Evidence Manifest.
Binds canonical evidence records to immutable cryptographic hashes, artifact digests,
and lifecycle outcomes. Provides tamper verification.
"""

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Union

from upas_core.evidence.model import compute_evidence_hash, to_canonical_bytes, to_canonical_json
from upas_core.evidence.signer import EvidenceSigner, HashOnlySigner


@dataclass(frozen=True)
class EvidenceManifest:
    """
    Cryptographic manifest guaranteeing tamper detection and provenance for an EvidenceRecord.
    """
    manifest_id: str
    operation_id: str
    correlation_id: str
    evidence_sha256: str
    artifact_digest: str
    final_state: str
    final_exit_code: int
    generated_at: str
    schema_version: str = "1.0.0"
    signature: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if not self.manifest_id:
            raise ValueError("EvidenceManifest.manifest_id cannot be empty")
        if not self.operation_id:
            raise ValueError("EvidenceManifest.operation_id cannot be empty")
        if not self.correlation_id:
            raise ValueError("EvidenceManifest.correlation_id cannot be empty")
        if not self.evidence_sha256 or len(self.evidence_sha256) != 64:
            raise ValueError("EvidenceManifest.evidence_sha256 must be a 64-char hex SHA256")
        if not self.artifact_digest.startswith("sha256:"):
            raise ValueError("EvidenceManifest.artifact_digest must start with 'sha256:'")
        if not self.final_state:
            raise ValueError("EvidenceManifest.final_state cannot be empty")
        if not self.generated_at:
            raise ValueError("EvidenceManifest.generated_at cannot be empty")

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "operation_id": self.operation_id,
            "correlation_id": self.correlation_id,
            "evidence_sha256": self.evidence_sha256,
            "artifact_digest": self.artifact_digest,
            "final_state": self.final_state,
            "final_exit_code": self.final_exit_code,
            "generated_at": self.generated_at,
        }
        if self.signature is not None:
            result["signature"] = self.signature
        return result

    def to_canonical_json(self) -> str:
        return to_canonical_json(self.to_dict())

    def to_canonical_bytes(self) -> bytes:
        return to_canonical_bytes(self.to_dict())


def generate_manifest(
    evidence_data: Union[Dict[str, Any], bytes, str],
    signer: Optional[EvidenceSigner] = None,
) -> EvidenceManifest:
    """
    Generates a cryptographic EvidenceManifest from canonical evidence data.
    """
    if isinstance(evidence_data, bytes):
        raw_bytes = evidence_data
        evidence_dict = json.loads(raw_bytes.decode("utf-8"))
    elif isinstance(evidence_data, str):
        evidence_dict = json.loads(evidence_data)
        raw_bytes = to_canonical_bytes(evidence_dict)
    elif isinstance(evidence_data, dict):
        evidence_dict = evidence_data
        raw_bytes = to_canonical_bytes(evidence_dict)
    else:
        if hasattr(evidence_data, "to_dict"):
            evidence_dict = evidence_data.to_dict()
            raw_bytes = to_canonical_bytes(evidence_dict)
        else:
            raise ValueError(f"Unsupported evidence_data type: {type(evidence_data)}")

    evidence_hash = compute_evidence_hash(raw_bytes)
    operation_id = evidence_dict.get("operation_id", "unknown_op")
    correlation_id = evidence_dict.get("correlation_id", "unknown_rel")
    
    # Extract authoritative properties
    auth_sources = evidence_dict.get("authoritative_sources", {})
    art_provenance = auth_sources.get("artifact_provenance", {})
    artifact_digest = art_provenance.get("immutable_digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000")

    verdict = evidence_dict.get("final_verdict", {})
    final_state = verdict.get("state", "UNKNOWN")
    final_exit_code = verdict.get("exit_code", -1)
    completed_at = verdict.get("completed_at", "")

    from datetime import datetime, timezone
    now_iso = completed_at or datetime.now(timezone.utc).isoformat()
    manifest_id = f"man_{operation_id}_{evidence_hash[:12]}"

    sig_provider = signer or HashOnlySigner()
    signature_meta = sig_provider.sign(raw_bytes)

    manifest = EvidenceManifest(
        manifest_id=manifest_id,
        operation_id=operation_id,
        correlation_id=correlation_id,
        evidence_sha256=evidence_hash,
        artifact_digest=artifact_digest,
        final_state=final_state,
        final_exit_code=final_exit_code,
        generated_at=now_iso,
        signature=signature_meta,
    )

    return manifest


def verify_evidence_against_manifest(
    manifest: EvidenceManifest,
    evidence_bytes: bytes,
    signer: Optional[EvidenceSigner] = None,
) -> bool:
    """
    Verifies that the given raw evidence bytes match the manifest's cryptographic hash,
    contained properties, and digital signature.
    Returns False if any tampering is detected.
    """
    if not manifest or not isinstance(manifest, EvidenceManifest):
        return False
    if not evidence_bytes:
        return False

    # 1. Verify SHA-256 hash match
    calculated_hash = compute_evidence_hash(evidence_bytes)
    if calculated_hash != manifest.evidence_sha256:
        return False

    # 2. Parse and verify structural properties
    try:
        evidence_dict = json.loads(evidence_bytes.decode("utf-8"))
    except Exception:
        return False

    if evidence_dict.get("operation_id") != manifest.operation_id:
        return False
    if evidence_dict.get("correlation_id") != manifest.correlation_id:
        return False

    verdict = evidence_dict.get("final_verdict", {})
    if verdict.get("state") != manifest.final_state:
        return False
    if verdict.get("exit_code") != manifest.final_exit_code:
        return False

    auth_sources = evidence_dict.get("authoritative_sources", {})
    art_provenance = auth_sources.get("artifact_provenance", {})
    if art_provenance.get("immutable_digest") != manifest.artifact_digest:
        return False

    # 3. Verify signature if present
    if manifest.signature:
        sig_verifier = signer or HashOnlySigner()
        if not sig_verifier.verify(evidence_bytes, manifest.signature):
            return False

    return True
