"""
UPAS Artifact Descriptor Contracts.
Defines typed immutable artifact specifications matching artifact.schema.json.
Guarantees canonical pinned identity: registry/image@sha256:<64 lowercase hex>.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from upas_core.contracts.enums import ArtifactType, ExitCode
from upas_core.contracts.errors import InvalidArtifactError

_ARTIFACT_ID_REGEX = re.compile(r"^art_[a-zA-Z0-9_\-\.]+$")
_PROJECT_NAME_REGEX = re.compile(r"^[a-z0-9_\-]+$")
_CANONICAL_REF_REGEX = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
_IMMUTABLE_DIGEST_REGEX = re.compile(r"^sha256:[a-f0-9]{64}$")
_COMMIT_SHA_REGEX = re.compile(r"^[a-f0-9]{40}$")


@dataclass(frozen=True)
class BuilderMetadata:
    """CI / build environment metadata."""
    ci_run_id: str
    runner_os: str
    toolchain: str

    def __post_init__(self):
        if not self.ci_run_id or not self.runner_os or not self.toolchain:
            raise ValueError("BuilderMetadata fields cannot be empty")


@dataclass(frozen=True)
class SignatureMetadata:
    """Cryptographic signature / provenance attestation metadata."""
    provenance_attestation: str
    verified: bool
    key_id: Optional[str] = None


@dataclass(frozen=True)
class ArtifactDescriptor:
    """
    Immutable Artifact Descriptor matching artifact.schema.json.
    Strictly forbids mutable tags, uppercase SHA, short SHA, or unpinned references.
    """
    artifact_id: str
    project_name: str
    artifact_type: ArtifactType
    canonical_reference: str
    immutable_digest: str
    source_commit: str
    source_branch: str
    build_timestamp: str
    builder_metadata: BuilderMetadata
    schema_version: str = "1.0.0"
    human_readable_tags: List[str] = field(default_factory=list)
    signature: Optional[SignatureMetadata] = None

    def __post_init__(self):
        if self.schema_version != "1.0.0":
            raise InvalidArtifactError(f"Invalid artifact schema_version: {self.schema_version}")
        if not _ARTIFACT_ID_REGEX.match(self.artifact_id):
            raise InvalidArtifactError(f"Malformed artifact_id: {self.artifact_id}")
        if not _PROJECT_NAME_REGEX.match(self.project_name):
            raise InvalidArtifactError(f"Malformed project_name: {self.project_name}")
        if not _IMMUTABLE_DIGEST_REGEX.match(self.immutable_digest):
            raise InvalidArtifactError(
                f"Malformed immutable_digest (must be sha256:<64 lowercase hex>): {self.immutable_digest}"
            )
        if not _CANONICAL_REF_REGEX.match(self.canonical_reference):
            raise InvalidArtifactError(
                f"Malformed canonical_reference (must end with @sha256:<64 lowercase hex>): {self.canonical_reference}"
            )
        # Verify the digest inside canonical_reference matches immutable_digest exactly
        ref_digest = self.canonical_reference.split("@")[-1]
        if ref_digest != self.immutable_digest:
            raise InvalidArtifactError(
                f"Canonical reference digest ({ref_digest}) does not match immutable_digest ({self.immutable_digest})"
            )
        if not _COMMIT_SHA_REGEX.match(self.source_commit):
            raise InvalidArtifactError(f"Malformed source_commit (must be 40 hex chars): {self.source_commit}")
        if not self.source_branch:
            raise InvalidArtifactError("source_branch cannot be empty")
        if not self.build_timestamp:
            raise InvalidArtifactError("build_timestamp cannot be empty")


@dataclass(frozen=True)
class ArtifactVerificationResult:
    """Result of multi-point artifact digest verification (approved == pulled == running)."""
    is_valid: bool
    approved_digest: str
    pulled_digest: Optional[str] = None
    running_digest: Optional[str] = None
    error_message: Optional[str] = None
    exit_code: ExitCode = ExitCode.SUCCESS

    def __post_init__(self):
        if self.is_valid:
            if self.approved_digest != self.pulled_digest or self.approved_digest != self.running_digest:
                raise ValueError("ArtifactVerificationResult cannot be valid when digests mismatch")
            if self.exit_code != ExitCode.SUCCESS:
                raise ValueError("ArtifactVerificationResult valid state cannot have non-zero exit code")
        else:
            if self.exit_code == ExitCode.SUCCESS:
                raise ValueError("ArtifactVerificationResult invalid state must have non-zero exit code")
            if not self.error_message:
                raise ValueError("ArtifactVerificationResult invalid state must have error_message")
