"""
Unit tests for UPAS Artifact Verifier.
Tests descriptor validation, digest format checks, and digest chain consistency.
"""

import pytest
from upas_core.contracts.artifacts import (
    ArtifactDescriptor,
    ArtifactType,
    BuilderMetadata,
)
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import DigestMismatchError, InvalidArtifactError
from upas_core.deployment.artifact_verifier import (
    CanonicalArtifactVerifier,
    validate_canonical_reference,
    validate_digest_format,
    verify_artifact_digest_chain,
)


@pytest.fixture
def valid_descriptor():
    digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    return ArtifactDescriptor(
        artifact_id="art_valid_001",
        project_name="support_bot",
        artifact_type=ArtifactType.CONTAINER_IMAGE,
        canonical_reference=f"registry.internal/support_bot@{digest}",
        immutable_digest=digest,
        source_commit="0123456789abcdef0123456789abcdef01234567",
        source_branch="main",
        build_timestamp="2026-08-28T12:00:00Z",
        builder_metadata=BuilderMetadata(
            ci_run_id="run_100",
            runner_os="ubuntu-22.04",
            toolchain="docker-buildx",
        ),
    )


def test_validate_digest_format():
    valid = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert validate_digest_format(valid) is True

    assert validate_digest_format("latest") is False
    assert validate_digest_format("v1.0.0") is False
    assert validate_digest_format("sha256:1234") is False  # Short
    assert validate_digest_format(valid.upper()) is False  # Uppercase
    assert validate_digest_format("") is False
    assert validate_digest_format(None) is False


def test_validate_canonical_reference():
    digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert validate_canonical_reference(f"docker.io/app@{digest}") is True
    assert validate_canonical_reference(f"ghcr.io/org/repo:v1.0.0@{digest}") is True
    assert validate_canonical_reference("docker.io/app:latest") is False
    assert validate_canonical_reference("docker.io/app:v1.0.0") is False


def test_artifact_verifier_valid_descriptor(valid_descriptor):
    verifier = CanonicalArtifactVerifier()
    res = verifier.validate_descriptor(valid_descriptor)
    assert res.is_valid is True
    assert res.exit_code == ExitCode.SUCCESS
    assert res.approved_digest == valid_descriptor.immutable_digest


def test_artifact_verifier_runtime_digest():
    verifier = CanonicalArtifactVerifier()
    digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    # Exact match
    res_ok = verifier.verify_runtime_digest(digest, digest)
    assert res_ok.is_valid is True
    assert res_ok.exit_code == ExitCode.SUCCESS

    # Match with reference prefix
    res_prefix = verifier.verify_runtime_digest(digest, f"repo/image@{digest}")
    assert res_prefix.is_valid is True

    # Mismatch
    other_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    res_mismatch = verifier.verify_runtime_digest(digest, other_digest)
    assert res_mismatch.is_valid is False
    assert res_mismatch.exit_code == ExitCode.DIGEST_MISMATCH


def test_verify_artifact_digest_chain_gate():
    d1 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    d2 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    d3 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    res = verify_artifact_digest_chain(d1, d2, d3)
    assert res.is_valid is True

    with pytest.raises(DigestMismatchError) as exc_info:
        verify_artifact_digest_chain(d1, d2, "sha256:bad0000000000000000000000000000000000000000000000000000000000000")
    assert exc_info.value.exit_code == ExitCode.DIGEST_MISMATCH
