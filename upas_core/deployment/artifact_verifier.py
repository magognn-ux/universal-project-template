"""
UPAS Immutable Artifact Verification Engine.
Implements the ArtifactVerifier protocol.
Enforces Invariant 1: Multi-Point Digest Integrity (Exit Code 65).
"""

import re
from typing import Optional
from upas_core.contracts.artifacts import ArtifactDescriptor, ArtifactVerificationResult
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import DigestMismatchError, InvalidArtifactError
from upas_core.contracts.interfaces import ArtifactVerifier

_IMMUTABLE_DIGEST_REGEX = re.compile(r"^sha256:[a-f0-9]{64}$")
_CANONICAL_REF_REGEX = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")


def validate_digest_format(digest: str) -> bool:
    """Validates that a digest string strictly matches sha256:<64 lowercase hex>."""
    if not digest or not isinstance(digest, str):
        return False
    return bool(_IMMUTABLE_DIGEST_REGEX.match(digest.strip()))


def validate_canonical_reference(reference: str) -> bool:
    """Validates that a canonical reference ends with @sha256:<64 lowercase hex>."""
    if not reference or not isinstance(reference, str):
        return False
    return bool(_CANONICAL_REF_REGEX.match(reference.strip()))


class CanonicalArtifactVerifier(ArtifactVerifier):
    """
    Authoritative verification engine for immutable artifacts.
    Verifies descriptor integrity, format correctness, and the full digest chain:
    APPROVED_DIGEST == PULLED_DIGEST == RUNNING_DIGEST.
    """

    def validate_descriptor(self, descriptor: ArtifactDescriptor) -> ArtifactVerificationResult:
        """
        Validates artifact descriptor structure and canonical immutable pinning.
        Fails closed on mutable tags, short SHAs, uppercase SHAs, or mismatching refs.
        """
        if not descriptor or not isinstance(descriptor, ArtifactDescriptor):
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest="unknown",
                error_message="Invalid or missing ArtifactDescriptor instance",
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        if not validate_digest_format(descriptor.immutable_digest):
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=descriptor.immutable_digest,
                error_message=(
                    f"Immutable digest '{descriptor.immutable_digest}' is invalid. "
                    "Must strictly match 'sha256:<64 lowercase hex>'."
                ),
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        if not validate_canonical_reference(descriptor.canonical_reference):
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=descriptor.immutable_digest,
                error_message=(
                    f"Canonical reference '{descriptor.canonical_reference}' is invalid. "
                    "Must strictly end with '@sha256:<64 lowercase hex>' (no mutable tags)."
                ),
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        ref_digest = descriptor.canonical_reference.split("@")[-1]
        if ref_digest != descriptor.immutable_digest:
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=descriptor.immutable_digest,
                error_message=(
                    f"Canonical reference digest '{ref_digest}' does not match "
                    f"immutable_digest '{descriptor.immutable_digest}'."
                ),
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        # Descriptor is structurally valid
        return ArtifactVerificationResult(
            is_valid=True,
            approved_digest=descriptor.immutable_digest,
            pulled_digest=descriptor.immutable_digest,
            running_digest=descriptor.immutable_digest,
            exit_code=ExitCode.SUCCESS,
        )

    def verify_runtime_digest(
        self,
        expected_digest: str,
        runtime_target: str,
    ) -> ArtifactVerificationResult:
        """
        Verifies that a running runtime target matches the expected immutable digest.
        """
        if not validate_digest_format(expected_digest):
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=str(expected_digest),
                error_message=f"Invalid expected digest format: '{expected_digest}'",
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        if not runtime_target or not isinstance(runtime_target, str) or not runtime_target.strip():
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=expected_digest,
                running_digest="unknown",
                error_message="Runtime target digest is missing or empty",
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        cleaned_target = runtime_target.strip()
        # Handle cases where runtime_target might be image@sha256:... or just sha256:...
        target_digest = cleaned_target.split("@")[-1] if "@" in cleaned_target else cleaned_target

        if not validate_digest_format(target_digest):
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=expected_digest,
                running_digest=target_digest,
                error_message=f"Runtime target digest '{target_digest}' is malformed",
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        if target_digest != expected_digest:
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=expected_digest,
                running_digest=target_digest,
                error_message=(
                    f"Runtime digest mismatch: expected '{expected_digest}', "
                    f"found running '{target_digest}'"
                ),
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        return ArtifactVerificationResult(
            is_valid=True,
            approved_digest=expected_digest,
            pulled_digest=expected_digest,
            running_digest=target_digest,
            exit_code=ExitCode.SUCCESS,
        )

    def verify_digest_chain(
        self,
        approved_digest: str,
        pulled_digest: str,
        running_digest: str,
    ) -> ArtifactVerificationResult:
        """
        Enforces the complete digest verification chain:
        APPROVED_DIGEST == PULLED_DIGEST == RUNNING_DIGEST.
        """
        for label, dig in [("approved", approved_digest), ("pulled", pulled_digest), ("running", running_digest)]:
            if not validate_digest_format(dig):
                return ArtifactVerificationResult(
                    is_valid=False,
                    approved_digest=str(approved_digest),
                    pulled_digest=str(pulled_digest) if pulled_digest else None,
                    running_digest=str(running_digest) if running_digest else None,
                    error_message=f"Invalid {label} digest format: '{dig}'",
                    exit_code=ExitCode.DIGEST_MISMATCH,
                )

        if approved_digest != pulled_digest:
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=approved_digest,
                pulled_digest=pulled_digest,
                running_digest=running_digest,
                error_message=(
                    f"Digest mismatch between approved '{approved_digest}' and pulled '{pulled_digest}'"
                ),
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        if approved_digest != running_digest:
            return ArtifactVerificationResult(
                is_valid=False,
                approved_digest=approved_digest,
                pulled_digest=pulled_digest,
                running_digest=running_digest,
                error_message=(
                    f"Digest mismatch between approved '{approved_digest}' and running '{running_digest}'"
                ),
                exit_code=ExitCode.DIGEST_MISMATCH,
            )

        return ArtifactVerificationResult(
            is_valid=True,
            approved_digest=approved_digest,
            pulled_digest=pulled_digest,
            running_digest=running_digest,
            exit_code=ExitCode.SUCCESS,
        )


def verify_artifact_digest_chain(
    approved_digest: str,
    pulled_digest: str,
    running_digest: str,
    verifier: Optional[ArtifactVerifier] = None,
) -> ArtifactVerificationResult:
    """
    Fail-closed gate function for digest chain validation.
    Raises DigestMismatchError (exit code 65) if any digest fails or mismatches.
    """
    v = verifier or CanonicalArtifactVerifier()
    if isinstance(v, CanonicalArtifactVerifier):
        res = v.verify_digest_chain(approved_digest, pulled_digest, running_digest)
    else:
        # Fallback using protocol methods
        res1 = v.verify_runtime_digest(approved_digest, pulled_digest)
        if not res1.is_valid:
            res = res1
        else:
            res = v.verify_runtime_digest(approved_digest, running_digest)

    if not res.is_valid:
        raise DigestMismatchError(res.error_message or "Digest chain verification failed")
    return res
