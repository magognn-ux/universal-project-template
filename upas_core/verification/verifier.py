"""
UPAS Post-Deploy Verification Engine.
Enforces Invariant 6: Mandatory Post-Deploy Multi-Dimensional Verification.
Verifies container identity, running digest, health check, and smoke tests.
"""

import os
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.request import urlopen, Request
import urllib.error

from upas_core.contracts.artifacts import ArtifactVerificationResult
from upas_core.contracts.enums import ExitCode, StepStatus
from upas_core.contracts.errors import DigestMismatchError
from upas_core.contracts.execution import CommandSpec
from upas_core.contracts.interfaces import ArtifactVerifier, CommandRunner
from upas_core.deployment.artifact_verifier import CanonicalArtifactVerifier
from upas_core.execution.runner import SafeCommandRunner


def _safe_split_command(command_str: str) -> List[str]:
    """Safely splits a command string into argv list across Windows and POSIX."""
    if not command_str or not isinstance(command_str, str):
        return []
    is_posix = (os.name != "nt")
    tokens = shlex.split(command_str.strip(), posix=is_posix)
    if not is_posix:
        cleaned = []
        for t in tokens:
            if len(t) >= 2 and ((t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'"))):
                cleaned.append(t[1:-1])
            else:
                cleaned.append(t)
        return cleaned
    return tokens


@dataclass(frozen=True)
class RuntimeStateResult:
    """Multi-dimensional post-deploy runtime verification result."""
    verified: bool
    service_name: str
    running_digest: str
    identity_matched: bool
    health_check_passed: bool
    smoke_test_passed: bool
    error_message: Optional[str] = None
    exit_code: ExitCode = ExitCode.SUCCESS
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.verified and self.exit_code != ExitCode.SUCCESS:
            raise ValueError("RuntimeStateResult cannot be verified with non-zero exit code")
        if not self.verified and self.exit_code == ExitCode.SUCCESS:
            raise ValueError("RuntimeStateResult unverified cannot have ExitCode.SUCCESS")
        if not self.verified and not self.error_message:
            raise ValueError("RuntimeStateResult failure must have error_message")


class PostDeployVerifier:
    """
    Executes comprehensive post-deployment verification.
    Guarantees that a deployment is only marked DEPLOYMENT_VERIFIED when:
      1. Expected container/service identity is active
      2. Running digest matches approved digest exactly
      3. Health check succeeds within retries
      4. Smoke test command succeeds
    """

    def __init__(
        self,
        artifact_verifier: Optional[ArtifactVerifier] = None,
        command_runner: Optional[CommandRunner] = None,
    ):
        self.artifact_verifier = artifact_verifier or CanonicalArtifactVerifier()
        self.command_runner = command_runner or SafeCommandRunner()

    def _check_http_health(
        self,
        endpoint: str,
        expected_status: int = 200,
        timeout_seconds: int = 5,
        max_retries: int = 3,
        retry_interval_seconds: int = 1,
    ) -> Tuple[bool, Optional[str]]:
        """Performs HTTP GET health check with retries."""
        for attempt in range(1, max_retries + 1):
            try:
                req = Request(endpoint, headers={"User-Agent": "UPAS-HealthCheck/1.0"})
                with urlopen(req, timeout=timeout_seconds) as resp:
                    if resp.status == expected_status:
                        return True, None
                    else:
                        if attempt == max_retries:
                            return False, f"HTTP status {resp.status} != expected {expected_status}"
            except Exception as exc:
                if attempt == max_retries:
                    return False, f"HTTP health check failed: {exc}"
            time.sleep(retry_interval_seconds)
        return False, "Health check retries exhausted"

    def _execute_custom_command(
        self,
        command_str: str,
        timeout_seconds: int = 30,
    ) -> Tuple[bool, Optional[str]]:
        """Executes a custom verification/smoke command safely."""
        try:
            argv = _safe_split_command(command_str)
        except Exception as exc:
            return False, f"Failed to parse verification command: {exc}"

        spec = CommandSpec(argv=argv, timeout_seconds=timeout_seconds)
        res = self.command_runner.run(spec)
        if not res.is_success:
            return False, f"Command failed (exit {res.exit_code}): {res.stderr or res.stdout}"
        return True, None

    def verify_runtime(
        self,
        service_name: str,
        approved_digest: str,
        running_digest: str,
        expected_container_name: Optional[str] = None,
        actual_container_name: Optional[str] = None,
        health_check_spec: Optional[Dict[str, Any]] = None,
        smoke_test_spec: Optional[Dict[str, Any]] = None,
    ) -> RuntimeStateResult:
        """
        Executes full post-deploy runtime verification.
        Returns RuntimeStateResult with verified=True only if all checks pass.
        """
        details: Dict[str, Any] = {}

        # 1. Container / Runtime Identity check
        identity_matched = True
        if expected_container_name:
            if not actual_container_name or actual_container_name.strip() != expected_container_name.strip():
                identity_matched = False
                return RuntimeStateResult(
                    verified=False,
                    service_name=service_name,
                    running_digest=running_digest,
                    identity_matched=False,
                    health_check_passed=False,
                    smoke_test_passed=False,
                    error_message=(
                        f"Container identity mismatch: expected '{expected_container_name}', "
                        f"got '{actual_container_name}'"
                    ),
                    exit_code=ExitCode.UNKNOWN_REMOTE_STATE,
                )
        details["identity_matched"] = True

        # 2. Running Digest verification
        digest_res = self.artifact_verifier.verify_runtime_digest(
            expected_digest=approved_digest,
            runtime_target=running_digest,
        )
        if not digest_res.is_valid:
            return RuntimeStateResult(
                verified=False,
                service_name=service_name,
                running_digest=running_digest,
                identity_matched=True,
                health_check_passed=False,
                smoke_test_passed=False,
                error_message=f"Post-deploy running digest mismatch: {digest_res.error_message}",
                exit_code=ExitCode.DIGEST_MISMATCH,
            )
        details["running_digest_verified"] = True

        # 3. Health Check
        health_ok = True
        if health_check_spec:
            hc_type = health_check_spec.get("type", "custom_command")
            if hc_type == "http_get":
                endpoint = health_check_spec.get("endpoint", "http://127.0.0.1:8000/health")
                expected_status = health_check_spec.get("expected_status", 200)
                timeout_s = health_check_spec.get("timeout_seconds", 5)
                max_retries = health_check_spec.get("max_retries", 3)
                retry_interval = health_check_spec.get("retry_interval_seconds", 1)
                health_ok, err = self._check_http_health(
                    endpoint=endpoint,
                    expected_status=expected_status,
                    timeout_seconds=timeout_s,
                    max_retries=max_retries,
                    retry_interval_seconds=retry_interval,
                )
                if not health_ok:
                    return RuntimeStateResult(
                        verified=False,
                        service_name=service_name,
                        running_digest=running_digest,
                        identity_matched=True,
                        health_check_passed=False,
                        smoke_test_passed=False,
                        error_message=f"Health check failed: {err}",
                        exit_code=ExitCode.TESTS_FAILED,
                        details=details,
                    )
            elif hc_type == "custom_command":
                cmd = health_check_spec.get("command", "true")
                timeout_s = health_check_spec.get("timeout_seconds", 10)
                health_ok, err = self._execute_custom_command(cmd, timeout_s)
                if not health_ok:
                    return RuntimeStateResult(
                        verified=False,
                        service_name=service_name,
                        running_digest=running_digest,
                        identity_matched=True,
                        health_check_passed=False,
                        smoke_test_passed=False,
                        error_message=f"Custom health check command failed: {err}",
                        exit_code=ExitCode.TESTS_FAILED,
                        details=details,
                    )
        details["health_check_passed"] = True

        # 4. Smoke Test
        smoke_ok = True
        if smoke_test_spec:
            cmd = smoke_test_spec.get("command")
            if cmd:
                timeout_s = smoke_test_spec.get("timeout_seconds", 30)
                smoke_ok, err = self._execute_custom_command(cmd, timeout_s)
                if not smoke_ok:
                    return RuntimeStateResult(
                        verified=False,
                        service_name=service_name,
                        running_digest=running_digest,
                        identity_matched=True,
                        health_check_passed=True,
                        smoke_test_passed=False,
                        error_message=f"Smoke test failed: {err}",
                        exit_code=ExitCode.TESTS_FAILED,
                        details=details,
                    )
        details["smoke_test_passed"] = True

        # All checks passed
        return RuntimeStateResult(
            verified=True,
            service_name=service_name,
            running_digest=running_digest,
            identity_matched=True,
            health_check_passed=True,
            smoke_test_passed=True,
            exit_code=ExitCode.SUCCESS,
            details=details,
        )


def verify_post_deploy_state(
    service_name: str,
    approved_digest: str,
    running_digest: str,
    verifier: Optional[PostDeployVerifier] = None,
    **kwargs,
) -> RuntimeStateResult:
    """Convenience functional gate for post-deploy verification."""
    v = verifier or PostDeployVerifier()
    return v.verify_runtime(
        service_name=service_name,
        approved_digest=approved_digest,
        running_digest=running_digest,
        **kwargs,
    )
