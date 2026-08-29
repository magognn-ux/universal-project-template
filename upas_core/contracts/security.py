"""
UPAS Security & Authorization Contracts.
Models OIDC claims, verification parameters, and structured authorization results.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from upas_core.contracts.enums import AuthPolicy, ExitCode


@dataclass(frozen=True)
class OIDCClaims:
    """Standard GitHub Actions OIDC JWT claims required by UPAS Host Guard."""
    iss: str
    aud: str
    repository: str
    environment: str
    ref: str
    job_workflow_ref: str
    jti: str
    exp: int
    sub: Optional[str] = None
    run_id: Optional[str] = None
    actor: Optional[str] = None

    def __post_init__(self):
        if not self.iss:
            raise ValueError("OIDC claim 'iss' cannot be empty")
        if not self.aud:
            raise ValueError("OIDC claim 'aud' cannot be empty")
        if not self.repository:
            raise ValueError("OIDC claim 'repository' cannot be empty")
        if not self.environment:
            raise ValueError("OIDC claim 'environment' cannot be empty")
        if not self.ref:
            raise ValueError("OIDC claim 'ref' cannot be empty")
        if not self.job_workflow_ref:
            raise ValueError("OIDC claim 'job_workflow_ref' cannot be empty")
        if not self.jti:
            raise ValueError("OIDC claim 'jti' cannot be empty")
        if self.exp <= 0:
            raise ValueError("OIDC claim 'exp' must be a positive unix timestamp")

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "iss": self.iss,
            "aud": self.aud,
            "repository": self.repository,
            "environment": self.environment,
            "ref": self.ref,
            "job_workflow_ref": self.job_workflow_ref,
            "jti": self.jti,
            "exp": self.exp,
        }
        if self.sub:
            result["sub"] = self.sub
        if self.run_id:
            result["run_id"] = self.run_id
        if self.actor:
            result["actor"] = self.actor
        return result


@dataclass(frozen=True)
class OIDCExpectedConfig:
    """Expected OIDC claims configuration derived from upas.adapter.yaml."""
    expected_issuer: str
    expected_audience: str
    expected_repository: str
    expected_environment: str
    required_claims: List[str]

    def __post_init__(self):
        if self.expected_issuer != "https://token.actions.githubusercontent.com":
            raise ValueError(f"Invalid OIDC expected issuer: {self.expected_issuer}")
        if not self.expected_audience:
            raise ValueError("OIDC expected audience cannot be empty")
        if not self.expected_repository:
            raise ValueError("OIDC expected repository cannot be empty")
        if not self.expected_environment:
            raise ValueError("OIDC expected environment cannot be empty")
        if len(self.required_claims) < 4:
            raise ValueError("OIDC required_claims must contain at least 4 core claims")


@dataclass(frozen=True)
class AuthResult:
    """Structured result of production authorization gate verification."""
    authenticated: bool
    policy: AuthPolicy
    actor: str
    run_id: str
    environment: str
    approval_timestamp: str
    claims: Optional[OIDCClaims] = None
    error_message: Optional[str] = None
    exit_code: ExitCode = ExitCode.SUCCESS

    def __post_init__(self):
        if self.authenticated and self.exit_code != ExitCode.SUCCESS:
            raise ValueError("AuthResult cannot be authenticated with a non-zero exit code")
        if not self.authenticated and self.exit_code == ExitCode.SUCCESS:
            raise ValueError("AuthResult unauthenticated cannot have ExitCode.SUCCESS")
        if not self.authenticated and not self.error_message:
            raise ValueError("AuthResult failure must provide an error_message")
