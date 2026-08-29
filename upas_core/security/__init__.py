"""
UPAS Security & Authorization Module.
Runtime enforcement of OIDC JWT verification, JTI replay protection, and Host Guard.
"""

from upas_core.security.oidc_verifier import GitHubOIDCVerifier, verify_oidc_token
from upas_core.security.jti_store import SQLiteJtiStore, InMemoryJtiStore
from upas_core.security.host_guard import ProductionHostGuard, verify_production_authorization

__all__ = [
    "GitHubOIDCVerifier",
    "verify_oidc_token",
    "SQLiteJtiStore",
    "InMemoryJtiStore",
    "ProductionHostGuard",
    "verify_production_authorization",
]
