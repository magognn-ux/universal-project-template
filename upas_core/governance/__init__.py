"""
UPAS Shared Infrastructure Governance Module.
Enforces shared external infrastructure boundaries and read-only constraints.
"""

from upas_core.governance.infra_guard import (
    SharedInfrastructureGuard,
    verify_infrastructure_boundary,
)

__all__ = [
    "SharedInfrastructureGuard",
    "verify_infrastructure_boundary",
]
