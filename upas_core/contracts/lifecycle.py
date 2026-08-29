"""
UPAS Lifecycle State Machines.
Defines typed states and explicit valid transitions for Change, Release, and Deployment lifecycles.
Illegal transitions raise InvalidStateTransitionError (fail-closed).
"""

from enum import Enum
from typing import Dict, Set
from upas_core.contracts.errors import InvalidStateTransitionError


class ChangeState(str, Enum):
    """Lifecycle states for local developer/AI changes."""
    DRAFT = "DRAFT"
    MODIFIED = "MODIFIED"
    TESTED = "TESTED"
    PRECHECK_OK = "PRECHECK_OK"
    COMMITTED = "COMMITTED"


class ReleaseState(str, Enum):
    """Lifecycle states for CI release generation."""
    CI_TRIGGERED = "CI_TRIGGERED"
    CI_TESTING = "CI_TESTING"
    ARTIFACT_BUILDING = "ARTIFACT_BUILDING"
    DIGEST_PINNED = "DIGEST_PINNED"
    RELEASE_CANDIDATE_READY = "RELEASE_CANDIDATE_READY"


class DeploymentState(str, Enum):
    """Lifecycle states for production deployment execution."""
    PROD_APPROVAL_PENDING = "PROD_APPROVAL_PENDING"
    PROD_AUTHORIZED = "PROD_AUTHORIZED"
    LOCK_ACQUIRED = "LOCK_ACQUIRED"
    PREFLIGHT = "PREFLIGHT"
    PRE_DEPLOY_BACKUP = "PRE_DEPLOY_BACKUP"
    MIGRATION = "MIGRATION"
    PULL_BY_DIGEST = "PULL_BY_DIGEST"
    RESTART = "RESTART"
    POST_DEPLOY_VERIFY = "POST_DEPLOY_VERIFY"
    DEPLOYMENT_VERIFIED = "DEPLOYMENT_VERIFIED"
    AUTO_ROLLBACK = "AUTO_ROLLBACK"
    ROLLED_BACK = "ROLLED_BACK"
    EMERGENCY_HALT = "EMERGENCY_HALT"
    UNKNOWN_REMOTE_STATE = "UNKNOWN_REMOTE_STATE"


class ChangeLifecycleStateMachine:
    """Explicit state transitions for Change lifecycle."""

    _VALID_TRANSITIONS: Dict[ChangeState, Set[ChangeState]] = {
        ChangeState.DRAFT: {ChangeState.MODIFIED},
        ChangeState.MODIFIED: {ChangeState.TESTED, ChangeState.DRAFT},
        ChangeState.TESTED: {ChangeState.PRECHECK_OK, ChangeState.MODIFIED},
        ChangeState.PRECHECK_OK: {ChangeState.COMMITTED, ChangeState.MODIFIED},
        ChangeState.COMMITTED: set(),  # Terminal state for local change
    }

    def __init__(self, initial_state: ChangeState = ChangeState.DRAFT):
        self._current_state = initial_state

    @property
    def current_state(self) -> ChangeState:
        return self._current_state

    def can_transition_to(self, target: ChangeState) -> bool:
        return target in self._VALID_TRANSITIONS.get(self._current_state, set())

    def transition_to(self, target: ChangeState) -> ChangeState:
        if not self.can_transition_to(target):
            raise InvalidStateTransitionError(
                current_state=self._current_state.value,
                target_state=target.value,
                lifecycle="ChangeLifecycle",
            )
        self._current_state = target
        return self._current_state


class ReleaseLifecycleStateMachine:
    """Explicit state transitions for Release lifecycle."""

    _VALID_TRANSITIONS: Dict[ReleaseState, Set[ReleaseState]] = {
        ReleaseState.CI_TRIGGERED: {ReleaseState.CI_TESTING},
        ReleaseState.CI_TESTING: {ReleaseState.ARTIFACT_BUILDING},
        ReleaseState.ARTIFACT_BUILDING: {ReleaseState.DIGEST_PINNED},
        ReleaseState.DIGEST_PINNED: {ReleaseState.RELEASE_CANDIDATE_READY},
        ReleaseState.RELEASE_CANDIDATE_READY: set(),  # Terminal state for release preparation
    }

    def __init__(self, initial_state: ReleaseState = ReleaseState.CI_TRIGGERED):
        self._current_state = initial_state

    @property
    def current_state(self) -> ReleaseState:
        return self._current_state

    def can_transition_to(self, target: ReleaseState) -> bool:
        return target in self._VALID_TRANSITIONS.get(self._current_state, set())

    def transition_to(self, target: ReleaseState) -> ReleaseState:
        if not self.can_transition_to(target):
            raise InvalidStateTransitionError(
                current_state=self._current_state.value,
                target_state=target.value,
                lifecycle="ReleaseLifecycle",
            )
        self._current_state = target
        return self._current_state


class DeploymentLifecycleStateMachine:
    """Explicit state transitions for Deployment lifecycle."""

    _VALID_TRANSITIONS: Dict[DeploymentState, Set[DeploymentState]] = {
        DeploymentState.PROD_APPROVAL_PENDING: {
            DeploymentState.PROD_AUTHORIZED,
            DeploymentState.EMERGENCY_HALT,
        },
        DeploymentState.PROD_AUTHORIZED: {
            DeploymentState.LOCK_ACQUIRED,
            DeploymentState.EMERGENCY_HALT,
        },
        DeploymentState.LOCK_ACQUIRED: {
            DeploymentState.PREFLIGHT,
            DeploymentState.EMERGENCY_HALT,
        },
        DeploymentState.PREFLIGHT: {
            DeploymentState.PRE_DEPLOY_BACKUP,
            DeploymentState.EMERGENCY_HALT,
        },
        DeploymentState.PRE_DEPLOY_BACKUP: {
            DeploymentState.MIGRATION,
            DeploymentState.EMERGENCY_HALT,
        },
        DeploymentState.MIGRATION: {
            DeploymentState.PULL_BY_DIGEST,
            DeploymentState.EMERGENCY_HALT,
        },
        DeploymentState.PULL_BY_DIGEST: {
            DeploymentState.RESTART,
            DeploymentState.AUTO_ROLLBACK,
            DeploymentState.EMERGENCY_HALT,
            DeploymentState.UNKNOWN_REMOTE_STATE,
        },
        DeploymentState.RESTART: {
            DeploymentState.POST_DEPLOY_VERIFY,
            DeploymentState.AUTO_ROLLBACK,
            DeploymentState.EMERGENCY_HALT,
            DeploymentState.UNKNOWN_REMOTE_STATE,
        },
        DeploymentState.POST_DEPLOY_VERIFY: {
            DeploymentState.DEPLOYMENT_VERIFIED,
            DeploymentState.AUTO_ROLLBACK,
            DeploymentState.EMERGENCY_HALT,
            DeploymentState.UNKNOWN_REMOTE_STATE,
        },
        DeploymentState.AUTO_ROLLBACK: {
            DeploymentState.ROLLED_BACK,
            DeploymentState.EMERGENCY_HALT,
            DeploymentState.UNKNOWN_REMOTE_STATE,
        },
        DeploymentState.DEPLOYMENT_VERIFIED: set(),
        DeploymentState.ROLLED_BACK: set(),
        DeploymentState.EMERGENCY_HALT: set(),
        DeploymentState.UNKNOWN_REMOTE_STATE: set(),
    }

    def __init__(self, initial_state: DeploymentState = DeploymentState.PROD_APPROVAL_PENDING):
        self._current_state = initial_state

    @property
    def current_state(self) -> DeploymentState:
        return self._current_state

    def can_transition_to(self, target: DeploymentState) -> bool:
        return target in self._VALID_TRANSITIONS.get(self._current_state, set())

    def transition_to(self, target: DeploymentState) -> DeploymentState:
        if not self.can_transition_to(target):
            raise InvalidStateTransitionError(
                current_state=self._current_state.value,
                target_state=target.value,
                lifecycle="DeploymentLifecycle",
            )
        self._current_state = target
        return self._current_state
