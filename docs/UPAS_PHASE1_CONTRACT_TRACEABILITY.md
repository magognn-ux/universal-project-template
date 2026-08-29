# UPAS Phase 1 — Contract Traceability Matrix (Hardened)

This document provides end-to-end architectural traceability between the hardened UPAS Architecture Invariants and their corresponding machine-readable JSON Schema implementations, structural constraints, and automated adversarial validation tests.

---

## Traceability Mapping Table

| Architecture Invariant | Hardened Requirement | Target Schema | Schema Field / Structural Rule | Validation Test (Automated) |
| :--- | :--- | :--- | :--- | :--- |
| **Production Authorization** | Only GitHub Environment OIDC JWT is valid for production mutations; local text tokens are rejected; core claims (repository, environment, ref, job_workflow_ref) mandatory. | `upas.adapter.schema.json` | `authorization.provider` (enum `["github_environment_oidc"]`), `authorization.expected_issuer` (enum `["https://token.actions.githubusercontent.com"]`), `authorization.required_claims` (minItems: 4). | `test_malformed_oidc_issuer_fails`, `test_missing_core_oidc_claims_fails`, `test_tour_monitor_adapter_valid` |
| **Immutable Digest** | Artifact identity is strictly pinned by `@sha256:[a-f0-9]{64}`. Tags, uppercase hex, short digests, and double `@` are forbidden. | `artifact.schema.json` | `canonical_reference` (pattern `^[^\\s@]+@sha256:[a-f0-9]{64}$`), `immutable_digest` (pattern `^sha256:[a-f0-9]{64}$`). | `test_tag_only_artifact_fails_digest_rule`, `test_double_at_artifact_fails`, `test_uppercase_sha_artifact_fails`, `test_short_sha_digest_fails`, `test_malformed_digest_fails`, `test_artifact_valid` |
| **Deployment Concurrency** | Dual-lock mutual exclusion in CI and Host. Absolute host path and positive timeout enforced. | `upas.adapter.schema.json` & `evidence.schema.json` | `deployment.concurrency_group`, `deployment.host_lock_path` (pattern `^/.*`), `deployment.lock_timeout_seconds` (minimum: 1), `authoritative_sources.host_runtime.lock_state`. | `test_zero_timeout_concurrency_fails`, `test_invalid_host_lock_path_fails`, `test_evidence_valid`, `test_tour_monitor_adapter_valid` |
| **Database Migration Safety** | Two-phase protocol enforced for non-additive migrations. Automatic rollback forbidden for incompatible schemas. | `upas.adapter.schema.json` & `evidence.schema.json` | `migration.default_classification` (enum `["NONE", "ADDITIVE_COMPATIBLE", "POTENTIALLY_INCOMPATIBLE", "DESTRUCTIVE_IRREVERSIBLE"]`), conditional rule `if POTENTIALLY_INCOMPATIBLE then two_phase_protocol: true`. | `test_invalid_migration_class_fails`, `test_incompatible_migration_without_two_phase_fails`, `test_support_bot_adapter_valid` |
| **Test Budget & Escalation** | 5-tier testing (L0-L5) with non-lowerable DB migration escalation triggers (min Level 4 or 5). | `upas.adapter.schema.json` | `test_engine.level_commands` (L0-L5 required), `test_engine.escalation_triggers.database_migrations` (enum `[4, 5]`). | `test_invalid_test_level_fails`, `test_lowered_db_migration_escalation_fails`, `test_minimal_adapter_valid` |
| **Shared Infrastructure Boundary** | Application adapters can only consume shared infrastructure as readonly consumers (`type: external`, `access: readonly_consumer`). | `upas.adapter.schema.json` | `infrastructure_dependencies[].type` (enum `["external"]`), `infrastructure_dependencies[].access` (enum `["readonly_consumer"]`). | `test_invalid_infra_dependency_fails`, `test_shared_infra_write_access_fails`, `test_tour_monitor_adapter_valid` |
| **Strict Schema Versioning** | Fail-closed validation on mismatched schema version or unexpected properties. | All Schemas | `schema_version` (enum `["1.0.0"]`), `additionalProperties: false`. | `test_invalid_schema_version_fails`, `test_unknown_field_fails`, `test_missing_required_field_fails` |
| **Evidence Authority Hierarchy** | Evidence is an audit log referencing external authoritative sources (Git, CI, OCI, Host). | `evidence.schema.json` | `authoritative_sources` (git_dag, ci_execution, artifact_provenance, production_authorization, host_runtime), `final_verdict.state`. | `test_invalid_evidence_state_fails`, `test_evidence_valid` |
| **Capability Manifest & Documentation Reality** | Machine-readable manifest of active capabilities to prevent documentation drift. | `upas.manifest.schema.json` | `cli_commands`, `capabilities`, `documentation_contract.required_documents`, `security_invariants`. | `test_invalid_manifest_invariants_fails`, `test_manifest_valid` |
| **Resource Gate Pre-Flight** | Bounded non-negative thresholds for RAM, Swap (<=100%), Load, and Disk headroom before mutation. | `upas.adapter.schema.json` | `resource_gate.pre_flight_checks` (min_free_ram_mb >= 0, max_swap_usage_pct <= 100, max_1m_load_average >= 0, min_free_disk_gb >= 0). | `test_invalid_resource_gate_fails`, `test_tour_monitor_adapter_valid` |

---

## Schema Files Reference

1. **`schemas/upas.adapter.schema.json`**: [Adapter Schema](file:///c:/Users/user/Projects/universal-project-template/schemas/upas.adapter.schema.json)
2. **`schemas/artifact.schema.json`**: [Artifact Schema](file:///c:/Users/user/Projects/universal-project-template/schemas/artifact.schema.json)
3. **`schemas/evidence.schema.json`**: [Evidence Schema](file:///c:/Users/user/Projects/universal-project-template/schemas/evidence.schema.json)
4. **`schemas/upas.manifest.schema.json`**: [Manifest Schema](file:///c:/Users/user/Projects/universal-project-template/schemas/upas.manifest.schema.json)

## Test Harness Reference

- **Test Suite**: [tests/test_schemas_validation.py](file:///c:/Users/user/Projects/universal-project-template/tests/test_schemas_validation.py)
- **Positive Fixtures**: `tests/fixtures/valid/` (6 fixtures)
- **Negative Adversarial Fixtures**: `tests/fixtures/invalid/` (21 fixtures)
- **Total Test Count**: 31 tests (100% PASS)
