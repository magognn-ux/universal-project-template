import json
from pathlib import Path
import pytest
import jsonschema
from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "schemas"
FIXTURES_VALID_DIR = REPO_ROOT / "tests" / "fixtures" / "valid"
FIXTURES_INVALID_DIR = REPO_ROOT / "tests" / "fixtures" / "invalid"


def load_json(file_path: Path) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def adapter_schema():
    return load_json(SCHEMAS_DIR / "upas.adapter.schema.json")


@pytest.fixture(scope="session")
def artifact_schema():
    return load_json(SCHEMAS_DIR / "artifact.schema.json")


@pytest.fixture(scope="session")
def evidence_schema():
    return load_json(SCHEMAS_DIR / "evidence.schema.json")


@pytest.fixture(scope="session")
def manifest_schema():
    return load_json(SCHEMAS_DIR / "upas.manifest.schema.json")


class TestSchemaIntegrity:
    """Validates that all UPAS schemas conform to Draft-07 JSON Schema standard."""

    @pytest.mark.parametrize(
        "schema_name",
        [
            "upas.adapter.schema.json",
            "artifact.schema.json",
            "evidence.schema.json",
            "upas.manifest.schema.json",
        ],
    )
    def test_schema_is_valid_draft7(self, schema_name):
        schema_path = SCHEMAS_DIR / schema_name
        assert schema_path.exists(), f"Schema {schema_name} does not exist"
        schema_data = load_json(schema_path)
        Draft7Validator.check_schema(schema_data)


class TestValidFixtures:
    """Validates all valid reference fixtures against their corresponding schemas."""

    def test_minimal_adapter_valid(self, adapter_schema):
        data = load_json(FIXTURES_VALID_DIR / "minimal_adapter.json")
        validator = Draft7Validator(adapter_schema)
        errors = list(validator.iter_errors(data))
        assert not errors, f"Validation errors: {[e.message for e in errors]}"

    def test_support_bot_adapter_valid(self, adapter_schema):
        data = load_json(FIXTURES_VALID_DIR / "support_bot_adapter.json")
        validator = Draft7Validator(adapter_schema)
        errors = list(validator.iter_errors(data))
        assert not errors, f"Validation errors: {[e.message for e in errors]}"

    def test_tour_monitor_adapter_valid(self, adapter_schema):
        data = load_json(FIXTURES_VALID_DIR / "tour_monitor_adapter.json")
        validator = Draft7Validator(adapter_schema)
        errors = list(validator.iter_errors(data))
        assert not errors, f"Validation errors: {[e.message for e in errors]}"

    def test_self_hosting_adapter_valid(self, adapter_schema):
        self_adapter_path = REPO_ROOT / "upas.adapter.json"
        if self_adapter_path.exists():
            data = load_json(self_adapter_path)
            validator = Draft7Validator(adapter_schema)
            errors = list(validator.iter_errors(data))
            assert not errors, f"Validation errors: {[e.message for e in errors]}"

    def test_all_archetypes_generated_templates_valid(self, adapter_schema):
        from upas_core.cli.init_cmd import (
            DEFAULT_APPLICATION_ADAPTER_TEMPLATE,
            DEFAULT_INFRASTRUCTURE_ADAPTER_TEMPLATE,
            DEFAULT_LIBRARY_ADAPTER_TEMPLATE,
        )
        validator = Draft7Validator(adapter_schema)
        for tpl in [DEFAULT_APPLICATION_ADAPTER_TEMPLATE, DEFAULT_INFRASTRUCTURE_ADAPTER_TEMPLATE, DEFAULT_LIBRARY_ADAPTER_TEMPLATE]:
            errors = list(validator.iter_errors(tpl))
            assert not errors, f"Validation errors for archetype {tpl['project']['type']}: {[e.message for e in errors]}"

    def test_artifact_valid(self, artifact_schema):
        data = load_json(FIXTURES_VALID_DIR / "valid_artifact.json")
        validator = Draft7Validator(artifact_schema)
        errors = list(validator.iter_errors(data))
        assert not errors, f"Validation errors: {[e.message for e in errors]}"

    def test_evidence_valid(self, evidence_schema):
        data = load_json(FIXTURES_VALID_DIR / "valid_evidence.json")
        validator = Draft7Validator(evidence_schema)
        errors = list(validator.iter_errors(data))
        assert not errors, f"Validation errors: {[e.message for e in errors]}"

    def test_manifest_valid(self, manifest_schema):
        data = load_json(FIXTURES_VALID_DIR / "valid_manifest.json")
        validator = Draft7Validator(manifest_schema)
        errors = list(validator.iter_errors(data))
        assert not errors, f"Validation errors: {[e.message for e in errors]}"


class TestInvalidFixtures:
    """Ensures strict validation and failure on all negative/malformed fixtures."""

    def test_missing_required_field_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "missing_required_field_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_unknown_field_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "unknown_field_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_invalid_schema_version_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_schema_version_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_tag_only_artifact_fails_digest_rule(self, artifact_schema):
        data = load_json(FIXTURES_INVALID_DIR / "tag_only_artifact.json")
        with pytest.raises(jsonschema.ValidationError) as excinfo:
            jsonschema.validate(instance=data, schema=artifact_schema)
        assert "canonical_reference" in str(excinfo.value) or "pattern" in str(excinfo.value)

    def test_double_at_artifact_fails(self, artifact_schema):
        data = load_json(FIXTURES_INVALID_DIR / "double_at_artifact.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=artifact_schema)

    def test_uppercase_sha_artifact_fails(self, artifact_schema):
        data = load_json(FIXTURES_INVALID_DIR / "uppercase_sha_artifact.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=artifact_schema)

    def test_short_sha_digest_fails(self, artifact_schema):
        data = load_json(FIXTURES_INVALID_DIR / "short_sha_digest_artifact.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=artifact_schema)

    def test_malformed_digest_fails(self, artifact_schema):
        data = load_json(FIXTURES_INVALID_DIR / "malformed_digest_artifact.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=artifact_schema)

    def test_invalid_migration_class_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_migration_class_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_incompatible_migration_without_two_phase_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "incompatible_migration_one_phase_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_missing_core_oidc_claims_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "missing_core_oidc_claims_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_invalid_host_lock_path_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_host_lock_path_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_zero_timeout_concurrency_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "zero_timeout_concurrency_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_lowered_db_migration_escalation_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "lowered_db_migration_escalation_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_shared_infra_write_access_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "shared_infra_write_access_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_invalid_test_level_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_test_level_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_invalid_infra_dependency_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_infra_dependency_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_malformed_oidc_issuer_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "malformed_oidc_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_invalid_resource_gate_fails(self, adapter_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_resource_gate_adapter.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=adapter_schema)

    def test_invalid_evidence_state_fails(self, evidence_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_evidence_state.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=evidence_schema)

    def test_invalid_manifest_invariants_fails(self, manifest_schema):
        data = load_json(FIXTURES_INVALID_DIR / "invalid_manifest_invariants.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=manifest_schema)

    def test_invalid_archetype_fails(self, adapter_schema):
        data = load_json(FIXTURES_VALID_DIR / "minimal_adapter.json")
        bad_data = dict(data)
        bad_data["project"] = dict(data["project"])
        bad_data["project"]["type"] = "microservice_invalid"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=bad_data, schema=adapter_schema)

