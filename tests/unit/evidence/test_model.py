"""
Unit tests for UPAS Evidence Models, Canonical Serializer, and Secret Redactor.
"""

import pytest
from upas_core.evidence.model import (
    AuditEvent,
    SecretRedactor,
    compute_evidence_hash,
    to_canonical_bytes,
    to_canonical_json,
)


def test_secret_redactor_bearer_token():
    text = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig and Bearer secret-token-123"
    redacted = SecretRedactor.redact_text(text)
    assert "secret-token-123" not in redacted
    assert "Bearer [REDACTED_TOKEN]" in redacted


def test_secret_redactor_private_key():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y123456789...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    redacted = SecretRedactor.redact_text(pem)
    assert "MIIEowIBAAKCAQEA0" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_secret_redactor_uri_credentials():
    uri = "postgres://admin:super_secret_pw@db.internal:5432/prod"
    redacted = SecretRedactor.redact_text(uri)
    assert "super_secret_pw" not in redacted
    assert "://[USER]:[REDACTED_PASSWORD]@" in redacted


def test_secret_redactor_object_recursive():
    data = {
        "user": "alice",
        "password": "plain_password_123",
        "api_key": "key_xyz",
        "nested": {
            "token": "token_abc",
            "url": "http://user:secretpass@host",
            "safe_val": 42,
        },
        "list_val": ["Bearer token-999", {"private_key": "some_key"}],
    }
    cleaned = SecretRedactor.redact_object(data)
    assert cleaned["password"] == "[REDACTED_SECRET]"
    assert cleaned["api_key"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["token"] == "[REDACTED_SECRET]"
    assert "secretpass" not in cleaned["nested"]["url"]
    assert cleaned["nested"]["safe_val"] == 42
    assert "token-999" not in cleaned["list_val"][0]
    assert cleaned["list_val"][1]["private_key"] == "[REDACTED_SECRET]"


def test_to_canonical_json_deterministic_ordering():
    dict_a = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    dict_b = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}

    json_a = to_canonical_json(dict_a)
    json_b = to_canonical_json(dict_b)

    assert json_a == json_b
    assert json_a == '{"a":2,"m":{"a":4,"b":3},"z":1}'


def test_to_canonical_json_rejects_nan_and_infinity():
    with pytest.raises(ValueError) as exc_nan:
        to_canonical_json({"val": float("nan")})
    assert "Non-finite float" in str(exc_nan.value)

    with pytest.raises(ValueError) as exc_inf:
        to_canonical_json({"val": float("inf")})
    assert "Non-finite float" in str(exc_inf.value)


def test_compute_evidence_hash():
    data = {"project": "support_bot", "status": "VERIFIED"}
    hash_1 = compute_evidence_hash(data)
    hash_2 = compute_evidence_hash(to_canonical_bytes(data))
    assert hash_1 == hash_2
    assert len(hash_1) == 64


def test_audit_event_hash_calculation():
    event = AuditEvent(
        sequence=0,
        state="PROD_AUTHORIZED",
        timestamp="2026-08-28T12:00:00Z",
        previous_hash="0" * 64,
        payload={"actor": "octocat"},
    )
    assert len(event.event_hash) == 64
    assert event.calculate_hash() == event.event_hash
