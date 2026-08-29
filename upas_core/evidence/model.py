"""
UPAS Evidence Domain Models & Canonical Deterministic Serializer.
Provides canonical JSON serialization, cryptographic SHA-256 hashing,
hash-chained audit event models, and automated secret redaction.
"""

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from upas_core.contracts.evidence import EvidenceRecord


# Regular expressions for detecting and redacting sensitive data
_BEARER_TOKEN_REGEX = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.+=/]+", re.IGNORECASE)
_JWT_TOKEN_REGEX = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-+/=]{10,}\b")
_PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
_CREDENTIAL_URI_REGEX = re.compile(r"://([^:]+):([^@]+)@")
_GENERIC_SECRET_REGEX = re.compile(
    r"(?i)\b(password|secret|api_key|access_token|private_key|token|auth_token)\s*[:=]\s*['\"]?([^'\"\s,;]+)['\"]?"
)

_SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "secret",
    "private_key",
    "raw_token",
    "api_key",
    "access_token",
    "auth_token",
    "token",
)


class SecretRedactor:
    """
    Automated deep secret scanner and redactor.
    Ensures that credentials, raw JWTs, bearer tokens, and private keys
    never leak into serialized evidence or audit records.
    """

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Sanitizes text by replacing all matched secrets with redaction markers."""
        if not text or not isinstance(text, str):
            return text

        # 1. Redact Private Key PEM blocks
        sanitized = _PRIVATE_KEY_REGEX.sub("[REDACTED_PRIVATE_KEY]", text)

        # 2. Redact Bearer tokens
        sanitized = _BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_TOKEN]", sanitized)

        # 3. Redact raw JWT tokens
        sanitized = _JWT_TOKEN_REGEX.sub("[REDACTED_JWT_TOKEN]", sanitized)

        # 4. Redact URI embedded credentials (e.g. postgres://user:pass@host)
        sanitized = _CREDENTIAL_URI_REGEX.sub("://[USER]:[REDACTED_PASSWORD]@", sanitized)

        # 5. Redact generic key-value secrets
        sanitized = _GENERIC_SECRET_REGEX.sub(r"\1=[REDACTED_SECRET]", sanitized)

        return sanitized

    @classmethod
    def redact_object(cls, obj: Any) -> Any:
        """Recursively traverses dictionaries, lists, and primitives to redact secrets."""
        if isinstance(obj, str):
            return cls.redact_text(obj)
        elif isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                k_lower = str(k).lower()
                if any(sec in k_lower for sec in _SENSITIVE_KEY_SUBSTRINGS):
                    new_dict[k] = "[REDACTED_SECRET]"
                else:
                    new_dict[k] = cls.redact_object(v)
            return new_dict
        elif isinstance(obj, (list, tuple, set)):
            return [cls.redact_object(item) for item in obj]
        else:
            return obj


def _validate_finite_numbers(obj: Any) -> None:
    """Ensures no NaN or Infinite float values exist in the object tree."""
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError(f"Non-finite float value '{obj}' cannot be serialized into deterministic evidence")
    elif isinstance(obj, dict):
        for v in obj.values():
            _validate_finite_numbers(v)
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            _validate_finite_numbers(item)


def to_canonical_json(data: Any, redact_secrets: bool = True) -> str:
    """
    Serializes data into deterministic canonical JSON:
      - Strict key sorting (sort_keys=True)
      - Compact separators (no trailing whitespace)
      - UTF-8 representation (ensure_ascii=False)
      - Rejects non-finite numbers (NaN, Inf)
      - Automatically redacts credentials if redact_secrets=True
    """
    if hasattr(data, "to_dict") and callable(data.to_dict):
        serializable_data = data.to_dict()
    elif isinstance(data, EvidenceRecord):
        serializable_data = data.to_dict()
    elif dataclass_is_instance(data):
        serializable_data = asdict(data)
    else:
        serializable_data = data

    if redact_secrets:
        serializable_data = SecretRedactor.redact_object(serializable_data)

    _validate_finite_numbers(serializable_data)

    return json.dumps(
        serializable_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def dataclass_is_instance(obj: Any) -> bool:
    """Checks if object is a dataclass instance."""
    return hasattr(obj, "__dataclass_fields__")


def to_canonical_bytes(data: Any, redact_secrets: bool = True) -> bytes:
    """Serializes data into deterministic canonical UTF-8 bytes."""
    return to_canonical_json(data, redact_secrets=redact_secrets).encode("utf-8")


def compute_evidence_hash(data: Union[EvidenceRecord, Dict[str, Any], str, bytes]) -> str:
    """
    Computes cryptographic SHA-256 hex digest of canonical evidence representation.
    """
    if isinstance(data, bytes):
        canonical_bytes = data
    elif isinstance(data, str):
        # Parse and re-canonicalize to guarantee key sorting and formatting
        try:
            parsed = json.loads(data)
            canonical_bytes = to_canonical_bytes(parsed)
        except json.JSONDecodeError:
            canonical_bytes = data.encode("utf-8")
    else:
        canonical_bytes = to_canonical_bytes(data)

    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True)
class AuditEvent:
    """
    Cryptographically chained lifecycle audit event.
    Guarantees tamper detection for intermediate lifecycle steps (hash-chaining).
    """
    sequence: int
    state: str
    timestamp: str
    previous_hash: str
    payload: Dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""

    def __post_init__(self):
        if self.sequence < 0:
            raise ValueError("AuditEvent sequence must be non-negative")
        if not self.state:
            raise ValueError("AuditEvent state cannot be empty")
        if not self.timestamp:
            raise ValueError("AuditEvent timestamp cannot be empty")
        if not self.previous_hash or len(self.previous_hash) != 64:
            raise ValueError("AuditEvent previous_hash must be a 64-char hex SHA256")

        # Automatically compute event hash if not explicitly provided
        calculated_hash = self.calculate_hash()
        if self.event_hash and self.event_hash != calculated_hash:
            raise ValueError(f"AuditEvent event_hash mismatch: expected {calculated_hash}, got {self.event_hash}")
        if not self.event_hash:
            object.__setattr__(self, "event_hash", calculated_hash)

    def calculate_hash(self) -> str:
        """Computes SHA-256 of canonical event representation."""
        event_dict = {
            "sequence": self.sequence,
            "state": self.state,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "payload": SecretRedactor.redact_object(self.payload),
        }
        return compute_evidence_hash(event_dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "state": self.state,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
            "payload": SecretRedactor.redact_object(self.payload),
        }
