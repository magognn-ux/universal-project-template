"""
Unit tests for UPAS Evidence Signers.
Tests HashOnlySigner and AsymmetricEvidenceSigner.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from upas_core.evidence.signer import AsymmetricEvidenceSigner, HashOnlySigner


def test_hash_only_signer():
    signer = HashOnlySigner()
    data = b'{"status":"VERIFIED"}'

    meta = signer.sign(data)
    assert meta["algorithm"] == "sha256"
    assert len(meta["digest"]) == 64

    # Verify original
    assert signer.verify(data, meta) is True

    # Tampered data fails
    assert signer.verify(b'{"status":"TAMPERED"}', meta) is False


def test_asymmetric_evidence_signer():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    signer = AsymmetricEvidenceSigner(private_key=priv, key_id="prod-key-1")
    data = b'{"deployment":"support_bot","verdict":"VERIFIED"}'

    meta = signer.sign(data)
    assert meta["algorithm"] == "RSASSA-PSS-SHA256"
    assert meta["key_id"] == "prod-key-1"
    assert "signature_hex" in meta

    # Verifier with public key
    verifier = AsymmetricEvidenceSigner(public_key=pub, key_id="prod-key-1")
    assert verifier.verify(data, meta) is True

    # Tampered data fails
    assert verifier.verify(b'{"deployment":"support_bot","verdict":"FAILED"}', meta) is False
