"""
Unit tests for UPAS JTI Replay Prevention Storage.
Tests atomic recording, replay detection, expiration, and multi-threaded concurrency.
"""

import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
import pytest

from upas_core.security.jti_store import SQLiteJtiStore, InMemoryJtiStore


@pytest.fixture
def temp_jti_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_jti.db")
        yield db_path


def test_sqlite_jti_store_first_valid_passes_second_fails(temp_jti_db):
    store = SQLiteJtiStore(temp_jti_db)
    jti = "unique-jti-001"
    exp = int(time.time()) + 3600

    # First attempt: succeeds
    assert store.has_jti(jti) is False
    assert store.record_jti(jti, exp) is True
    assert store.has_jti(jti) is True

    # Second attempt (replay): fails
    assert store.record_jti(jti, exp) is False


def test_sqlite_jti_store_expired_token_rejected(temp_jti_db):
    store = SQLiteJtiStore(temp_jti_db)
    jti = "expired-jti-002"
    exp = int(time.time()) - 10  # Expired 10s ago

    assert store.record_jti(jti, exp) is False
    assert store.has_jti(jti) is False


def test_sqlite_jti_store_malformed_jti_rejected(temp_jti_db):
    store = SQLiteJtiStore(temp_jti_db)
    exp = int(time.time()) + 3600

    assert store.record_jti("", exp) is False
    assert store.record_jti("   ", exp) is False
    assert store.record_jti(None, exp) is False
    assert store.record_jti("valid-jti", -100) is False
    assert store.record_jti("valid-jti", 0) is False


def test_sqlite_jti_store_concurrent_same_jti_only_one_succeeds(temp_jti_db):
    store = SQLiteJtiStore(temp_jti_db)
    jti = "race-condition-jti-999"
    exp = int(time.time()) + 3600

    results = []

    def try_record():
        local_store = SQLiteJtiStore(temp_jti_db)
        return local_store.record_jti(jti, exp)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(try_record) for _ in range(20)]
        results = [f.result() for f in futures]

    # Exactly ONE thread must succeed
    assert results.count(True) == 1
    assert results.count(False) == 19


def test_in_memory_jti_store():
    store = InMemoryJtiStore()
    jti = "mem-jti-123"
    exp = int(time.time()) + 3600

    assert store.has_jti(jti) is False
    assert store.record_jti(jti, exp) is True
    assert store.has_jti(jti) is True
    assert store.record_jti(jti, exp) is False

    # Expired
    assert store.record_jti("mem-exp", int(time.time()) - 5) is False


def test_sqlite_jti_store_default_path_uses_state_dir(monkeypatch, tmp_path):
    custom_state = tmp_path / "custom_upas_state"
    monkeypatch.setenv("UPAS_STATE_DIR", str(custom_state))

    store = SQLiteJtiStore()
    expected_db_path = str(custom_state / "jti_store.db")
    assert store.db_path == expected_db_path
    assert os.path.exists(expected_db_path)

