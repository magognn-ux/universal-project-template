"""
UPAS JTI Replay Prevention Storage.
Implements the JtiStore protocol using ACID-compliant SQLite WAL persistence.
Enforces Invariant 1: Single-Use Production Authorization (Anti-Replay).
"""

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Iterator, Optional
from upas_core.contracts.interfaces import JtiStore


def get_default_jti_store_path() -> str:
    """
    Resolves canonical persistent JTI store database path without polluting project root.
    Precedence:
    1. $UPAS_STATE_DIR/jti_store.db (if environment variable set)
    2. Windows: %LOCALAPPDATA%/upas/jti_store.db (fallback ~/.upas/state/jti_store.db)
    3. POSIX: $XDG_STATE_HOME/upas/jti_store.db (fallback ~/.upas/state/jti_store.db)
    """
    state_dir = os.environ.get("UPAS_STATE_DIR")
    if state_dir and state_dir.strip():
        return os.path.join(os.path.abspath(state_dir.strip()), "jti_store.db")

    import sys
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data and local_app_data.strip():
            return os.path.join(os.path.abspath(local_app_data.strip()), "upas", "jti_store.db")
    else:
        xdg_state = os.environ.get("XDG_STATE_HOME")
        if xdg_state and xdg_state.strip():
            return os.path.join(os.path.abspath(xdg_state.strip()), "upas", "jti_store.db")

    return os.path.expanduser("~/.upas/state/jti_store.db")


class SQLiteJtiStore(JtiStore):
    """
    Persistent atomic JTI storage backed by SQLite in WAL mode.
    Guarantees cross-process and cross-thread mutual exclusion on JTI insertion.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            self.db_path = get_default_jti_store_path()
        else:
            self.db_path = os.path.abspath(db_path)

        parent_dir = os.path.dirname(self.db_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            conn.execute("PRAGMA busy_timeout=30000;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            with self._connection() as conn:
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                except sqlite3.OperationalError:
                    pass
                conn.execute("PRAGMA synchronous=NORMAL;")
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS jti_records (
                            jti TEXT PRIMARY KEY,
                            exp INTEGER NOT NULL,
                            recorded_at INTEGER NOT NULL
                        );
                        """
                    )
                    conn.execute(
                        """
                        CREATE INDEX IF NOT EXISTS idx_jti_exp ON jti_records(exp);
                        """
                    )

    def has_jti(self, jti: str) -> bool:
        """
        Check if JTI has already been recorded.
        Fails closed: returns True (indicating presence) if storage error occurs.
        """
        if not jti or not isinstance(jti, str) or not jti.strip():
            return False

        try:
            with self._lock:
                with self._connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1 FROM jti_records WHERE jti = ?", (jti.strip(),))
                    return cursor.fetchone() is not None
        except Exception:
            # Fail closed on database access errors to prevent unauthorized replay
            return True

    def record_jti(self, jti: str, exp: int) -> bool:
        """
        Atomically records a JTI with its expiration timestamp.
        Returns True if the JTI was newly and successfully recorded.
        Returns False if the JTI already exists (replay detected), is expired,
        is malformed, or if a storage corruption error occurs.
        """
        if not jti or not isinstance(jti, str) or not jti.strip():
            return False

        if not isinstance(exp, int) or exp <= 0:
            return False

        now = int(time.time())
        if exp <= now:
            # Token is already expired; cannot authorize mutation
            return False

        cleaned_jti = jti.strip()

        try:
            with self._lock:
                with self._connection() as conn:
                    with conn:
                        cursor = conn.cursor()
                        # Clean up old records that expired more than a day ago
                        cursor.execute("DELETE FROM jti_records WHERE exp < ?", (now - 86400,))
                        # Attempt atomic insert
                        cursor.execute(
                            "INSERT INTO jti_records (jti, exp, recorded_at) VALUES (?, ?, ?)",
                            (cleaned_jti, exp, now),
                        )
                        return True
        except sqlite3.IntegrityError:
            # Duplicate primary key (race condition between concurrent processes)
            return False
        except Exception:
            # Storage error or corruption -> fail closed
            return False


class InMemoryJtiStore(JtiStore):
    """
    In-memory thread-safe JTI store for lightweight testing.
    """

    def __init__(self):
        self._records = {}  # jti -> exp
        self._lock = threading.Lock()

    def has_jti(self, jti: str) -> bool:
        if not jti or not isinstance(jti, str) or not jti.strip():
            return False
        with self._lock:
            return jti.strip() in self._records

    def record_jti(self, jti: str, exp: int) -> bool:
        if not jti or not isinstance(jti, str) or not jti.strip():
            return False
        if not isinstance(exp, int) or exp <= 0:
            return False

        now = int(time.time())
        if exp <= now:
            return False

        cleaned = jti.strip()
        with self._lock:
            if cleaned in self._records:
                return False
            self._records[cleaned] = exp
            return True
