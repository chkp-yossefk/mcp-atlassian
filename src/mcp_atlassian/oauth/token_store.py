"""SQLite-backed per-user OAuth token store.

Stores one token record per (username, service) pair. Designed for single-replica
deployment with uvicorn's threaded request handling. For multi-replica deployments,
replace with a Redis-backed implementation using the same interface.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("mcp-atlassian.oauth.token_store")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS user_tokens (
    username      TEXT NOT NULL,
    service       TEXT NOT NULL,
    access_token  TEXT NOT NULL,
    refresh_token TEXT,
    expires_at    REAL NOT NULL,
    base_url      TEXT NOT NULL,
    updated_at    REAL NOT NULL,
    PRIMARY KEY (username, service)
)
"""

_TOKEN_EXPIRY_MARGIN = 300  # refresh 5 minutes before actual expiry


@dataclass
class TokenRecord:
    username: str
    service: str
    access_token: str
    refresh_token: str | None
    expires_at: float
    base_url: str

    @property
    def is_expired(self) -> bool:
        return time.time() + _TOKEN_EXPIRY_MARGIN >= self.expires_at


class UserTokenStore:
    """Thread-safe SQLite token store keyed by (username, service)."""

    def __init__(self, db_path: str = "/data/tokens.db") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
        logger.info(f"UserTokenStore initialised at {db_path}")

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path, check_same_thread=False)

    def get(self, username: str, service: str) -> TokenRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, service, access_token, refresh_token, "
                "expires_at, base_url FROM user_tokens WHERE username=? AND service=?",
                (username, service),
            ).fetchone()
        if row:
            return TokenRecord(*row)
        return None

    def upsert(
        self,
        username: str,
        service: str,
        access_token: str,
        refresh_token: str | None,
        expires_at: float,
        base_url: str,
    ) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO user_tokens
                        (username, service, access_token, refresh_token,
                         expires_at, base_url, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(username, service) DO UPDATE SET
                        access_token  = excluded.access_token,
                        refresh_token = excluded.refresh_token,
                        expires_at    = excluded.expires_at,
                        base_url      = excluded.base_url,
                        updated_at    = excluded.updated_at
                    """,
                    (
                        username,
                        service,
                        access_token,
                        refresh_token,
                        expires_at,
                        base_url,
                        time.time(),
                    ),
                )
                conn.commit()

    def delete(self, username: str, service: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM user_tokens WHERE username=? AND service=?",
                    (username, service),
                )
                conn.commit()
        logger.info(f"Deleted token for {username}/{service}")
