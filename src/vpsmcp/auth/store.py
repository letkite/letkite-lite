"""OAuth state in SQLite (WAL). Only hashes are stored, never raw credentials."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS clients (
    client_id     TEXT PRIMARY KEY,
    secret_hash   TEXT,
    metadata      TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash     TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    scope         TEXT NOT NULL,
    challenge     TEXT NOT NULL,
    challenge_method TEXT NOT NULL DEFAULT 'S256',
    resource      TEXT,
    subject       TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash    TEXT PRIMARY KEY,
    family        TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    subject       TEXT NOT NULL,
    scope         TEXT NOT NULL,
    resource      TEXT,
    expires_at    INTEGER NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family);
CREATE TABLE IF NOT EXISTS login_sessions (
    sid           TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    ip            TEXT PRIMARY KEY,
    fails         INTEGER NOT NULL DEFAULT 0,
    locked_until  INTEGER NOT NULL DEFAULT 0
);
-- redirect_uri prefixes added at runtime (`vpsmcp redirect allow`), merged with
-- the ones from the client profiles and VPSMCP_ALLOWED_REDIRECTS.
CREATE TABLE IF NOT EXISTS redirect_allow (
    prefix        TEXT PRIMARY KEY,
    note          TEXT,
    created_at    INTEGER NOT NULL
);
-- callbacks that were refused, so a new client can be allowed by copying a
-- command instead of guessing the vendor's URL.
CREATE TABLE IF NOT EXISTS redirect_rejects (
    uri           TEXT PRIMARY KEY,
    client_name   TEXT,
    hits          INTEGER NOT NULL DEFAULT 1,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL
);
"""

# Columns added after 1.0. CREATE TABLE IF NOT EXISTS leaves an existing table
# alone, so a new column has to be added explicitly.
MIGRATIONS = (
    ("auth_codes", "challenge_method", "TEXT NOT NULL DEFAULT 'S256'"),
)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._migrate()
            self._db.commit()

    def _migrate(self) -> None:
        for table, column, decl in MIGRATIONS:
            cols = {r["name"] for r in self._db.execute(f"PRAGMA table_info({table})")}
            if cols and column not in cols:
                self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def _x(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # ---------- clients ----------
    def put_client(self, client_id: str, metadata: dict, secret_hash: str | None = None) -> None:
        self._x(
            "INSERT OR REPLACE INTO clients(client_id, secret_hash, metadata, created_at)"
            " VALUES(?,?,?,?)",
            (client_id, secret_hash, json.dumps(metadata, ensure_ascii=False), int(time.time())),
        )

    def get_client(self, client_id: str) -> dict | None:
        rows = self._q("SELECT * FROM clients WHERE client_id=?", (client_id,))
        if not rows:
            return None
        r = rows[0]
        return {"client_id": r["client_id"], "secret_hash": r["secret_hash"],
                "metadata": json.loads(r["metadata"]), "created_at": r["created_at"]}

    def list_clients(self) -> list[dict]:
        return [{"client_id": r["client_id"],
                 "name": json.loads(r["metadata"]).get("client_name", ""),
                 "created_at": r["created_at"]}
                for r in self._q("SELECT * FROM clients ORDER BY created_at DESC")]

    def delete_client(self, client_id: str) -> None:
        self._x("DELETE FROM clients WHERE client_id=?", (client_id,))
        self._x("UPDATE refresh_tokens SET revoked=1 WHERE client_id=?", (client_id,))

    # ---------- auth codes ----------
    def put_code(self, code: str, **f: Any) -> None:
        self._x(
            "INSERT INTO auth_codes(code_hash,client_id,redirect_uri,scope,challenge,"
            "challenge_method,resource,subject,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (sha(code), f["client_id"], f["redirect_uri"], f["scope"], f["challenge"],
             f.get("challenge_method") or "none", f.get("resource"), f["subject"],
             f["expires_at"]),
        )

    def take_code(self, code: str) -> dict | None:
        """Single use. A replay revokes the refresh-token family derived from it."""
        h = sha(code)
        rows = self._q("SELECT * FROM auth_codes WHERE code_hash=?", (h,))
        if not rows:
            return None
        r = dict(rows[0])
        if r["used"]:
            self._x("UPDATE refresh_tokens SET revoked=1 WHERE family=?", (h,))
            return {"replayed": True, **r}
        self._x("UPDATE auth_codes SET used=1 WHERE code_hash=?", (h,))
        return {"replayed": False, **r}

    # ---------- refresh tokens ----------
    def put_refresh(self, token: str, *, family: str, client_id: str, subject: str,
                    scope: str, resource: str | None, expires_at: int) -> None:
        self._x(
            "INSERT INTO refresh_tokens(token_hash,family,client_id,subject,scope,resource,"
            "expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (sha(token), family, client_id, subject, scope, resource, expires_at, int(time.time())),
        )

    def refresh_owner(self, token: str) -> str | None:
        """Which client a refresh token belongs to, without consuming it: the
        confidential-client check has to happen before rotation."""
        rows = self._q("SELECT client_id FROM refresh_tokens WHERE token_hash=?",
                       (sha(token),))
        return rows[0]["client_id"] if rows else None

    def take_refresh(self, token: str) -> dict | None:
        h = sha(token)
        rows = self._q("SELECT * FROM refresh_tokens WHERE token_hash=?", (h,))
        if not rows:
            return None
        r = dict(rows[0])
        if r["revoked"]:
            # reuse of a revoked refresh token invalidates the family (OAuth 2.1)
            self._x("UPDATE refresh_tokens SET revoked=1 WHERE family=?", (r["family"],))
            return {"reused": True, **r}
        self._x("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (h,))
        return {"reused": False, **r}

    def revoke_refresh(self, token: str) -> None:
        self._x("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (sha(token),))

    def revoke_family(self, family: str) -> None:
        self._x("UPDATE refresh_tokens SET revoked=1 WHERE family=?", (family,))

    def active_grants(self) -> list[dict]:
        now = int(time.time())
        return [dict(r) for r in self._q(
            "SELECT client_id, subject, scope, family, expires_at, created_at"
            " FROM refresh_tokens WHERE revoked=0 AND expires_at>? ORDER BY created_at DESC",
            (now,))]

    # ---------- login sessions ----------
    def put_session(self, sid: str, subject: str, expires_at: int) -> None:
        self._x("INSERT OR REPLACE INTO login_sessions VALUES(?,?,?)", (sha(sid), subject, expires_at))

    def get_session(self, sid: str) -> str | None:
        rows = self._q("SELECT * FROM login_sessions WHERE sid=? AND expires_at>?",
                       (sha(sid), int(time.time())))
        return rows[0]["subject"] if rows else None

    def drop_session(self, sid: str) -> None:
        self._x("DELETE FROM login_sessions WHERE sid=?", (sha(sid),))

    # ---------- login rate limit ----------
    def login_locked(self, ip: str) -> int:
        rows = self._q("SELECT * FROM login_attempts WHERE ip=?", (ip,))
        if not rows:
            return 0
        left = rows[0]["locked_until"] - int(time.time())
        return max(0, left)

    def login_failed(self, ip: str) -> None:
        rows = self._q("SELECT * FROM login_attempts WHERE ip=?", (ip,))
        fails = (rows[0]["fails"] if rows else 0) + 1
        lock = int(time.time()) + min(900, 2 ** min(fails, 9)) if fails >= 5 else 0
        self._x("INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)", (ip, fails, lock))

    def login_ok(self, ip: str) -> None:
        self._x("DELETE FROM login_attempts WHERE ip=?", (ip,))

    def clear_login_locks(self, ip: str | None = None) -> int:
        """Clear the login lockout for one IP, or all of them. Returns rows removed."""
        if ip:
            return self._x("DELETE FROM login_attempts WHERE ip=?", (ip,)).rowcount
        return self._x("DELETE FROM login_attempts").rowcount

    def login_locks(self) -> list[dict]:
        now = int(time.time())
        return [{"ip": r["ip"], "fails": r["fails"],
                 "locked_for_s": max(0, r["locked_until"] - now)}
                for r in self._q("SELECT * FROM login_attempts ORDER BY locked_until DESC")]

    # ---------- redirect allowlist ----------
    def allow_redirect(self, prefix: str, note: str = "") -> None:
        self._x("INSERT OR REPLACE INTO redirect_allow(prefix,note,created_at) VALUES(?,?,?)",
                (prefix, note, int(time.time())))
        self._x("DELETE FROM redirect_rejects WHERE uri=? OR uri LIKE ?", (prefix, prefix + "%"))

    def disallow_redirect(self, prefix: str) -> bool:
        return self._x("DELETE FROM redirect_allow WHERE prefix=?", (prefix,)).rowcount > 0

    def redirect_prefixes(self) -> tuple[str, ...]:
        return tuple(r["prefix"] for r in
                     self._q("SELECT prefix FROM redirect_allow ORDER BY created_at"))

    def redirect_allow_rows(self) -> list[dict]:
        return [dict(r) for r in
                self._q("SELECT * FROM redirect_allow ORDER BY created_at")]

    def note_rejected_redirect(self, uri: str, client_name: str = "", cap: int = 200) -> None:
        """Remember a refused callback so it can be allowed by copying a command.
        Written from unauthenticated requests, so distinct URIs are capped; known
        ones keep counting."""
        now, uri = int(time.time()), uri[:400]
        hit = self._x(
            "UPDATE redirect_rejects SET hits=hits+1, last_seen=?,"
            " client_name=COALESCE(NULLIF(?,''), client_name) WHERE uri=?",
            (now, client_name[:120], uri),
        ).rowcount
        if hit:
            return
        n = self._q("SELECT COUNT(*) AS n FROM redirect_rejects")[0]["n"]
        if n >= cap:
            return
        self._x("INSERT INTO redirect_rejects(uri,client_name,hits,first_seen,last_seen)"
                " VALUES(?,?,1,?,?)", (uri, client_name[:120], now, now))

    def rejected_redirects(self, limit: int = 20) -> list[dict]:
        return [dict(r) for r in self._q(
            "SELECT * FROM redirect_rejects ORDER BY last_seen DESC LIMIT ?", (limit,))]

    def clear_rejected_redirects(self) -> None:
        self._x("DELETE FROM redirect_rejects")

    # ---------- gc ----------
    def gc(self) -> None:
        now = int(time.time())
        self._x("DELETE FROM auth_codes WHERE expires_at < ?", (now - 3600,))
        self._x("DELETE FROM refresh_tokens WHERE expires_at < ?", (now - 86400,))
        self._x("DELETE FROM login_sessions WHERE expires_at < ?", (now,))
        self._x("DELETE FROM redirect_rejects WHERE last_seen < ?", (now - 30 * 86400,))
