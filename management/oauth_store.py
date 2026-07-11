#!/usr/local/lib/mailinabox/env/bin/python
# Storage layer for the OAuth 2.0 authorization server: the persistent
# server secret, single-use authorization codes, and access/refresh tokens,
# kept in a root-only sqlite database at STORAGE_ROOT/auth/auth.sqlite.
#
# STDLIB ONLY: this module must not import anything outside the Python
# standard library because setup/oauth.sh drives it with the system
# python3, outside the management daemon's virtualenv.

import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
import threading
import time


def auth_dir(env):
	return os.path.join(env["STORAGE_ROOT"], "auth")


def db_path(env):
	return os.path.join(auth_dir(env), "auth.sqlite")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_config (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS oauth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT, user_email TEXT, scopes TEXT, redirect_uri TEXT, code_challenge TEXT, code_challenge_method TEXT, auth_time INTEGER, expires_at INTEGER, used_at INTEGER);
CREATE TABLE IF NOT EXISTS oauth_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE, token_type TEXT, client_id TEXT, user_email TEXT, scopes TEXT, auth_time INTEGER, origin_code_hash TEXT, issued_at INTEGER, expires_at INTEGER, revoked_at INTEGER, parent_id INTEGER, last_used_at INTEGER, password_state TEXT);
CREATE INDEX IF NOT EXISTS idx_tokens_origin ON oauth_tokens (origin_code_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON oauth_tokens (user_email, revoked_at);
CREATE INDEX IF NOT EXISTS idx_codes_expires ON oauth_codes (expires_at);
"""


# Keys of the dict returned by lookup_token (everything except token_hash,
# which callers never need and must never log).
_TOKEN_KEYS = ("id", "token_type", "client_id", "user_email", "scopes", "auth_time", "origin_code_hash", "issued_at", "expires_at", "revoked_at", "parent_id", "last_used_at", "password_state")


def _now(now):
	return int(time.time()) if now is None else now


class OAuthStore:
	def __init__(self, path):
		# Create the parent directory root-only, connect in autocommit mode
		# (the daemon shares one connection across request threads), make the
		# database file itself 0600, and ensure the schema idempotently.
		parent = os.path.dirname(path)
		os.makedirs(parent, mode=0o700, exist_ok=True)
		os.chmod(parent, 0o700)
		self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
		self.conn.row_factory = sqlite3.Row
		os.chmod(path, 0o600)
		self._lock = threading.Lock()
		self.conn.executescript(_SCHEMA)

	def get_server_secret(self):
		# A stable secret that persists across daemon restarts (unlike the
		# api.key), used to key password-state fingerprints and the authorize
		# form binding token. Created on first use.
		with self._lock:
			row = self.conn.execute("SELECT value FROM oauth_config WHERE key = 'server_secret'").fetchone()
			if row is None:
				# INSERT OR IGNORE + re-read so two racing processes agree on one value.
				self.conn.execute("INSERT OR IGNORE INTO oauth_config (key, value) VALUES ('server_secret', ?)", (secrets.token_hex(32),))
				row = self.conn.execute("SELECT value FROM oauth_config WHERE key = 'server_secret'").fetchone()
			return bytes.fromhex(row["value"])

	@staticmethod
	def hash_token(raw):
		# Tokens and codes are stored hashed so a leaked database cannot be replayed.
		return hashlib.sha256(raw.encode()).hexdigest()

	def _execute_one(self, sql, params=()):
		# Execute a SELECT query and return fetchone(), serializing with _lock.
		with self._lock:
			return self.conn.execute(sql, params).fetchone()

	def _write(self, sql, params=()):
		# Execute an INSERT/UPDATE/DELETE and return (rowcount, lastrowid), serializing with _lock.
		with self._lock:
			cur = self.conn.execute(sql, params)
			return cur.rowcount, cur.lastrowid

	# --- authorization codes ---

	def save_code(self, raw_code, client_id, user_email, scopes, redirect_uri, code_challenge, code_challenge_method, auth_time, now=None):
		now = _now(now)
		self._write(
			"INSERT INTO oauth_codes (code_hash, client_id, user_email, scopes, redirect_uri, code_challenge, code_challenge_method, auth_time, expires_at, used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
			(self.hash_token(raw_code), client_id, user_email, scopes, redirect_uri, code_challenge, code_challenge_method, auth_time, now + 60))

	def take_code(self, raw_code, now=None):
		# Single-use redemption. Returns the full row dict on success (and
		# marks the code used), {"replayed": True, "code_hash": ...} if the
		# code was already used (the caller must revoke the token family),
		# or None if the code is unknown or expired.
		now = _now(now)
		code_hash = self.hash_token(raw_code)
		with self._lock:
			row = self.conn.execute("SELECT * FROM oauth_codes WHERE code_hash = ?", (code_hash,)).fetchone()
			if row is None:
				return None
			if row["used_at"] is not None:
				return {"replayed": True, "code_hash": code_hash}
			if row["expires_at"] <= now:
				return None
			# Claim the code atomically: a single guarded UPDATE is the only writer,
			# so two concurrent redemptions cannot both succeed (the loser sees
			# used_at already set and reports a replay, which the server treats as
			# an attack signal and revokes the winner's tokens — RFC-correct).
			cur = self.conn.execute("UPDATE oauth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?", (now, code_hash, now))
			if cur.rowcount == 1:
				return dict(row)
			# UPDATE failed; check if the code was already used by another thread.
			row2 = self.conn.execute("SELECT used_at FROM oauth_codes WHERE code_hash = ?", (code_hash,)).fetchone()
			if row2 is not None and row2[0] is not None:
				return {"replayed": True, "code_hash": code_hash}
			return None

	# --- tokens ---

	def create_token(self, token_type, client_id, user_email, scopes, expires_at, auth_time=None, origin_code_hash=None, parent_id=None, password_state=None, now=None):
		# Mints a new opaque token. Returns (raw, rowid); the raw value is
		# returned to the client and only its hash is stored.
		now = _now(now)
		raw = secrets.token_urlsafe(32)
		_, lastrowid = self._write(
			"INSERT INTO oauth_tokens (token_hash, token_type, client_id, user_email, scopes, auth_time, origin_code_hash, issued_at, expires_at, revoked_at, parent_id, last_used_at, password_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?)",
			(self.hash_token(raw), token_type, client_id, user_email, scopes, auth_time, origin_code_hash, now, expires_at, parent_id, password_state))
		return (raw, lastrowid)

	def lookup_token(self, raw, token_type, now=None):
		# Looks up a token by hash and type. Deliberately returns revoked and
		# expired rows too: the caller decides what they mean (refresh-token
		# reuse detection needs to see revoked rows). Records last_used_at as
		# a side effect; the returned dict carries the row as it was stored.
		now = _now(now)
		row = self._execute_one("SELECT * FROM oauth_tokens WHERE token_hash = ? AND token_type = ?", (self.hash_token(raw), token_type))
		if row is None:
			return None
		self._write("UPDATE oauth_tokens SET last_used_at = ? WHERE id = ?", (now, row["id"]))
		return {k: row[k] for k in _TOKEN_KEYS}

	def revoke_token(self, token_id, now=None):
		now = _now(now)
		self._write("UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (now, token_id))

	def revoke_family_by_origin(self, origin_code_hash, now=None):
		# Revokes every not-yet-revoked token minted from one authorization
		# code (auth-code replay, refresh-token reuse). Returns the count.
		now = _now(now)
		rowcount, _ = self._write("UPDATE oauth_tokens SET revoked_at = ? WHERE origin_code_hash = ? AND revoked_at IS NULL", (now, origin_code_hash))
		return rowcount

	def revoke_client_tokens(self, client_id, now=None):
		# Used at daemon startup to revoke all "system" client-credentials
		# tokens, preserving the api.key rotation-on-restart guarantee.
		now = _now(now)
		rowcount, _ = self._write("UPDATE oauth_tokens SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL", (now, client_id))
		return rowcount

	def revoke_user_tokens(self, user_email, now=None):
		now = _now(now)
		rowcount, _ = self._write("UPDATE oauth_tokens SET revoked_at = ? WHERE user_email = ? AND revoked_at IS NULL", (now, user_email))
		return rowcount

	def purge(self, now=None, keep_seconds=7 * 86400):
		# Nightly cleanup (management/daily_tasks.sh). Rows are kept for
		# keep_seconds after they stop being live: codes after expiry, tokens
		# after revocation (if revoked) or expiry. Returns rows deleted.
		now = _now(now)
		cutoff = now - keep_seconds
		rowcount, _ = self._write("DELETE FROM oauth_codes WHERE expires_at < ?", (cutoff,))
		deleted = rowcount
		rowcount, _ = self._write("DELETE FROM oauth_tokens WHERE COALESCE(revoked_at, expires_at) < ?", (cutoff,))
		deleted += rowcount
		return deleted

	def password_state(self, password_hash, mfa_state_json):
		# Fingerprint of the user's password hash + MFA state, keyed by the
		# persistent server secret (NOT the restart-rotated api.key, unlike
		# auth.py's create_user_password_state_token). Stored on every
		# user-bound token and re-checked on every use, so a password or MFA
		# change through any writer invalidates the user's tokens while
		# tokens survive daemon restarts.
		return hmac.new(self.get_server_secret(), (password_hash + "|" + mfa_state_json).encode(), hashlib.sha256).hexdigest()


if __name__ == "__main__":
	if len(sys.argv) == 2 and sys.argv[1] == "purge":
		import utils  # same directory; deferred so this module stays importable without /etc/mailinabox.conf
		env = utils.load_environment()
		print(OAuthStore(db_path(env)).purge())
	else:
		print("usage: oauth_store.py purge", file=sys.stderr)
		sys.exit(1)
