#!/usr/local/lib/mailinabox/env/bin/python
# Storage layer for the OAuth 2.0 authorization server: the persistent
# server secret, single-use authorization codes, and access/refresh tokens,
# kept in a root-only sqlite database at STORAGE_ROOT/auth/auth.sqlite.
#
# STDLIB ONLY: this module must not import anything outside the Python
# standard library because setup/oauth.sh drives it with the system
# python3, outside the management daemon's virtualenv.

import hashlib
import os
import secrets
import sqlite3
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
		self.conn.executescript(_SCHEMA)

	def get_server_secret(self):
		# A stable secret that persists across daemon restarts (unlike the
		# api.key), used to key password-state fingerprints and the authorize
		# form binding token. Created on first use.
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

	# --- authorization codes ---

	def save_code(self, raw_code, client_id, user_email, scopes, redirect_uri, code_challenge, code_challenge_method, auth_time, now=None):
		now = _now(now)
		self.conn.execute(
			"INSERT INTO oauth_codes (code_hash, client_id, user_email, scopes, redirect_uri, code_challenge, code_challenge_method, auth_time, expires_at, used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
			(self.hash_token(raw_code), client_id, user_email, scopes, redirect_uri, code_challenge, code_challenge_method, auth_time, now + 60))

	def take_code(self, raw_code, now=None):
		# Single-use redemption. Returns the full row dict on success (and
		# marks the code used), {"replayed": True, "code_hash": ...} if the
		# code was already used (the caller must revoke the token family),
		# or None if the code is unknown or expired.
		now = _now(now)
		code_hash = self.hash_token(raw_code)
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
