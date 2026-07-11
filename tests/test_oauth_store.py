# Local unit tests for management/oauth_store.py. These run WITHOUT a
# Mail-in-a-Box — everything happens against a temporary sqlite database:
#
#   python3 -m pytest tests/test_oauth_store.py -q
#
# ruff: noqa: S101

import hashlib
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "management"))

from oauth_store import OAuthStore, auth_dir, db_path

# A fixed "current time" so every expiry assertion is deterministic.
NOW = 1_800_000_000


@pytest.fixture
def env(tmp_path):
	return {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "box.example.com"}


@pytest.fixture
def store(env):
	return OAuthStore(db_path(env))


def test_paths(env):
	assert auth_dir(env) == os.path.join(env["STORAGE_ROOT"], "auth")
	assert db_path(env) == os.path.join(env["STORAGE_ROOT"], "auth", "auth.sqlite")


def test_schema_created_and_idempotent(env):
	s1 = OAuthStore(db_path(env))
	tables = {r[0] for r in s1.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
	assert {"oauth_config", "oauth_codes", "oauth_tokens"} <= tables
	# Index NAMES are incidental (a future migration may rename them);
	# what matters is that these lookups are index-backed.
	def indexed_column_sets(table):
		names = [r[0] for r in s1.conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=?", (table,))]
		return {tuple(r[2] for r in s1.conn.execute("PRAGMA index_info(%s)" % name)) for name in names}  # noqa: UP031
	assert ("origin_code_hash",) in indexed_column_sets("oauth_tokens")
	assert ("user_email", "revoked_at") in indexed_column_sets("oauth_tokens")
	assert ("expires_at",) in indexed_column_sets("oauth_codes")
	# Re-opening the same database must neither raise nor lose data.
	s1.conn.execute("INSERT INTO oauth_config (key, value) VALUES ('probe', 'x')")
	s2 = OAuthStore(db_path(env))
	assert s2.conn.execute("SELECT value FROM oauth_config WHERE key = 'probe'").fetchone()[0] == "x"


def test_file_modes(env):
	OAuthStore(db_path(env))
	assert stat.S_IMODE(os.stat(auth_dir(env)).st_mode) == 0o700
	assert stat.S_IMODE(os.stat(db_path(env)).st_mode) == 0o600


def test_server_secret_stable_across_instances(env):
	s1 = OAuthStore(db_path(env))
	secret1 = s1.get_server_secret()
	assert isinstance(secret1, bytes)
	assert len(secret1) == 32
	assert s1.get_server_secret() == secret1
	# A second store on the same database (e.g. after a daemon restart)
	# sees the same secret — this is what makes tokens restart-proof.
	s2 = OAuthStore(db_path(env))
	assert s2.get_server_secret() == secret1


def test_server_secret_differs_between_databases(tmp_path):
	s1 = OAuthStore(str(tmp_path / "a" / "auth.sqlite"))
	s2 = OAuthStore(str(tmp_path / "b" / "auth.sqlite"))
	assert s1.get_server_secret() != s2.get_server_secret()


def test_hash_token():
	assert OAuthStore.hash_token("abc") == hashlib.sha256(b"abc").hexdigest()
	assert OAuthStore.hash_token("abc") != OAuthStore.hash_token("abd")


def test_take_code_roundtrip(store):
	store.save_code("rawcode", "panel", "user@box.example.com", "admin profile", "https://box.example.com/admin", "challenge123", "S256", auth_time=NOW - 5, now=NOW)
	row = store.take_code("rawcode", now=NOW + 10)
	assert row is not None
	assert "replayed" not in row
	assert row["code_hash"] == OAuthStore.hash_token("rawcode")
	assert row["client_id"] == "panel"
	assert row["user_email"] == "user@box.example.com"
	assert row["scopes"] == "admin profile"
	assert row["redirect_uri"] == "https://box.example.com/admin"
	assert row["code_challenge"] == "challenge123"
	assert row["code_challenge_method"] == "S256"
	assert row["auth_time"] == NOW - 5
	assert row["expires_at"] == NOW + 60
	assert row["used_at"] is None


def test_take_code_replay_sentinel(store):
	store.save_code("rawcode", "panel", "user@box.example.com", "admin", "https://box.example.com/admin", "c", "S256", auth_time=NOW, now=NOW)
	assert store.take_code("rawcode", now=NOW + 1) is not None
	assert store.take_code("rawcode", now=NOW + 2) == {"replayed": True, "code_hash": OAuthStore.hash_token("rawcode")}


def test_take_code_expired(store):
	store.save_code("rawcode", "panel", "user@box.example.com", "admin", "https://box.example.com/admin", "c", "S256", auth_time=NOW, now=NOW)
	# expires_at must be strictly greater than now; at NOW + 60 the code is dead.
	assert store.take_code("rawcode", now=NOW + 60) is None
	# An expired-but-never-used code is NOT a replay.
	assert store.take_code("rawcode", now=NOW + 61) is None


def test_take_code_missing(store):
	assert store.take_code("never-saved", now=NOW) is None
