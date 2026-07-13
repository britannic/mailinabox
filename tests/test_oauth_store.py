# Local unit tests for management/oauth_store.py. These run WITHOUT a
# Mail-in-a-Box — everything happens against a temporary sqlite database:
#
#   python3 -m pytest tests/test_oauth_store.py -q
#
# ruff: noqa: S101, S105, S106

import concurrent.futures
import hashlib
import hmac
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


# --- token lifecycle (Task 2) ---


def test_create_token_returns_raw_and_rowid(store):
	raw, rowid = store.create_token("access", "panel", "user@box.example.com", "admin profile", expires_at=NOW + 3600, auth_time=NOW, origin_code_hash="och", password_state="ps", now=NOW)
	assert isinstance(raw, str)
	assert len(raw) >= 43  # secrets.token_urlsafe(32)
	assert isinstance(rowid, int)
	raw2, rowid2 = store.create_token("access", "panel", "user@box.example.com", "admin profile", expires_at=NOW + 3600, now=NOW)
	assert raw2 != raw
	assert rowid2 == rowid + 1


def test_lookup_token_full_row_and_last_used(store):
	raw, rowid = store.create_token("refresh", "panel", "user@box.example.com", "admin profile", expires_at=NOW + 86400, auth_time=NOW - 100, origin_code_hash="och1", parent_id=None, password_state="ps1", now=NOW)
	row = store.lookup_token(raw, "refresh", now=NOW + 50)
	assert row is not None
	assert set(row.keys()) == {"id", "token_type", "client_id", "user_email", "scopes", "auth_time", "origin_code_hash", "issued_at", "expires_at", "revoked_at", "parent_id", "last_used_at", "password_state"}
	assert row["id"] == rowid
	assert row["token_type"] == "refresh"
	assert row["client_id"] == "panel"
	assert row["user_email"] == "user@box.example.com"
	assert row["scopes"] == "admin profile"
	assert row["auth_time"] == NOW - 100
	assert row["origin_code_hash"] == "och1"
	assert row["issued_at"] == NOW
	assert row["expires_at"] == NOW + 86400
	assert row["revoked_at"] is None
	assert row["parent_id"] is None
	assert row["password_state"] == "ps1"
	# The first lookup recorded last_used_at; a second lookup sees it.
	row2 = store.lookup_token(raw, "refresh", now=NOW + 99)
	assert row2["last_used_at"] == NOW + 50


def test_lookup_token_wrong_type_or_missing(store):
	raw, _ = store.create_token("access", "panel", "u@x", "admin", expires_at=NOW + 3600, now=NOW)
	assert store.lookup_token(raw, "refresh", now=NOW) is None
	assert store.lookup_token("never-issued", "access", now=NOW) is None


def test_lookup_token_returns_revoked_and_expired_rows(store):
	# Revoked and expired rows MUST still be returned: the caller decides
	# what they mean (refresh-token reuse detection depends on this).
	raw, rowid = store.create_token("refresh", "panel", "u@x", "admin", expires_at=NOW + 86400, now=NOW)
	store.revoke_token(rowid, now=NOW + 1)
	row = store.lookup_token(raw, "refresh", now=NOW + 2)
	assert row is not None
	assert row["revoked_at"] == NOW + 1
	raw2, _ = store.create_token("access", "panel", "u@x", "admin", expires_at=NOW + 10, now=NOW)
	row2 = store.lookup_token(raw2, "access", now=NOW + 9999)
	assert row2 is not None
	assert row2["expires_at"] == NOW + 10


def test_revoke_token_sets_revoked_at_once(store):
	raw, rowid = store.create_token("access", "panel", "u@x", "admin", expires_at=NOW + 3600, now=NOW)
	store.revoke_token(rowid, now=NOW + 1)
	store.revoke_token(rowid, now=NOW + 5)  # second revocation must not move the timestamp
	assert store.lookup_token(raw, "access", now=NOW + 6)["revoked_at"] == NOW + 1


def test_revoke_family_by_origin(store):
	raw1, id1 = store.create_token("access", "panel", "u@x", "admin", expires_at=NOW + 3600, origin_code_hash="fam1", now=NOW)
	raw2, _ = store.create_token("refresh", "panel", "u@x", "admin", expires_at=NOW + 86400, origin_code_hash="fam1", now=NOW)
	raw3, _ = store.create_token("refresh", "panel", "u@x", "admin", expires_at=NOW + 86400, origin_code_hash="fam2", now=NOW)
	store.revoke_token(id1, now=NOW + 1)
	# Only the not-yet-revoked member of fam1 counts.
	assert store.revoke_family_by_origin("fam1", now=NOW + 2) == 1
	assert store.lookup_token(raw2, "refresh", now=NOW + 3)["revoked_at"] == NOW + 2
	assert store.lookup_token(raw1, "access", now=NOW + 3)["revoked_at"] == NOW + 1
	assert store.lookup_token(raw3, "refresh", now=NOW + 3)["revoked_at"] is None
	assert store.revoke_family_by_origin("fam1", now=NOW + 4) == 0


def test_revoke_client_tokens(store):
	store.create_token("access", "system", None, "admin", expires_at=NOW + 3600, now=NOW)
	raw_panel, _ = store.create_token("access", "panel", "u@x", "admin", expires_at=NOW + 3600, now=NOW)
	assert store.revoke_client_tokens("system", now=NOW + 1) == 1
	assert store.lookup_token(raw_panel, "access", now=NOW + 2)["revoked_at"] is None
	assert store.revoke_client_tokens("system", now=NOW + 3) == 0


def test_revoke_user_tokens(store):
	store.create_token("access", "panel", "alice@x", "admin", expires_at=NOW + 3600, now=NOW)
	store.create_token("refresh", "roundcube", "alice@x", "mail", expires_at=NOW + 3600, now=NOW)
	raw_bob, _ = store.create_token("access", "panel", "bob@x", "admin", expires_at=NOW + 3600, now=NOW)
	assert store.revoke_user_tokens("alice@x", now=NOW + 1) == 2
	assert store.lookup_token(raw_bob, "access", now=NOW + 2)["revoked_at"] is None


def test_purge_retention(store):
	keep = 7 * 86400
	# Codes: expired beyond retention (purged) / expired within retention (kept, but dead) / live (kept).
	store.save_code("code-ancient", "panel", "u@x", "admin", "https://x/admin", "c", "S256", auth_time=NOW - keep - 120, now=NOW - keep - 120)
	store.save_code("code-recent", "panel", "u@x", "admin", "https://x/admin", "c", "S256", auth_time=NOW - 3600, now=NOW - 3600)
	store.save_code("code-live", "panel", "u@x", "admin", "https://x/admin", "c", "S256", auth_time=NOW - 30, now=NOW - 30)
	# Tokens: expired beyond retention (purged) / revoked beyond retention (purged)
	# / live (kept) / recently revoked (kept — reuse-detection window).
	store.create_token("access", "panel", "u@x", "admin", expires_at=NOW - keep - 10, now=NOW - keep - 3600)
	_, old_revoked_id = store.create_token("refresh", "panel", "u@x", "admin", expires_at=NOW + 86400, now=NOW - keep - 3600)
	store.revoke_token(old_revoked_id, now=NOW - keep - 10)
	raw_live, _ = store.create_token("access", "panel", "u@x", "admin", expires_at=NOW + 3600, now=NOW)
	raw_recent_revoked, recent_revoked_id = store.create_token("refresh", "panel", "u@x", "admin", expires_at=NOW + 86400, now=NOW - 60)
	store.revoke_token(recent_revoked_id, now=NOW - 10)
	assert store.purge(now=NOW) == 3
	assert store.take_code("code-live", now=NOW) is not None
	assert store.lookup_token(raw_live, "access", now=NOW) is not None
	assert store.lookup_token(raw_recent_revoked, "refresh", now=NOW) is not None
	assert store.conn.execute("SELECT COUNT(*) FROM oauth_codes").fetchone()[0] == 2
	assert store.conn.execute("SELECT COUNT(*) FROM oauth_tokens").fetchone()[0] == 2


def test_password_state_deterministic_and_secret_dependent(env, tmp_path):
	s1 = OAuthStore(db_path(env))
	state = s1.password_state("{SHA512-CRYPT}$6$abc", '[["totp", "x"]]')
	# Deterministic for the same inputs on the same box.
	assert s1.password_state("{SHA512-CRYPT}$6$abc", '[["totp", "x"]]') == state
	assert len(state) == 64
	assert all(c in "0123456789abcdef" for c in state)
	# Any change to the password hash or the MFA state changes the fingerprint.
	assert s1.password_state("{SHA512-CRYPT}$6$abd", '[["totp", "x"]]') != state
	assert s1.password_state("{SHA512-CRYPT}$6$abc", "[]") != state
	# Exact construction: HMAC-SHA256(server_secret, password_hash | mfa_state_json).
	assert state == hmac.new(s1.get_server_secret(), b'{SHA512-CRYPT}$6$abc|[["totp", "x"]]', hashlib.sha256).hexdigest()
	# A different box (different server secret) produces a different fingerprint
	# for identical credentials — the state is secret-dependent.
	s2 = OAuthStore(str(tmp_path / "other" / "auth.sqlite"))
	assert s2.password_state("{SHA512-CRYPT}$6$abc", '[["totp", "x"]]') != state


def test_concurrent_take_code_single_winner(store):
	# Regression test for thread-safety: concurrent take_code calls for the
	# same code must result in exactly one winner and all others seeing a
	# replay or expired sentinel. No call should raise.
	store.save_code("concurrent", "panel", "u@x", "admin", "https://x/admin", "c", "S256", auth_time=NOW, now=NOW)

	def take_it():
		return store.take_code("concurrent", now=NOW + 1)

	# Fire 50 concurrent take_code calls
	with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
		results = list(executor.map(lambda _: take_it(), range(50)))

	# Exactly one should succeed (return a full row with no 'replayed' key)
	successes = [r for r in results if r is not None and "replayed" not in r]
	assert len(successes) == 1
	assert successes[0]["code_hash"] == OAuthStore.hash_token("concurrent")

	# All others should either be None (expired) or the replay sentinel
	for r in results:
		if r is not None:
			assert r.get("replayed") is True or r == successes[0]



# --- WebAuthn schema + challenges (Task 2) ---


def test_webauthn_schema_created(env):
	s = OAuthStore(db_path(env))
	tables = {r[0] for r in s.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
	assert {"webauthn_credentials", "webauthn_challenges"} <= tables
	# Column name -> declared type must match spec §7 exactly.
	cred_cols = {r[1]: r[2] for r in s.conn.execute("PRAGMA table_info(webauthn_credentials)")}
	assert cred_cols == {
		"id": "INTEGER",
		"user_email": "TEXT",
		"credential_id": "BLOB",
		"public_key": "BLOB",
		"sign_count": "INTEGER",
		"transports": "TEXT",
		"aaguid": "TEXT",
		"name": "TEXT",
		"created_at": "INTEGER",
		"last_used_at": "INTEGER",
	}
	chal_cols = {r[1]: r[2] for r in s.conn.execute("PRAGMA table_info(webauthn_challenges)")}
	assert chal_cols == {
		"challenge": "TEXT",
		"user_email": "TEXT",
		"type": "TEXT",
		"expires_at": "INTEGER",
	}
	# The hot-path lookups must be index-backed (index NAMES are incidental).
	def indexed_column_sets(table):
		names = [r[0] for r in s.conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=?", (table,))]
		return {tuple(r[2] for r in s.conn.execute("PRAGMA index_info(%s)" % name)) for name in names}  # noqa: UP031
	assert ("user_email",) in indexed_column_sets("webauthn_credentials")
	assert ("expires_at",) in indexed_column_sets("webauthn_challenges")



def test_webauthn_challenge_roundtrip(store):
	store.save_webauthn_challenge("chal-abc", "user@box.example.com", "registration", now=NOW)
	row = store.take_webauthn_challenge("chal-abc", "registration", now=NOW + 10)
	assert row is not None
	assert row["challenge"] == "chal-abc"
	assert row["user_email"] == "user@box.example.com"
	assert row["type"] == "registration"
	assert row["expires_at"] == NOW + 120  # TTL is now + 120


def test_webauthn_challenge_authentication_user_email_null(store):
	# Sign-in (authentication) challenges are usernameless: user_email is NULL.
	store.save_webauthn_challenge("chal-auth", None, "authentication", now=NOW)
	row = store.take_webauthn_challenge("chal-auth", "authentication", now=NOW + 1)
	assert row is not None
	assert row["user_email"] is None


def test_webauthn_challenge_single_use(store):
	store.save_webauthn_challenge("chal-once", "u@x", "registration", now=NOW)
	assert store.take_webauthn_challenge("chal-once", "registration", now=NOW + 1) is not None
	# A second redemption of the same challenge must fail — the row is gone
	# (pure single-use: the atomic DELETE is the claim, no retained row).
	assert store.take_webauthn_challenge("chal-once", "registration", now=NOW + 2) is None


def test_webauthn_challenge_expired(store):
	store.save_webauthn_challenge("chal-exp", "u@x", "registration", now=NOW)
	# expires_at must be strictly greater than now; at NOW + 120 it is dead.
	assert store.take_webauthn_challenge("chal-exp", "registration", now=NOW + 120) is None
	# The expired take did NOT consume the row; a later take is still expired.
	assert store.take_webauthn_challenge("chal-exp", "registration", now=NOW + 121) is None


def test_webauthn_challenge_type_isolation(store):
	# A registration challenge cannot satisfy an authentication take (§9.3).
	store.save_webauthn_challenge("chal-typed", "u@x", "registration", now=NOW)
	assert store.take_webauthn_challenge("chal-typed", "authentication", now=NOW + 1) is None
	# The wrong-type take did not consume it; the correctly-typed take works.
	assert store.take_webauthn_challenge("chal-typed", "registration", now=NOW + 1) is not None


def test_webauthn_challenge_missing(store):
	assert store.take_webauthn_challenge("never-saved", "authentication", now=NOW) is None


def test_webauthn_challenge_concurrent_single_winner(store):
	# The guarded DELETE is the atomic claim: concurrent takes of one
	# challenge yield exactly one winner and no call raises.
	store.save_webauthn_challenge("chal-race", "u@x", "authentication", now=NOW)

	def take_it():
		return store.take_webauthn_challenge("chal-race", "authentication", now=NOW + 1)

	with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
		results = list(executor.map(lambda _: take_it(), range(50)))

	winners = [r for r in results if r is not None]
	assert len(winners) == 1
	assert winners[0]["challenge"] == "chal-race"
	assert winners[0]["user_email"] == "u@x"



def test_purge_webauthn_challenges(store):
	# Expired challenges are deleted; live ones are kept. No retention window
	# (unlike codes/tokens): a 120s single-use nonce is dead the instant it expires.
	store.save_webauthn_challenge("chal-old", "u@x", "registration", now=NOW - 200)   # expires_at = NOW - 80 (expired)
	store.save_webauthn_challenge("chal-live", None, "authentication", now=NOW - 30)  # expires_at = NOW + 90 (live)
	assert store.purge_webauthn_challenges(now=NOW) == 1
	assert store.conn.execute("SELECT challenge FROM webauthn_challenges").fetchone()[0] == "chal-live"


def test_purge_folds_in_challenges(env):
	# OAuthStore.purge() must also drop expired challenges so daily_tasks.sh
	# (which only calls purge()) cleans them up with no edit (spec §7).
	s = OAuthStore(db_path(env))
	s.save_webauthn_challenge("chal-old", "u@x", "registration", now=NOW - 200)   # expired at NOW - 80
	s.save_webauthn_challenge("chal-live", None, "authentication", now=NOW - 30)  # live until NOW + 90
	# No codes/tokens exist, so purge()'s count is exactly the one expired challenge.
	assert s.purge(now=NOW) == 1
	assert s.conn.execute("SELECT COUNT(*) FROM webauthn_challenges").fetchone()[0] == 1


# --- webauthn credentials (Task 3) ---

CRED_ID = b"\x01\x02\x03cred-id-bytes"
PUBKEY = b"\xa5\x01\x02\x03\x26cose-key-bytes"


def test_add_and_get_webauthn_credentials(store):
	rowid = store.add_webauthn_credential(
		"alice@box.example.com", CRED_ID, PUBKEY, 0,
		'["internal","hybrid"]', "00000000-0000-0000-0000-000000000000",
		"Alice's YubiKey", now=NOW)
	assert isinstance(rowid, int)
	# Look up by the raw credential-id bytes.
	row = store.get_webauthn_credential_by_id(CRED_ID)
	assert row is not None
	assert row["id"] == rowid
	assert row["user_email"] == "alice@box.example.com"
	assert row["credential_id"] == CRED_ID          # BLOB round-trips as bytes
	assert isinstance(row["credential_id"], bytes)
	assert row["public_key"] == PUBKEY
	assert isinstance(row["public_key"], bytes)
	assert row["sign_count"] == 0
	assert row["transports"] == '["internal","hybrid"]'
	assert row["aaguid"] == "00000000-0000-0000-0000-000000000000"
	assert row["name"] == "Alice's YubiKey"
	assert row["created_at"] == NOW
	assert row["last_used_at"] is None
	# Unknown credential id → None (never KeyError).
	assert store.get_webauthn_credential_by_id(b"nope") is None
	# get_webauthn_credentials is scoped to one user and returns a list of dicts.
	store.add_webauthn_credential("bob@box.example.com", b"bob-cred", PUBKEY, 5, None, None, "Bob's phone", now=NOW + 1)
	alice = store.get_webauthn_credentials("alice@box.example.com")
	assert [c["credential_id"] for c in alice] == [CRED_ID]
	assert store.get_webauthn_credentials("bob@box.example.com")[0]["name"] == "Bob's phone"
	assert store.get_webauthn_credentials("nobody@box.example.com") == []


def test_update_webauthn_sign_count(store):
	rowid = store.add_webauthn_credential("alice@box.example.com", CRED_ID, PUBKEY, 0, None, None, "k", now=NOW)
	store.update_webauthn_sign_count(rowid, 7, now=NOW + 100)
	row = store.get_webauthn_credential_by_id(CRED_ID)
	assert row["sign_count"] == 7
	assert row["last_used_at"] == NOW + 100


def test_rename_and_delete_webauthn_credential_scoped(store):
	rowid = store.add_webauthn_credential("alice@box.example.com", CRED_ID, PUBKEY, 0, None, None, "old name", now=NOW)
	# A different user cannot rename Alice's credential.
	assert store.rename_webauthn_credential(rowid, "mallory@box.example.com", "hacked") is False
	assert store.get_webauthn_credential_by_id(CRED_ID)["name"] == "old name"
	# The owner can.
	assert store.rename_webauthn_credential(rowid, "alice@box.example.com", "new name") is True
	assert store.get_webauthn_credential_by_id(CRED_ID)["name"] == "new name"
	# A different user cannot delete it.
	assert store.delete_webauthn_credential(rowid, "mallory@box.example.com") is False
	assert store.get_webauthn_credential_by_id(CRED_ID) is not None
	# An unknown row id is a no-op → False.
	assert store.delete_webauthn_credential(99999, "alice@box.example.com") is False
	# The owner can delete it.
	assert store.delete_webauthn_credential(rowid, "alice@box.example.com") is True
	assert store.get_webauthn_credential_by_id(CRED_ID) is None


def test_count_outstanding_webauthn_challenges(store):
	# Two live authentication challenges + one registration challenge.
	store.save_webauthn_challenge("chal-a", None, "authentication", now=NOW)
	store.save_webauthn_challenge("chal-b", None, "authentication", now=NOW)
	store.save_webauthn_challenge("chal-r", "alice@box.example.com", "registration", now=NOW)
	# Counts only live challenges of the requested type (type isolation).
	assert store.count_outstanding_webauthn_challenges("authentication", now=NOW + 1) == 2
	assert store.count_outstanding_webauthn_challenges("registration", now=NOW + 1) == 1
	# TTL is now+120, so past expiry the live count drops to zero.
	assert store.count_outstanding_webauthn_challenges("authentication", now=NOW + 121) == 0
