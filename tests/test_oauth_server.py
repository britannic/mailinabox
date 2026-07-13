#!/usr/bin/env python3
# Local unit tests for management/oauth_server.py.
#
# Run: python3 -m pytest tests/test_oauth_server.py -q
#
# No Mail-in-a-Box is required: the OAuth store lives in a pytest tmp_path,
# the client registry is replaced with stand-ins whose secret files also live
# in tmp_path, user auth is faked through FakeDeps, and time.time is
# monkeypatched so expiry behavior is tested with explicit timestamps.
#
# `re` and `urllib.parse` were unused by the Task 4 tests below; they were
# imported ahead of need because Tasks 5-8 append authorization_code/PKCE/
# refresh/authorize tests to this same file that need them (Task 7's
# authorize-flow tests are the first to actually use them).
#
# ruff: noqa: ARG001, ARG005, EM101, PLR6201, S101, S105, S106, S107, TRY003

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.parse
from types import SimpleNamespace

import pytest
from flask import Flask, request
from flask.testing import FlaskClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "management"))

import oauth_clients
import oauth_server

TEST_NOW = 1_700_000_000


class HttpsTestClient(FlaskClient):
	# management/daemon.py no longer sets the global AUTHLIB_INSECURE_TRANSPORT
	# bypass (Task 11, Step 9): it reconstructs the real scheme per-request from
	# X-Forwarded-Proto, as nginx would set it in production. This test app is a
	# bare Flask app (not daemon.py's), so there's no such before_request hook
	# here; instead, drive every request over https directly so Authlib's
	# InsecureTransportError check sees a secure scheme, same as it would on-box.
	def open(self, *args, **kwargs):
		kwargs.setdefault("base_url", "https://localhost")
		return super().open(*args, **kwargs)


class FakeDeps:
	# Mirrors the deps object daemon.py constructs in Task 9.
	def __init__(self):
		self.users = {}
		self.failed_logins = []

	def add_user(self, email, password="swordfish", privileges=None, totp=None):
		self.users[email] = {
			"password": password,
			"hash": "{SHA512-CRYPT}$6$salt$" + hashlib.sha256(email.encode()).hexdigest(),
			"mfa": "[]" if totp is None else json.dumps([{"id": 1, "type": "totp"}]),
			"totp": totp,
			"privileges": privileges if privileges is not None else ["admin"],
		}

	def check_user_password(self, email, password):
		u = self.users.get(email)
		return u is not None and u["password"] == password

	def get_mail_password(self, email):
		u = self.users.get(email)
		return u["hash"] if u else None

	def get_mfa_state_json(self, email):
		u = self.users.get(email)
		return u["mfa"] if u else "[]"

	def validate_mfa(self, email, totp_code):
		u = self.users.get(email)
		if u is None or u["totp"] is None:
			return "ok"
		if not totp_code:
			return "missing-totp-token"
		if totp_code != u["totp"]:
			return "invalid-totp-token"
		return "ok"

	def get_user_privileges(self, email):
		u = self.users.get(email)
		return u["privileges"] if u else []

	def log_failed_login(self, request):
		self.failed_logins.append(request.path)


def basic_auth(client_id, client_secret):
	return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()}


def pkce_pair():
	verifier = secrets.token_urlsafe(32)
	challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
	return verifier, challenge


@pytest.fixture
def clock(monkeypatch):
	state = {"now": float(TEST_NOW)}
	monkeypatch.setattr(time, "time", lambda: state["now"])
	return state


@pytest.fixture
def box(tmp_path, monkeypatch, clock):
	env = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "box.example.com"}
	auth_dir = tmp_path / "auth"
	auth_dir.mkdir(mode=0o700)
	(auth_dir / "dovecot_client_secret.txt").write_text("dovecot-secret-123\n")
	(auth_dir / "roundcube_client_secret.txt").write_text("roundcube-secret-456\n")
	(auth_dir / "system.key").write_text("system-secret-789\n")

	# Stand-ins for oauth_clients.OAuthClient (same plain attrs, per contract),
	# so these tests do not depend on OAuthClient's constructor signature and
	# do not need /var/lib/mailinabox/api.key to exist.
	clients = {
		"panel": SimpleNamespace(client_id="panel", is_public=True, grant_types=frozenset({"authorization_code", "refresh_token"}), allowed_scopes=frozenset({"admin", "profile"}), redirect_uris=("https://box.example.com/admin",), secret_path=None),
		"roundcube": SimpleNamespace(client_id="roundcube", is_public=False, grant_types=frozenset({"authorization_code", "refresh_token"}), allowed_scopes=frozenset({"mail", "profile"}), redirect_uris=("https://box.example.com/mail/index.php/login/oauth",), secret_path=str(auth_dir / "roundcube_client_secret.txt")),
		"system": SimpleNamespace(client_id="system", is_public=False, grant_types=frozenset({"client_credentials"}), allowed_scopes=frozenset({"admin"}), redirect_uris=(), secret_path=str(auth_dir / "system.key")),
		"dovecot": SimpleNamespace(client_id="dovecot", is_public=False, grant_types=frozenset(), allowed_scopes=frozenset(), redirect_uris=(), secret_path=str(auth_dir / "dovecot_client_secret.txt")),
	}
	monkeypatch.setattr(oauth_clients, "get_client", lambda env_, client_id: clients.get(client_id))

	deps = FakeDeps()
	deps.add_user("alice@box.example.com")

	app = Flask("oauth-test", template_folder=os.path.join(os.path.dirname(__file__), "..", "management", "templates"))
	app.testing = True
	app.test_client_class = HttpsTestClient
	oauth_server.init_oauth(app, env, deps)

	return SimpleNamespace(http=app.test_client(), app=app, env=env, deps=deps, store=oauth_server.current_store(env), clock=clock, clients=clients)


# ---------------------------------------------------------------------------
# Task 4: client_credentials grant + POST /oauth/token
# ---------------------------------------------------------------------------

def test_client_credentials_issues_access_token(box):
	r = box.http.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "admin"}, headers=basic_auth("system", "system-secret-789"))
	assert r.status_code == 200
	body = r.get_json()
	assert body["token_type"] == "Bearer"
	assert body["expires_in"] == oauth_server.ACCESS_TOKEN_TTL
	assert body["scope"] == "admin"
	assert "refresh_token" not in body
	row = box.store.lookup_token(body["access_token"], "access")
	assert row is not None
	assert row["client_id"] == "system"
	assert row["user_email"] is None
	assert row["password_state"] is None
	assert row["expires_at"] == TEST_NOW + oauth_server.ACCESS_TOKEN_TTL


def test_client_credentials_default_scope_is_all_allowed(box):
	r = box.http.post("/oauth/token", data={"grant_type": "client_credentials"}, headers=basic_auth("system", "system-secret-789"))
	assert r.status_code == 200
	assert r.get_json()["scope"] == "admin"


def test_client_credentials_secret_post(box):
	r = box.http.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": "system", "client_secret": "system-secret-789"})
	assert r.status_code == 200
	assert "access_token" in r.get_json()


def test_client_credentials_wrong_secret_logs_and_fails(box):
	r = box.http.post("/oauth/token", data={"grant_type": "client_credentials"}, headers=basic_auth("system", "wrong"))
	assert r.status_code in (400, 401)
	assert r.get_json()["error"] == "invalid_client"
	assert box.deps.failed_logins == ["/oauth/token"]


def test_client_credentials_scope_broadening_rejected(box):
	r = box.http.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "admin mail"}, headers=basic_auth("system", "system-secret-789"))
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_scope"


def test_credentials_in_query_string_rejected(box):
	# Correct credentials, but presented in the query string: hard 400, no grant processing.
	r = box.http.post("/oauth/token?client_id=system&client_secret=system-secret-789", data={"grant_type": "client_credentials"})
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_request"


def test_public_client_cannot_use_client_credentials(box):
	r = box.http.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": "panel"})
	assert r.status_code in (400, 401)
	assert r.get_json()["error"] in ("invalid_client", "unauthorized_client")


def test_internal_errors_return_json_server_error(box, monkeypatch):
	def boom(env_, client_id):
		raise RuntimeError("registry exploded")
	monkeypatch.setattr(oauth_clients, "get_client", boom)
	r = box.http.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "admin"}, headers=basic_auth("system", "system-secret-789"))
	assert r.status_code == 500
	assert r.content_type.startswith("application/json")
	assert r.get_json() == {"error": "server_error"}
	assert "Traceback" not in r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Task 5: POST /oauth/introspect and POST /oauth/revoke
# ---------------------------------------------------------------------------

def make_user_tokens(box, client_id="roundcube", email="alice@box.example.com", scopes="mail profile", auth_time=None, origin="origin-hash-1"):
	# Builds a linked access+refresh pair directly in the store, the same way
	# the code-exchange grant does (Task 6), so introspection/revocation can be
	# tested independently of the grants.
	now = int(time.time())
	auth_time = auth_time if auth_time is not None else now
	ps = box.store.password_state(box.deps.get_mail_password(email), box.deps.get_mfa_state_json(email))
	access_raw, access_id = box.store.create_token("access", client_id, email, scopes, now + oauth_server.ACCESS_TOKEN_TTL, auth_time=auth_time, origin_code_hash=origin, password_state=ps)
	refresh_raw, refresh_id = box.store.create_token("refresh", client_id, email, scopes, min(now + oauth_server.REFRESH_TOKEN_TTL, auth_time + oauth_server.CHAIN_LIFETIME_CAP), auth_time=auth_time, origin_code_hash=origin, password_state=ps)
	return SimpleNamespace(access=access_raw, access_id=access_id, refresh=refresh_raw, refresh_id=refresh_id, origin=origin)


def introspect(box, token, client_id="dovecot", secret="dovecot-secret-123", extra_headers=None, query=""):
	headers = basic_auth(client_id, secret)
	if extra_headers:
		headers.update(extra_headers)
	return box.http.post("/oauth/introspect" + query, data={"token": token}, headers=headers)


def test_introspect_public_path_guard_404(box):
	# nginx always sets X-Forwarded-For on proxied requests; its presence means
	# the request came through the public path and must 404 before anything else.
	t = make_user_tokens(box)
	r = introspect(box, t.access, extra_headers={"X-Forwarded-For": "203.0.113.5"})
	assert r.status_code == 404


def test_introspect_active_token(box):
	t = make_user_tokens(box)
	r = introspect(box, t.access)
	assert r.status_code == 200
	assert r.get_json() == {"active": True, "username": "alice@box.example.com", "scope": "mail profile", "client_id": "roundcube", "exp": TEST_NOW + oauth_server.ACCESS_TOKEN_TTL, "token_type": "Bearer"}


def test_introspect_wrong_secret_inactive_and_logged(box):
	t = make_user_tokens(box)
	r = introspect(box, t.access, secret="wrong")
	assert r.status_code == 200
	assert r.get_json() == {"active": False}
	assert box.deps.failed_logins == ["/oauth/introspect"]


def test_introspect_non_dovecot_client_inactive(box):
	# Even a valid confidential client that is not 'dovecot' is refused.
	t = make_user_tokens(box)
	r = introspect(box, t.access, client_id="roundcube", secret="roundcube-secret-456")
	assert r.status_code == 200
	assert r.get_json() == {"active": False}


def test_introspect_expired_token_inactive(box):
	t = make_user_tokens(box)
	box.clock["now"] = float(TEST_NOW + oauth_server.ACCESS_TOKEN_TTL + 1)
	assert introspect(box, t.access).get_json() == {"active": False}


def test_introspect_revoked_token_inactive(box):
	t = make_user_tokens(box)
	box.store.revoke_token(t.access_id)
	assert introspect(box, t.access).get_json() == {"active": False}


def test_introspect_token_without_mail_scope_inactive(box):
	# A panel token (scopes: admin profile) can never log into IMAP.
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	assert introspect(box, t.access).get_json() == {"active": False}


def test_introspect_password_change_inactive(box):
	t = make_user_tokens(box)
	box.deps.users["alice@box.example.com"]["hash"] = "{SHA512-CRYPT}$6$salt$CHANGED"
	assert introspect(box, t.access).get_json() == {"active": False}


def test_introspect_missing_token_inactive(box):
	assert introspect(box, "").get_json() == {"active": False}


def test_introspect_credentials_in_query_inactive(box):
	t = make_user_tokens(box)
	r = box.http.post("/oauth/introspect?client_id=dovecot&client_secret=dovecot-secret-123", data={"token": t.access})
	assert r.status_code == 200
	assert r.get_json() == {"active": False}


def test_revoke_refresh_token_revokes_family(box):
	t = make_user_tokens(box)
	r = box.http.post("/oauth/revoke", data={"token": t.refresh}, headers=basic_auth("roundcube", "roundcube-secret-456"))
	assert r.status_code == 200
	assert box.store.lookup_token(t.refresh, "refresh")["revoked_at"] is not None
	assert box.store.lookup_token(t.access, "access")["revoked_at"] is not None


def test_revoke_access_token_revokes_only_itself(box):
	t = make_user_tokens(box)
	r = box.http.post("/oauth/revoke", data={"token": t.access, "token_type_hint": "access_token"}, headers=basic_auth("roundcube", "roundcube-secret-456"))
	assert r.status_code == 200
	assert box.store.lookup_token(t.access, "access")["revoked_at"] is not None
	assert box.store.lookup_token(t.refresh, "refresh")["revoked_at"] is None


def test_revoke_public_panel_client_without_secret(box):
	# The panel is a public client: it may revoke its own tokens (logout flow)
	# authenticated by client_id alone.
	t = make_user_tokens(box, client_id="panel", scopes="admin profile", origin="origin-panel-1")
	r = box.http.post("/oauth/revoke", data={"token": t.refresh, "client_id": "panel"})
	assert r.status_code == 200
	assert box.store.lookup_token(t.refresh, "refresh")["revoked_at"] is not None
	assert box.store.lookup_token(t.access, "access")["revoked_at"] is not None


def test_revoke_other_clients_token_is_noop_200(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	r = box.http.post("/oauth/revoke", data={"token": t.refresh}, headers=basic_auth("roundcube", "roundcube-secret-456"))
	assert r.status_code == 200
	assert box.store.lookup_token(t.refresh, "refresh")["revoked_at"] is None


def test_revoke_unknown_token_200(box):
	r = box.http.post("/oauth/revoke", data={"token": "no-such-token"}, headers=basic_auth("roundcube", "roundcube-secret-456"))
	assert r.status_code == 200


def test_revoke_confidential_client_missing_secret_401(box):
	t = make_user_tokens(box)
	r = box.http.post("/oauth/revoke", data={"token": t.refresh, "client_id": "roundcube"})
	assert r.status_code == 401
	assert r.get_json()["error"] == "invalid_client"
	assert box.deps.failed_logins == ["/oauth/revoke"]
	assert box.store.lookup_token(t.refresh, "refresh")["revoked_at"] is None


def test_revoke_credentials_in_query_rejected(box):
	t = make_user_tokens(box)
	r = box.http.post("/oauth/revoke?client_id=roundcube&client_secret=roundcube-secret-456", data={"token": t.refresh})
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# Task 6: authorization_code + PKCE, refresh rotation
# ---------------------------------------------------------------------------

PANEL_REDIRECT = "https://box.example.com/admin"
RC_REDIRECT = "https://box.example.com/mail/index.php/login/oauth"


def make_code(box, challenge, client_id="panel", email="alice@box.example.com", scopes="admin profile", redirect_uri=PANEL_REDIRECT, method="S256"):
	raw_code = secrets.token_urlsafe(32)
	box.store.save_code(raw_code, client_id, email, scopes, redirect_uri, challenge, method, int(time.time()))
	return raw_code


def exchange(box, code, verifier, client_id="panel", redirect_uri=PANEL_REDIRECT, secret=None, scope=None):
	data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "client_id": client_id, "code_verifier": verifier}
	if secret is not None:
		data["client_secret"] = secret
	if scope is not None:
		data["scope"] = scope
	if verifier is None:
		del data["code_verifier"]
	return box.http.post("/oauth/token", data=data)


def refresh(box, refresh_token, client_id="panel", secret=None, scope=None):
	data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
	if secret is not None:
		data["client_secret"] = secret
	if scope is not None:
		data["scope"] = scope
	return box.http.post("/oauth/token", data=data)


def test_code_exchange_issues_linked_token_pair(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge)
	r = exchange(box, code, verifier)
	assert r.status_code == 200
	body = r.get_json()
	assert body["token_type"] == "Bearer"
	assert body["expires_in"] == oauth_server.ACCESS_TOKEN_TTL
	assert body["scope"] == "admin profile"
	access = box.store.lookup_token(body["access_token"], "access")
	refresh_row = box.store.lookup_token(body["refresh_token"], "refresh")
	origin = box.store.hash_token(code)
	for row in (access, refresh_row):
		assert row["user_email"] == "alice@box.example.com"
		assert row["client_id"] == "panel"
		assert row["auth_time"] == TEST_NOW
		assert row["origin_code_hash"] == origin
		assert row["password_state"]
	assert refresh_row["expires_at"] == min(TEST_NOW + oauth_server.REFRESH_TOKEN_TTL, TEST_NOW + oauth_server.CHAIN_LIFETIME_CAP)


def test_code_exchange_wrong_pkce_verifier_invalid_grant(box):
	_, challenge = pkce_pair()
	other_verifier, _ = pkce_pair()
	code = make_code(box, challenge)
	r = exchange(box, code, other_verifier)
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"
	assert "/oauth/token" in box.deps.failed_logins


def test_code_exchange_missing_pkce_verifier_rejected(box):
	_, challenge = pkce_pair()
	code = make_code(box, challenge)
	r = exchange(box, code, None)
	assert r.status_code == 400
	assert r.get_json()["error"] in ("invalid_request", "invalid_grant")


def test_code_exchange_wrong_redirect_uri_invalid_grant(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge)
	r = exchange(box, code, verifier, redirect_uri="https://box.example.com/other")
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"


def test_code_exchange_expired_code_invalid_grant(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge)
	box.clock["now"] = float(TEST_NOW + oauth_server.CODE_TTL + 1)
	r = exchange(box, code, verifier)
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"


def test_code_replay_revokes_issued_tokens(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge)
	first = exchange(box, code, verifier)
	assert first.status_code == 200
	body = first.get_json()
	replay = exchange(box, code, verifier)
	assert replay.status_code == 400
	assert replay.get_json()["error"] == "invalid_grant"
	# Replay revoked everything minted from that code — observable in the store.
	assert box.store.lookup_token(body["access_token"], "access")["revoked_at"] is not None
	assert box.store.lookup_token(body["refresh_token"], "refresh")["revoked_at"] is not None
	assert "/oauth/token" in box.deps.failed_logins


def test_code_exchange_non_s256_method_rejected(box):
	# PKCE downgrade guard: a stored code with code_challenge_method "plain" or
	# missing/None must never be accepted, even though Authlib's CodeChallenge
	# extension would otherwise default an absent method to "plain" and do a
	# trivial verifier == challenge compare. The verifier used here is the
	# genuine S256 verifier for the challenge, so this proves the method check
	# rejects on the stored method alone, before any PKCE compare runs.
	verifier, challenge = pkce_pair()
	plain_code = make_code(box, challenge, method="plain")
	r = exchange(box, plain_code, verifier)
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"
	assert "/oauth/token" in box.deps.failed_logins

	none_code = make_code(box, challenge, method=None)
	r2 = exchange(box, none_code, verifier)
	assert r2.status_code == 400
	assert r2.get_json()["error"] == "invalid_grant"


def test_code_for_other_client_invalid_grant(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge, client_id="roundcube", scopes="mail profile", redirect_uri=RC_REDIRECT)
	r = exchange(box, code, verifier)  # panel tries to redeem roundcube's code
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"


def test_confidential_roundcube_exchange_requires_secret(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge, client_id="roundcube", scopes="mail profile", redirect_uri=RC_REDIRECT)
	no_secret = exchange(box, code, verifier, client_id="roundcube", redirect_uri=RC_REDIRECT)
	assert no_secret.status_code in (400, 401)
	assert no_secret.get_json()["error"] == "invalid_client"
	code2 = make_code(box, challenge, client_id="roundcube", scopes="mail profile", redirect_uri=RC_REDIRECT)
	ok = exchange(box, code2, verifier, client_id="roundcube", redirect_uri=RC_REDIRECT, secret="roundcube-secret-456")
	assert ok.status_code == 200
	assert ok.get_json()["scope"] == "mail profile"


def test_code_exchange_scope_broadening_invalid_scope(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge, scopes="profile")
	r = exchange(box, code, verifier, scope="admin profile")
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_scope"


def test_refresh_rotation(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge)
	body = exchange(box, code, verifier).get_json()
	old_row = box.store.lookup_token(body["refresh_token"], "refresh")
	r = refresh(box, body["refresh_token"])
	assert r.status_code == 200
	new_body = r.get_json()
	assert new_body["refresh_token"] != body["refresh_token"]
	assert new_body["access_token"] != body["access_token"]
	# Old refresh token is now revoked; new one chains to it.
	assert box.store.lookup_token(body["refresh_token"], "refresh")["revoked_at"] is not None
	new_row = box.store.lookup_token(new_body["refresh_token"], "refresh")
	assert new_row["parent_id"] == old_row["id"]
	assert new_row["auth_time"] == old_row["auth_time"]
	assert new_row["origin_code_hash"] == old_row["origin_code_hash"]


def test_refresh_reuse_revokes_family(box):
	verifier, challenge = pkce_pair()
	code = make_code(box, challenge)
	gen1 = exchange(box, code, verifier).get_json()
	gen2 = refresh(box, gen1["refresh_token"]).get_json()
	box.deps.failed_logins.clear()
	reuse = refresh(box, gen1["refresh_token"])  # rotated-out token
	assert reuse.status_code == 400
	assert reuse.get_json()["error"] == "invalid_grant"
	assert box.deps.failed_logins == ["/oauth/token"]
	# The entire family is revoked, including the live gen2 pair.
	assert box.store.lookup_token(gen2["refresh_token"], "refresh")["revoked_at"] is not None
	assert box.store.lookup_token(gen2["access_token"], "access")["revoked_at"] is not None


def test_refresh_scope_subsetting(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile", origin="origin-sub-1")
	narrowed = refresh(box, t.refresh, scope="admin")
	assert narrowed.status_code == 200
	assert narrowed.get_json()["scope"] == "admin"
	t2 = make_user_tokens(box, client_id="panel", scopes="admin", origin="origin-sub-2")
	broadened = refresh(box, t2.refresh, scope="admin profile")
	assert broadened.status_code == 400
	assert broadened.get_json()["error"] == "invalid_scope"


def test_refresh_chain_cap_forces_reauth(box):
	# Token row itself unexpired (expires_at in the future), but the chain
	# anchor (auth_time) is too old: auth_time + CHAIN_LIFETIME_CAP <= now.
	ps = box.store.password_state(box.deps.get_mail_password("alice@box.example.com"), box.deps.get_mfa_state_json("alice@box.example.com"))
	raw, _ = box.store.create_token("refresh", "panel", "alice@box.example.com", "admin profile", TEST_NOW + 1000, auth_time=TEST_NOW - oauth_server.CHAIN_LIFETIME_CAP, origin_code_hash="origin-cap-1", password_state=ps)
	r = refresh(box, raw)
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"


def test_refresh_rotation_never_extends_past_chain_cap(box):
	auth_time = TEST_NOW - (oauth_server.CHAIN_LIFETIME_CAP - 5000)
	t = make_user_tokens(box, client_id="panel", scopes="admin profile", auth_time=auth_time, origin="origin-cap-2")
	r = refresh(box, t.refresh)
	assert r.status_code == 200
	new_row = box.store.lookup_token(r.get_json()["refresh_token"], "refresh")
	assert new_row["expires_at"] == auth_time + oauth_server.CHAIN_LIFETIME_CAP  # == TEST_NOW + 5000, not TEST_NOW + 30 days


def test_refresh_expired_token_invalid_grant(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	box.clock["now"] = float(TEST_NOW + oauth_server.REFRESH_TOKEN_TTL + 1)
	r = refresh(box, t.refresh)
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"


def test_refresh_password_change_invalid_grant(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	box.deps.users["alice@box.example.com"]["hash"] = "{SHA512-CRYPT}$6$salt$CHANGED"
	r = refresh(box, t.refresh)
	assert r.status_code == 400
	assert r.get_json()["error"] == "invalid_grant"


# ---------------------------------------------------------------------------
# Task 7: GET/POST /oauth/authorize + oauth-authorize.html
# ---------------------------------------------------------------------------

def authz_url(challenge, **overrides):
	q = {"response_type": "code", "client_id": "panel", "redirect_uri": PANEL_REDIRECT, "scope": "admin profile", "state": "st123", "code_challenge": challenge, "code_challenge_method": "S256"}
	q.update(overrides)
	return "/oauth/authorize?" + urllib.parse.urlencode({k: v for k, v in q.items() if v is not None})


def form_binding(html):
	binding = re.search(r'name="binding" value="([0-9a-f]{64})"', html).group(1)
	expires = re.search(r'name="binding_expires" value="(\d+)"', html).group(1)
	return binding, expires


def post_login(box, url, page_html, email="alice@box.example.com", password="swordfish", totp=None, binding=None):
	b, exp = form_binding(page_html)
	data = {"email": email, "password": password, "binding": binding if binding is not None else b, "binding_expires": exp}
	if totp is not None:
		data["totp_token"] = totp
	return box.http.post(url, data=data)


def test_authorize_get_renders_standalone_form(box):
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge))
	assert r.status_code == 200
	html = r.get_data(as_text=True)
	assert 'name="email"' in html
	assert 'name="password"' in html
	assert 'name="totp_token"' not in html  # hidden until needed
	assert re.search(r'name="binding" value="[0-9a-f]{64}"', html)
	assert "box.example.com" in html
	# Passkeys (Task 9) add a nonced inline <script> when the feature is enabled
	# (the default), so "no inline JS" no longer holds. CSP-proof by construction
	# now means every <script> is nonce-gated and there are no inline on*= handlers.
	for tag in re.findall(r"<script[^>]*>", html):
		assert "nonce=" in tag
	assert "onclick=" not in html and "onload=" not in html


def test_authorize_unknown_client_400_never_redirects(box):
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge, client_id="evil"))
	assert r.status_code == 400
	assert "Location" not in r.headers
	assert "client_id" in r.get_data(as_text=True)


def test_authorize_bad_redirect_uri_400_never_redirects(box):
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge, redirect_uri="https://evil.example.com/"))
	assert r.status_code == 400
	assert "Location" not in r.headers


def test_authorize_bad_response_type_redirects_error(box):
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge, response_type="token"))
	assert r.status_code == 302
	assert r.headers["Location"].startswith(PANEL_REDIRECT + "?")
	q = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["Location"]).query)
	assert q["error"] == ["unsupported_response_type"]
	assert q["state"] == ["st123"]


def test_authorize_scope_ceiling_per_client(box):
	# panel may never request 'mail'.
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge, scope="mail"))
	assert r.status_code == 302
	assert "error=invalid_scope" in r.headers["Location"]


def test_authorize_missing_code_challenge_rejected(box):
	r = box.http.get(authz_url(None, code_challenge=None))
	assert r.status_code == 302
	assert "error=invalid_request" in r.headers["Location"]


def test_authorize_plain_challenge_method_rejected(box):
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge, code_challenge_method="plain"))
	assert r.status_code == 302
	assert "error=invalid_request" in r.headers["Location"]


def test_authorize_post_success_full_flow(box):
	verifier, challenge = pkce_pair()
	url = authz_url(challenge)
	page = box.http.get(url).get_data(as_text=True)
	r = post_login(box, url, page)
	assert r.status_code == 302
	loc = urllib.parse.urlparse(r.headers["Location"])
	assert r.headers["Location"].startswith(PANEL_REDIRECT + "?")
	q = urllib.parse.parse_qs(loc.query)
	assert q["state"] == ["st123"]
	code = q["code"][0]
	# End-to-end: the issued code is exchangeable with PKCE (Task 6 grant).
	tok = exchange(box, code, verifier)
	assert tok.status_code == 200
	assert tok.get_json()["scope"] == "admin profile"


def test_authorize_post_wrong_password_rerenders_and_logs(box):
	_, challenge = pkce_pair()
	url = authz_url(challenge)
	page = box.http.get(url).get_data(as_text=True)
	r = post_login(box, url, page, password="nope")
	assert r.status_code == 200
	assert "Incorrect email address or password." in r.get_data(as_text=True)
	assert box.deps.failed_logins == ["/oauth/authorize"]


def test_authorize_totp_missing_rerenders_with_totp_field(box):
	box.deps.add_user("bob@box.example.com", password="hunter2", totp="424242")
	_, challenge = pkce_pair()
	url = authz_url(challenge)
	page = box.http.get(url).get_data(as_text=True)
	r = post_login(box, url, page, email="bob@box.example.com", password="hunter2")
	assert r.status_code == 200
	html = r.get_data(as_text=True)
	assert 'name="totp_token"' in html
	assert 'value="bob@box.example.com"' in html  # email preserved
	assert box.deps.failed_logins == []  # a missing TOTP step is not a failed login


def test_authorize_totp_invalid_rerenders_with_error_and_logs(box):
	box.deps.add_user("bob@box.example.com", password="hunter2", totp="424242")
	_, challenge = pkce_pair()
	url = authz_url(challenge)
	page = box.http.get(url).get_data(as_text=True)
	r = post_login(box, url, page, email="bob@box.example.com", password="hunter2", totp="000000")
	assert r.status_code == 200
	assert "Incorrect two factor authentication token." in r.get_data(as_text=True)
	assert 'name="totp_token"' in r.get_data(as_text=True)
	assert box.deps.failed_logins == ["/oauth/authorize"]


def test_authorize_totp_success_two_step(box):
	box.deps.add_user("bob@box.example.com", password="hunter2", totp="424242")
	_, challenge = pkce_pair()
	url = authz_url(challenge)
	page = box.http.get(url).get_data(as_text=True)
	step1 = post_login(box, url, page, email="bob@box.example.com", password="hunter2")
	# The re-rendered form carries a fresh binding; submit it with the code.
	step2 = post_login(box, url, step1.get_data(as_text=True), email="bob@box.example.com", password="hunter2", totp="424242")
	assert step2.status_code == 302
	assert "code=" in step2.headers["Location"]


def test_authorize_binding_tamper_rejected(box):
	_, challenge = pkce_pair()
	url = authz_url(challenge)
	page = box.http.get(url).get_data(as_text=True)
	b, _ = form_binding(page)
	tampered = ("0" if b[0] != "0" else "1") + b[1:]
	r = post_login(box, url, page, binding=tampered)
	assert r.status_code == 200
	assert "expired" in r.get_data(as_text=True)
	assert "code=" not in (r.headers.get("Location") or "")


def test_authorize_binding_bound_to_exact_params(box):
	# A binding minted for scope "admin profile" must not authorize a POST
	# whose query string says scope "profile" (even though that alone would validate).
	_, challenge = pkce_pair()
	page = box.http.get(authz_url(challenge)).get_data(as_text=True)
	r = post_login(box, authz_url(challenge, scope="profile"), page)
	assert r.status_code == 200
	assert "expired" in r.get_data(as_text=True)


def test_authorize_binding_expiry(box):
	_, challenge = pkce_pair()
	url = authz_url(challenge)
	page = box.http.get(url).get_data(as_text=True)
	box.clock["now"] = float(TEST_NOW + oauth_server.AUTHZ_FORM_TTL + 1)
	r = post_login(box, url, page)
	assert r.status_code == 200
	assert "expired" in r.get_data(as_text=True)


def test_authorize_binding_canonicalization_unambiguous(box):
	# state and code_challenge are arbitrary, client-controlled strings. Before
	# the per-field-hash fix, the binding message was built by naively joining
	# raw fields with "|", so state="a|b", code_challenge="c" and state="a",
	# code_challenge="b|c" concatenated identically and hashed to the same
	# binding. Both GETs below happen at the same frozen clock tick (the
	# `clock` fixture freezes time.time), so binding_expires is identical too
	# -- the only difference is where the "|" falls -- and the bindings must
	# still differ.
	url_a = authz_url("c", state="a|b", code_challenge="c")
	url_b = authz_url("c", state="a", code_challenge="b|c")
	page_a = box.http.get(url_a).get_data(as_text=True)
	page_b = box.http.get(url_b).get_data(as_text=True)
	binding_a, expires_a = form_binding(page_a)
	binding_b, expires_b = form_binding(page_b)
	assert expires_a == expires_b  # sanity check: same binding_expires
	assert binding_a != binding_b


# ---------------------------------------------------------------------------
# Task 8: /oauth/userinfo, RFC 8414 metadata, validate_bearer
# ---------------------------------------------------------------------------

def test_userinfo_requires_profile_scope(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	r = box.http.get("/oauth/userinfo", headers={"Authorization": "Bearer " + t.access})
	assert r.status_code == 200
	assert r.get_json() == {"sub": "alice@box.example.com", "email": "alice@box.example.com", "privileges": ["admin"]}
	t2 = make_user_tokens(box, client_id="panel", scopes="admin", origin="origin-ui-2")
	r2 = box.http.get("/oauth/userinfo", headers={"Authorization": "Bearer " + t2.access})
	assert r2.status_code == 401


def test_userinfo_no_bearer_header_401(box):
	r = box.http.get("/oauth/userinfo")
	assert r.status_code == 401
	assert r.headers["WWW-Authenticate"].startswith("Bearer")


def test_userinfo_bad_token_401(box):
	r = box.http.get("/oauth/userinfo", headers={"Authorization": "Bearer nonsense"})
	assert r.status_code == 401
	assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]


def test_userinfo_client_credentials_token_401(box):
	# A user-less token can never pass userinfo, even if it somehow had the scope.
	raw, _ = box.store.create_token("access", "system", None, "profile", int(time.time()) + 600)
	r = box.http.get("/oauth/userinfo", headers={"Authorization": "Bearer " + raw})
	assert r.status_code == 401


def test_metadata_document(box):
	r = box.http.get("/.well-known/oauth-authorization-server")
	assert r.status_code == 200
	assert r.get_json() == {
		"issuer": "https://box.example.com",
		"authorization_endpoint": "https://box.example.com/admin/oauth/authorize",
		"token_endpoint": "https://box.example.com/admin/oauth/token",
		"revocation_endpoint": "https://box.example.com/admin/oauth/revoke",
		"userinfo_endpoint": "https://box.example.com/admin/oauth/userinfo",
		"scopes_supported": ["mail", "admin", "profile"],
		"response_types_supported": ["code"],
		"grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
		"code_challenge_methods_supported": ["S256"],
		"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
	}


def test_client_credentials_over_plain_loopback_http(box):
	# Regression for the whole-branch-review critical finding: the local root
	# tooling (cli.py, tools/dns_update, tools/web_update) POSTs client_credentials
	# directly to http://127.0.0.1:10222/oauth/token — plain http, bypassing nginx,
	# with no X-Forwarded-Proto. daemon.py's apply_forwarded_proto treats such a
	# no-proxy-header loopback request as secure so Authlib does not reject it with
	# insecure_transport (which would abort setup/start.sh). This test reproduces
	# that hook on the test app and drives the grant over a plain-http base_url.
	@box.app.before_request
	def _loopback_is_secure():
		if "X-Forwarded-Proto" not in request.headers and "X-Forwarded-For" not in request.headers:
			request.environ["wsgi.url_scheme"] = "https"

	plain = box.app.test_client()  # default http base_url, no HttpsTestClient
	r = plain.post("http://127.0.0.1/oauth/token", data={"grant_type": "client_credentials", "scope": "admin"}, headers=basic_auth("system", "system-secret-789"))
	assert r.status_code == 200, r.get_data(as_text=True)
	assert r.get_json()["access_token"]


def test_validate_bearer_returns_info(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	info = oauth_server.validate_bearer(box.env, t.access, "admin", box.deps)
	assert info == {"user_email": "alice@box.example.com", "scopes": {"admin", "profile"}, "client_id": "panel"}


def test_validate_bearer_rejects_expired(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	box.clock["now"] = float(TEST_NOW + oauth_server.ACCESS_TOKEN_TTL + 1)
	assert oauth_server.validate_bearer(box.env, t.access, "admin", box.deps) is None


def test_validate_bearer_rejects_revoked(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	box.store.revoke_token(t.access_id)
	assert oauth_server.validate_bearer(box.env, t.access, "admin", box.deps) is None


def test_validate_bearer_rejects_missing_scope(box):
	t = make_user_tokens(box, client_id="roundcube", scopes="mail profile")
	assert oauth_server.validate_bearer(box.env, t.access, "admin", box.deps) is None


def test_validate_bearer_rejects_password_change(box):
	t = make_user_tokens(box, client_id="panel", scopes="admin profile")
	box.deps.users["alice@box.example.com"]["mfa"] = json.dumps([{"id": 9, "type": "totp"}])  # MFA-state change also invalidates
	assert oauth_server.validate_bearer(box.env, t.access, "admin", box.deps) is None


def test_validate_bearer_client_credentials_token(box):
	raw, _ = box.store.create_token("access", "system", None, "admin", int(time.time()) + 600)
	info = oauth_server.validate_bearer(box.env, raw, "admin", box.deps)
	assert info == {"user_email": None, "scopes": {"admin"}, "client_id": "system"}


# ---------------------------------------------------------------------------
# Passkeys Task 1: authorize helpers extracted to module scope
# ---------------------------------------------------------------------------

def test_build_code_redirect_appends_code_and_state():
	# Extracted from the inline authorize success path so the passkey sign-in
	# ceremony (Task 6) can return the same URL in a JSON body. It returns a URL
	# string, not a Flask response.
	p = {"redirect_uri": PANEL_REDIRECT, "state": "st123"}
	assert oauth_server.build_code_redirect(p, "the-code") == PANEL_REDIRECT + "?code=the-code&state=st123"
	p2 = {"redirect_uri": PANEL_REDIRECT + "?x=1", "state": ""}
	assert oauth_server.build_code_redirect(p2, "c2") == PANEL_REDIRECT + "?x=1&code=c2"


def test_validate_authorize_request_is_module_scope(box):
	# The passkey module (Task 6) imports this from module scope; it was a closure
	# inside init_oauth, unreachable from another module. A valid authorize request
	# returns None (acceptable); the extracted logic is otherwise identical.
	assert callable(oauth_server.validate_authorize_request)
	_, challenge = pkce_pair()
	p = {"client_id": "panel", "redirect_uri": PANEL_REDIRECT, "response_type": "code", "scope": "admin profile", "state": "st123", "code_challenge": challenge, "code_challenge_method": "S256"}
	assert oauth_server.validate_authorize_request(p, box.env) is None


def test_validate_authorize_request_fatal_for_unknown_client(box):
	# An unknown client_id still yields the 400 HTML fatal page (never a redirect).
	p = {"client_id": "evil", "redirect_uri": PANEL_REDIRECT, "response_type": "code", "scope": "admin profile", "state": "", "code_challenge": "x", "code_challenge_method": "S256"}
	with box.app.test_request_context():
		html, status = oauth_server.validate_authorize_request(p, box.env)
	assert status == 400
	assert "client_id" in html


# ---------------------------------------------------------------------------
# Task 9: authorize passkey button + sign-in ceremony script; daemon wiring
# ---------------------------------------------------------------------------

def test_authorize_get_shows_passkey_button_when_enabled(box, monkeypatch):
	import webauthn_auth  # noqa: PLC0415
	monkeypatch.setattr(webauthn_auth, "is_passkeys_enabled", lambda env: True)
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge))
	assert r.status_code == 200
	html = r.get_data(as_text=True)
	assert "Sign in with a passkey" in html
	assert 'id="passkeyButton"' in html
	# The ceremony script is the FIRST (and only) inline script and is nonce-gated.
	scripts = re.findall(r"<script[^>]*>", html)
	assert scripts and all("nonce=" in tag for tag in scripts)
	assert "/auth/webauthn/authenticate/begin" in html
	assert "/auth/webauthn/authenticate/finish" in html
	assert "navigator.credentials.get" in html
	assert "window.location" in html  # assigns the JSON redirect (no HTTP 302)


def test_authorize_get_hides_passkey_button_when_disabled(box, monkeypatch):
	import webauthn_auth  # noqa: PLC0415
	monkeypatch.setattr(webauthn_auth, "is_passkeys_enabled", lambda env: False)
	_, challenge = pkce_pair()
	r = box.http.get(authz_url(challenge))
	assert r.status_code == 200
	html = r.get_data(as_text=True)
	assert "Sign in with a passkey" not in html
	assert "passkeyButton" not in html
	assert "/auth/webauthn/authenticate/begin" not in html
	assert "<script" not in html  # feature off -> zero inline JS


def test_daemon_wires_init_webauthn_after_init_oauth():
	path = os.path.join(os.path.dirname(__file__), "..", "management", "daemon.py")
	with open(path, encoding="utf-8") as f:  # noqa: FURB101 -- os.path/open mirrors this file's existing style
		src = f.read()
	assert re.search(r"^import\b.*\bwebauthn_auth\b", src, re.MULTILINE)
	m_oauth = re.search(r"oauth_server\.init_oauth\(app, env, (\w+)\)", src)
	m_wa = re.search(r"webauthn_auth\.init_webauthn\(app, env, (\w+)\)", src)
	assert m_oauth is not None, "expected oauth_server.init_oauth(app, env, <deps>)"
	assert m_wa is not None, "expected webauthn_auth.init_webauthn(app, env, <deps>)"
	assert m_oauth.group(1) == m_wa.group(1), "init_webauthn must reuse the SAME deps object"
	assert m_oauth.end() <= m_wa.start(), "init_webauthn must be wired after init_oauth"
