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
# `re` and `urllib.parse` are unused by the Task 4 tests below; they are
# imported here because Tasks 5-8 append authorization_code/PKCE/refresh
# tests to this same file that need them.
#
# ruff: noqa: ARG001, ARG005, EM101, F401, PLR6201, S101, S105, S106, S107, TRY003

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
from flask import Flask

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "management"))

import oauth_clients
import oauth_server

TEST_NOW = 1_700_000_000


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
	oauth_server.init_oauth(app, env, deps)

	return SimpleNamespace(http=app.test_client(), env=env, deps=deps, store=oauth_server.current_store(env), clock=clock, clients=clients)


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
