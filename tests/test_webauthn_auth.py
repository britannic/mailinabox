#!/usr/bin/env python3
# Local unit tests for management/webauthn_auth.py and the scripted software
# authenticator in tests/webauthn_softauth.py. No live Mail-in-a-Box is needed:
# the OAuth store lives in a pytest tmp_path, settings.yaml is written into it,
# and every WebAuthn ceremony is driven by the cryptography-scripted authenticator.
#
#   python3 -m pytest tests/test_webauthn_auth.py -v
#
# Run under Python 3.10-3.12 to match the box (webauthn==1.8.0 needs pydantic<2).
#
# ruff: noqa: S101, SLF001, ARG005, S107

import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import sys
import time
import urllib.parse
from types import SimpleNamespace

import pytest
from flask import Flask
from flask.testing import FlaskClient

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "management"))

import oauth_clients
import oauth_server
import webauthn_auth
from oauth_store import OAuthStore, db_path

import webauthn
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import AuthenticationCredential, RegistrationCredential

from webauthn_softauth import SoftwareAuthenticator

HOST = "box.example.com"
ORIGIN = "https://box.example.com"
EMAIL = "alice@box.example.com"


def _b64url_decode(v):
	# base64url string (no padding, as py_webauthn emits) -> raw bytes.
	return base64.urlsafe_b64decode(v + "===")


@pytest.fixture
def env(tmp_path):
	e = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": HOST}
	(tmp_path / "auth").mkdir(mode=0o700)
	return e


@pytest.fixture
def store(env):
	return OAuthStore(db_path(env))


def _write_settings(env, text):
	pathlib.Path(env["STORAGE_ROOT"], "settings.yaml").write_text(text, encoding="utf-8")


def test_is_passkeys_enabled_default_true_when_no_settings(env):
	assert webauthn_auth.is_passkeys_enabled(env) is True


def test_is_passkeys_enabled_reads_flag_false(env):
	_write_settings(env, "auth:\n  passkeys: false\n")
	assert webauthn_auth.is_passkeys_enabled(env) is False


def test_is_passkeys_enabled_reads_flag_true(env):
	_write_settings(env, "auth:\n  passkeys: true\n")
	assert webauthn_auth.is_passkeys_enabled(env) is True


def test_is_passkeys_enabled_fail_open_on_unparseable(env):
	_write_settings(env, "this is not a mapping\n")
	assert webauthn_auth.is_passkeys_enabled(env) is True


def test_user_handle_is_deterministic_and_32_bytes(env, store):
	h1 = webauthn_auth.user_handle(env, EMAIL, store)
	h2 = webauthn_auth.user_handle(env, EMAIL, store)
	assert isinstance(h1, bytes)
	assert len(h1) == 32
	assert h1 == h2


def test_user_handle_differs_per_user(env, store):
	assert webauthn_auth.user_handle(env, "alice@box.example.com", store) != webauthn_auth.user_handle(env, "bob@box.example.com", store)


def test_user_handle_matches_hmac_of_server_secret(env, store):
	expected = hmac.new(store.get_server_secret(), EMAIL.encode("utf-8"), hashlib.sha256).digest()
	assert webauthn_auth.user_handle(env, EMAIL, store) == expected


def test_registration_options_shape(env, store):
	options_json, raw_challenge = webauthn_auth._registration_options(env, store, EMAIL)
	opts = json.loads(options_json)
	assert opts["rp"]["id"] == HOST
	# user.id must be the raw 32-byte handle (NOT the UTF-8 of the email that
	# py_webauthn 1.8.0's generate_registration_options would otherwise encode).
	assert _b64url_decode(opts["user"]["id"]) == webauthn_auth.user_handle(env, EMAIL, store)
	assert len(_b64url_decode(opts["user"]["id"])) == 32
	assert opts["user"]["name"] == EMAIL
	algs = {p["alg"] for p in opts["pubKeyCredParams"]}
	assert -7 in algs and -257 in algs  # ES256 + RS256
	assert opts["authenticatorSelection"]["residentKey"] == "required"
	assert opts["authenticatorSelection"]["userVerification"] == "required"
	assert opts["attestation"] == "none"
	assert opts["excludeCredentials"] == []
	assert _b64url_decode(opts["challenge"]) == _b64url_decode(raw_challenge)


def test_registration_options_excludes_existing_credentials(env, store):
	cred_id = b"\x11" * 20
	store.add_webauthn_credential(EMAIL, cred_id, b"cose-key", 0, json.dumps(["internal"]), "aaguid-x", "Passkey")
	options_json, _ = webauthn_auth._registration_options(env, store, EMAIL)
	opts = json.loads(options_json)
	excluded = {_b64url_decode(c["id"]) for c in opts["excludeCredentials"]}
	assert cred_id in excluded


def test_authentication_options_shape(env, store):
	options_json, raw_challenge = webauthn_auth._authentication_options(env, store)
	opts = json.loads(options_json)
	assert opts["rpId"] == HOST
	assert opts["userVerification"] == "required"
	assert opts["allowCredentials"] == []
	assert _b64url_decode(opts["challenge"]) == _b64url_decode(raw_challenge)


def _enroll(env, store):
	# Run a registration ceremony and return (authenticator, VerifiedRegistration).
	auth = SoftwareAuthenticator(rp_id=HOST, origin=ORIGIN)
	_, challenge = webauthn_auth._registration_options(env, store, EMAIL)
	reg = webauthn.verify_registration_response(
		credential=RegistrationCredential.parse_raw(json.dumps(auth.create(challenge))),
		expected_challenge=_b64url_decode(challenge),
		expected_rp_id=HOST,
		expected_origin=ORIGIN,
		require_user_verification=True,
	)
	return auth, reg


def test_softauth_registration_roundtrip(env, store):
	auth, reg = _enroll(env, store)
	assert reg.credential_id == auth.credential_id
	assert reg.user_verified is True
	assert reg.sign_count == 0


def test_softauth_registration_uv_absent_rejected(env, store):
	auth = SoftwareAuthenticator(rp_id=HOST, origin=ORIGIN)
	_, challenge = webauthn_auth._registration_options(env, store, EMAIL)
	with pytest.raises(InvalidRegistrationResponse):
		webauthn.verify_registration_response(
			credential=RegistrationCredential.parse_raw(json.dumps(auth.create(challenge, uv=False))),
			expected_challenge=_b64url_decode(challenge),
			expected_rp_id=HOST,
			expected_origin=ORIGIN,
			require_user_verification=True,
		)


def test_softauth_authentication_roundtrip(env, store):
	auth, reg = _enroll(env, store)
	_, challenge = webauthn_auth._authentication_options(env, store)
	verified = webauthn.verify_authentication_response(
		credential=AuthenticationCredential.parse_raw(json.dumps(auth.get(challenge))),
		expected_challenge=_b64url_decode(challenge),
		expected_rp_id=HOST,
		expected_origin=ORIGIN,
		credential_public_key=reg.credential_public_key,
		credential_current_sign_count=reg.sign_count,
		require_user_verification=True,
	)
	assert verified.credential_id == auth.credential_id
	assert verified.new_sign_count == 1


def test_softauth_authentication_wrong_origin_rejected(env, store):
	auth, reg = _enroll(env, store)
	_, challenge = webauthn_auth._authentication_options(env, store)
	assertion = auth.get(challenge, origin="https://evil.example.com")
	with pytest.raises(InvalidAuthenticationResponse):
		webauthn.verify_authentication_response(
			credential=AuthenticationCredential.parse_raw(json.dumps(assertion)),
			expected_challenge=_b64url_decode(challenge),
			expected_rp_id=HOST,
			expected_origin=ORIGIN,
			credential_public_key=reg.credential_public_key,
			credential_current_sign_count=reg.sign_count,
			require_user_verification=True,
		)


def test_softauth_authentication_counter_regression_rejected(env, store):
	auth, reg = _enroll(env, store)
	_, challenge = webauthn_auth._authentication_options(env, store)
	assertion = auth.get(challenge, sign_count=5)  # equals current -> not greater -> reject
	with pytest.raises(InvalidAuthenticationResponse):
		webauthn.verify_authentication_response(
			credential=AuthenticationCredential.parse_raw(json.dumps(assertion)),
			expected_challenge=_b64url_decode(challenge),
			expected_rp_id=HOST,
			expected_origin=ORIGIN,
			credential_public_key=reg.credential_public_key,
			credential_current_sign_count=5,
			require_user_verification=True,
		)


def test_softauth_authentication_uv_absent_rejected(env, store):
	auth, reg = _enroll(env, store)
	_, challenge = webauthn_auth._authentication_options(env, store)
	assertion = auth.get(challenge, uv=False)
	with pytest.raises(InvalidAuthenticationResponse):
		webauthn.verify_authentication_response(
			credential=AuthenticationCredential.parse_raw(json.dumps(assertion)),
			expected_challenge=_b64url_decode(challenge),
			expected_rp_id=HOST,
			expected_origin=ORIGIN,
			credential_public_key=reg.credential_public_key,
			credential_current_sign_count=reg.sign_count,
			require_user_verification=True,
		)


def _make_app(env):
	app = Flask("webauthn-test")
	app.testing = True
	webauthn_auth.init_webauthn(app, env, deps=None)
	return app


def test_init_webauthn_registers_six_endpoints(env):
	app = _make_app(env)
	rules = {(r.rule, m) for r in app.url_map.iter_rules() for m in (r.methods - {"HEAD", "OPTIONS"})}
	assert ("/auth/webauthn/register/begin", "POST") in rules
	assert ("/auth/webauthn/register/finish", "POST") in rules
	assert ("/auth/webauthn/authenticate/begin", "POST") in rules
	assert ("/auth/webauthn/authenticate/finish", "POST") in rules
	assert ("/auth/webauthn/credentials", "GET") in rules
	assert ("/auth/webauthn/credentials/<int:cred_id>", "PATCH") in rules
	assert ("/auth/webauthn/credentials/<int:cred_id>", "DELETE") in rules


def test_endpoints_404_when_flag_disabled(env):
	_write_settings(env, "auth:\n  passkeys: false\n")
	client = _make_app(env).test_client()
	assert client.post("/auth/webauthn/register/begin").status_code == 404
	assert client.post("/auth/webauthn/register/finish").status_code == 404
	assert client.post("/auth/webauthn/authenticate/begin").status_code == 404
	assert client.post("/auth/webauthn/authenticate/finish").status_code == 404
	assert client.get("/auth/webauthn/credentials").status_code == 404
	assert client.patch("/auth/webauthn/credentials/1").status_code == 404
	assert client.delete("/auth/webauthn/credentials/1").status_code == 404


def test_endpoint_reachable_when_flag_enabled(env):
	# All six routes are now real (T5-T7); with no bearer at all this hits the
	# 401 branch rather than the flag-off 404 branch, which is what this test
	# actually needs to distinguish: "flag-enabled route is reachable, not
	# 404'd" (the no-settings.yaml default is enabled).
	client = _make_app(env).test_client()
	assert client.get("/auth/webauthn/credentials").status_code == 401


# ---------------------------------------------------------------------------
# Task 5: registration ceremony (register/begin + register/finish)
#
# T4's own scaffolding stopped at the flag-gated 501 stubs above and did not
# add a full wired-app fixture; the "wbox" fixture, FakeDeps, and HttpsTestClient
# below are added here (T5) mirroring tests/test_oauth_server.py's `box`
# fixture/FakeDeps exactly (duplicated rather than imported so this file has no
# import-time coupling to test_oauth_server.py), so that Bearer-authenticated
# ceremony tests have a real init_oauth + init_webauthn app to drive end to end.
# T6/T7 reuse this fixture for the sign-in and credential-management routes.
# ---------------------------------------------------------------------------


class HttpsTestClient(FlaskClient):
	# oauth_server's Authlib integration enforces a real HTTPS scheme
	# (InsecureTransportError); drive every request in this file over https,
	# same as nginx would present it on-box. Mirrors test_oauth_server.py.
	def open(self, *args, **kwargs):
		kwargs.setdefault("base_url", "https://" + HOST)
		return super().open(*args, **kwargs)


class FakeDeps:
	# Mirrors tests/test_oauth_server.py's FakeDeps (the deps object daemon.py
	# constructs) -- duplicated rather than imported for zero cross-file coupling.
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


@pytest.fixture
def clock(monkeypatch):
	state = {"now": 1_700_000_000.0}
	monkeypatch.setattr(time, "time", lambda: state["now"])
	return state


@pytest.fixture
def wbox(env, clock, monkeypatch):
	# A fully-wired app (init_oauth + init_webauthn), for Bearer-authenticated
	# WebAuthn ceremony tests. The client registry (panel/roundcube/system) is
	# stubbed the same way test_oauth_server.py's `box` fixture does it, so a
	# later task's sign-in ceremony (which calls validate_authorize_request,
	# needing oauth_clients.get_client) can reuse this same fixture unchanged.
	auth_dir = pathlib.Path(env["STORAGE_ROOT"], "auth")
	(auth_dir / "roundcube_client_secret.txt").write_text("roundcube-secret-456\n", encoding="utf-8")
	(auth_dir / "system.key").write_text("system-secret-789\n", encoding="utf-8")
	clients = {
		"panel": SimpleNamespace(client_id="panel", is_public=True, grant_types=frozenset({"authorization_code", "refresh_token"}), allowed_scopes=frozenset({"admin", "profile"}), redirect_uris=("https://" + HOST + "/admin",), secret_path=None),
		"roundcube": SimpleNamespace(client_id="roundcube", is_public=False, grant_types=frozenset({"authorization_code", "refresh_token"}), allowed_scopes=frozenset({"mail", "profile"}), redirect_uris=("https://" + HOST + "/mail/index.php/login/oauth",), secret_path=str(auth_dir / "roundcube_client_secret.txt")),
		"system": SimpleNamespace(client_id="system", is_public=False, grant_types=frozenset({"client_credentials"}), allowed_scopes=frozenset({"admin"}), redirect_uris=(), secret_path=str(auth_dir / "system.key")),
	}
	monkeypatch.setattr(oauth_clients, "get_client", lambda env_, client_id: clients.get(client_id))

	deps = FakeDeps()
	deps.add_user(EMAIL)

	app = Flask("webauthn-full-test", template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "management", "templates"))
	app.testing = True
	app.test_client_class = HttpsTestClient
	oauth_server.init_oauth(app, env, deps)
	webauthn_auth.init_webauthn(app, env, deps)

	return SimpleNamespace(http=app.test_client(), app=app, env=env, deps=deps, store=oauth_server.current_store(env), clock=clock)


def _register_attestation(options_json, *, user_verified=True, origin=None):
	# Adapts tests/webauthn_softauth.py's SoftwareAuthenticator to a
	# register(options_json, ...) convenience shape: T4's actual authenticator
	# takes a bare challenge string plus uv/origin kwargs on .create() (there is
	# no .register() method), so pull the challenge out of the begin route's
	# options JSON and drive the authenticator against it directly. No edits to
	# webauthn_softauth.py -- this only adapts call shape, not behavior.
	challenge = json.loads(options_json)["challenge"]
	authenticator = SoftwareAuthenticator(rp_id=HOST, origin=ORIGIN)
	return authenticator.create(challenge, uv=user_verified, origin=origin)


def _admin_headers(wbox, email):
	# Mint a scope-'admin' access token the way the code-exchange grant does,
	# carrying the current password/MFA fingerprint so validate_bearer accepts it.
	ps = wbox.store.password_state(wbox.deps.get_mail_password(email), wbox.deps.get_mfa_state_json(email))
	raw, _ = wbox.store.create_token("access", "panel", email, "admin profile", int(time.time()) + 3600, auth_time=int(time.time()), origin_code_hash="wa-origin", password_state=ps)
	return {"Authorization": "Bearer " + raw}


def test_register_begin_returns_options_and_stores_challenge(wbox):
	r = wbox.http.post("/auth/webauthn/register/begin", headers=_admin_headers(wbox, "alice@box.example.com"))
	assert r.status_code == 200
	options = r.get_json()
	assert options["rp"]["id"] == "box.example.com"
	assert options["user"]["name"] == "alice@box.example.com"
	assert "challenge" in options
	# The challenge row is stored bound to the caller, typed 'registration'.
	row = wbox.store.take_webauthn_challenge(options["challenge"], "registration")
	assert row is not None
	assert row["user_email"] == "alice@box.example.com"


def test_register_begin_without_bearer_401(wbox):
	assert wbox.http.post("/auth/webauthn/register/begin").status_code == 401


def test_register_finish_happy_path_creates_credential(wbox):
	headers = _admin_headers(wbox, "alice@box.example.com")
	options_json = wbox.http.post("/auth/webauthn/register/begin", headers=headers).get_data(as_text=True)
	attestation = _register_attestation(options_json)
	r = wbox.http.post("/auth/webauthn/register/finish", json=attestation, headers=headers)
	assert r.status_code == 200, r.get_data(as_text=True)
	created = r.get_json()
	assert created["name"] == "Passkey"
	assert created["last_used_at"] is None
	creds = wbox.store.get_webauthn_credentials("alice@box.example.com")
	assert len(creds) == 1
	assert creds[0]["id"] == created["id"]


def test_register_finish_rejects_uv_absent(wbox):
	headers = _admin_headers(wbox, "alice@box.example.com")
	options_json = wbox.http.post("/auth/webauthn/register/begin", headers=headers).get_data(as_text=True)
	attestation = _register_attestation(options_json, user_verified=False)
	r = wbox.http.post("/auth/webauthn/register/finish", json=attestation, headers=headers)
	assert r.status_code == 400
	assert r.get_json()["error"] == "Could not verify passkey."
	assert wbox.store.get_webauthn_credentials("alice@box.example.com") == []


def test_register_finish_rejects_wrong_origin(wbox):
	headers = _admin_headers(wbox, "alice@box.example.com")
	options_json = wbox.http.post("/auth/webauthn/register/begin", headers=headers).get_data(as_text=True)
	attestation = _register_attestation(options_json, origin="https://evil.example.com")
	r = wbox.http.post("/auth/webauthn/register/finish", json=attestation, headers=headers)
	assert r.status_code == 400
	assert wbox.store.get_webauthn_credentials("alice@box.example.com") == []


def test_register_finish_rejects_challenge_user_mismatch(wbox):
	wbox.deps.add_user("bob@box.example.com")
	alice = _admin_headers(wbox, "alice@box.example.com")
	bob = _admin_headers(wbox, "bob@box.example.com")
	# Alice begins (challenge bound to alice); Bob tries to finish it.
	options_json = wbox.http.post("/auth/webauthn/register/begin", headers=alice).get_data(as_text=True)
	attestation = _register_attestation(options_json)
	r = wbox.http.post("/auth/webauthn/register/finish", json=attestation, headers=bob)
	assert r.status_code == 400
	assert r.get_json()["error"] == "Could not verify passkey."
	# No credential is bound to EITHER identity.
	assert wbox.store.get_webauthn_credentials("bob@box.example.com") == []
	assert wbox.store.get_webauthn_credentials("alice@box.example.com") == []


def test_register_endpoints_404_when_flag_off(wbox, monkeypatch):
	monkeypatch.setattr(webauthn_auth, "is_passkeys_enabled", lambda env: False)
	headers = _admin_headers(wbox, "alice@box.example.com")
	assert wbox.http.post("/auth/webauthn/register/begin", headers=headers).status_code == 404
	assert wbox.http.post("/auth/webauthn/register/finish", json={}, headers=headers).status_code == 404


# ---------------------------------------------------------------------------
# Task 6: sign-in ceremony (authenticate/begin + authenticate/finish)
#
# Unauthenticated, usernameless passkey sign-in wired into the OAuth
# authorize flow. Reuses the `wbox` fixture (T5) -- the brief's restated
# fixture is named `box`, but T5 actually landed it as `wbox`; kept as-is
# here for a single definition and zero churn on the passing T5 suite above.
# `soft` is a fresh SoftwareAuthenticator (tests/webauthn_softauth.py, T4)
# bound to wbox's HOST/ORIGIN -- its constructor takes rp_id/origin (not the
# brief's restated zero-arg form), and it exposes .create()/.get() (dict
# returning) rather than a single .authenticate() helper, so `sign_in()`
# below adapts call shape only, exactly like T5's `_register_attestation`.
# ---------------------------------------------------------------------------

PANEL_REDIRECT = "https://" + HOST + "/admin"


@pytest.fixture
def soft():
	return SoftwareAuthenticator(rp_id=HOST, origin=ORIGIN)


def pkce_pair():
	verifier = secrets.token_urlsafe(32)
	challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
	return verifier, challenge


def authorize_query(pkce_challenge, **overrides):
	q = {"response_type": "code", "client_id": "panel", "redirect_uri": PANEL_REDIRECT, "scope": "admin profile", "state": "st123", "code_challenge": pkce_challenge, "code_challenge_method": "S256"}
	q.update(overrides)
	return urllib.parse.urlencode({k: v for k, v in q.items() if v is not None})


def enroll(wbox, soft, email=EMAIL, sign_count=0, name="Test key"):
	wbox.store.add_webauthn_credential(email, soft.credential_id, soft.cose_public_key(), sign_count, json.dumps(["internal"]), soft.aaguid.hex(), name)


def sign_in(wbox, soft, pkce_challenge, *, origin=ORIGIN, user_verified=True, sign_count=1, **authz_overrides):
	challenge = wbox.http.post("/auth/webauthn/authenticate/begin").get_json()["challenge"]
	assertion = json.dumps(soft.get(challenge, uv=user_verified, origin=origin, sign_count=sign_count))
	url = "/auth/webauthn/authenticate/finish?" + authorize_query(pkce_challenge, **authz_overrides)
	return wbox.http.post(url, data=assertion, content_type="application/json")


def test_authenticate_begin_stores_challenge_and_returns_options(wbox):
	r = wbox.http.post("/auth/webauthn/authenticate/begin")
	assert r.status_code == 200
	opts = r.get_json()
	assert opts["rpId"] == HOST
	assert opts["userVerification"] == "required"
	assert opts["allowCredentials"] == []
	# The row was stored as an authentication challenge with no bound user, and
	# it is single-use (this take consumes it).
	row = wbox.store.take_webauthn_challenge(opts["challenge"], "authentication")
	assert row is not None
	assert row["user_email"] is None


def test_authenticate_finish_issues_valid_code(wbox, soft):
	enroll(wbox, soft)
	_, challenge = pkce_pair()
	r = sign_in(wbox, soft, challenge)
	assert r.status_code == 200
	target = r.get_json()["redirect"]
	assert target.startswith(PANEL_REDIRECT + "?")
	q = urllib.parse.parse_qs(urllib.parse.urlparse(target).query)
	assert q["state"] == ["st123"]
	# Identity is resolved from the credential row (alice), and the code is
	# bound to exactly the query-string OAuth request.
	row = wbox.store.take_code(q["code"][0])
	assert row["user_email"] == EMAIL
	assert row["client_id"] == "panel"
	assert row["scopes"] == "admin profile"
	assert row["redirect_uri"] == PANEL_REDIRECT
	assert row["code_challenge"] == challenge
	assert row["code_challenge_method"] == "S256"
	assert wbox.deps.failed_logins == []


def test_authenticate_endpoints_404_when_flag_disabled(wbox, soft):
	_write_settings(wbox.env, "auth:\n  passkeys: false\n")
	assert wbox.http.post("/auth/webauthn/authenticate/begin").status_code == 404
	enroll(wbox, soft)
	r = wbox.http.post("/auth/webauthn/authenticate/finish", data="{}", content_type="application/json")
	assert r.status_code == 404


def test_authenticate_finish_bad_redirect_uri_fatal_no_code(wbox, soft):
	enroll(wbox, soft)
	_, challenge = pkce_pair()
	r = sign_in(wbox, soft, challenge, redirect_uri="https://evil.example.com/")
	# validate_authorize_request returns the 400 HTML fatal page (never a
	# redirect, never a code) for an unregistered redirect_uri.
	assert r.status_code == 400
	assert "invalid redirect URI" in r.get_data(as_text=True)
	assert r.get_json(silent=True) is None  # not the JSON {"redirect": ...} success shape
	# A client-config error mirrors the password path: it is not a failed login.
	assert wbox.deps.failed_logins == []


def test_authenticate_finish_replayed_challenge_rejected(wbox, soft):
	enroll(wbox, soft)
	_, challenge = pkce_pair()
	c = wbox.http.post("/auth/webauthn/authenticate/begin").get_json()["challenge"]
	assertion = json.dumps(soft.get(c, uv=True, origin=ORIGIN, sign_count=1))
	url = "/auth/webauthn/authenticate/finish?" + authorize_query(challenge)
	first = wbox.http.post(url, data=assertion, content_type="application/json")
	assert first.status_code == 200
	second = wbox.http.post(url, data=assertion, content_type="application/json")
	assert second.status_code == 400
	assert second.get_json()["error"] == "This request expired, please try again."
	assert wbox.deps.failed_logins == ["/auth/webauthn/authenticate/finish"]


def test_authenticate_finish_expired_challenge_rejected(wbox, soft):
	enroll(wbox, soft)
	_, challenge = pkce_pair()
	c = wbox.http.post("/auth/webauthn/authenticate/begin").get_json()["challenge"]
	assertion = json.dumps(soft.get(c, uv=True, origin=ORIGIN, sign_count=1))
	wbox.clock["now"] += 121  # challenge TTL is 120s
	url = "/auth/webauthn/authenticate/finish?" + authorize_query(challenge)
	r = wbox.http.post(url, data=assertion, content_type="application/json")
	assert r.status_code == 400
	assert r.get_json()["error"] == "This request expired, please try again."


def test_authenticate_finish_wrong_type_challenge_rejected(wbox, soft):
	# A registration-typed challenge must not satisfy the authentication ceremony.
	enroll(wbox, soft)
	_, challenge = pkce_pair()
	raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
	wbox.store.save_webauthn_challenge(raw, EMAIL, "registration")
	assertion = json.dumps(soft.get(raw, uv=True, origin=ORIGIN, sign_count=1))
	url = "/auth/webauthn/authenticate/finish?" + authorize_query(challenge)
	r = wbox.http.post(url, data=assertion, content_type="application/json")
	assert r.status_code == 400
	assert r.get_json()["error"] == "This request expired, please try again."


def test_authenticate_finish_unknown_credential_generic_and_logs(wbox, soft):
	# soft's credential is never enrolled -> generic error + fail2ban line.
	_, challenge = pkce_pair()
	r = sign_in(wbox, soft, challenge)
	assert r.status_code == 400
	assert r.get_json()["error"] == "Could not verify passkey."
	assert wbox.deps.failed_logins == ["/auth/webauthn/authenticate/finish"]


def test_authenticate_finish_uv_absent_rejected(wbox, soft):
	enroll(wbox, soft)
	_, challenge = pkce_pair()
	r = sign_in(wbox, soft, challenge, user_verified=False)
	assert r.status_code == 400
	assert r.get_json()["error"] == "Could not verify passkey."
	assert wbox.deps.failed_logins == ["/auth/webauthn/authenticate/finish"]


def test_authenticate_finish_wrong_origin_rejected(wbox, soft):
	enroll(wbox, soft)
	_, challenge = pkce_pair()
	r = sign_in(wbox, soft, challenge, origin="https://evil.example.com")
	assert r.status_code == 400
	assert r.get_json()["error"] == "Could not verify passkey."
	assert wbox.deps.failed_logins == ["/auth/webauthn/authenticate/finish"]


def test_authenticate_finish_counter_regression_rejected(wbox, soft):
	enroll(wbox, soft, sign_count=5)
	_, challenge = pkce_pair()
	r = sign_in(wbox, soft, challenge, sign_count=3)  # regression from 5 -> 3
	assert r.status_code == 400
	assert r.get_json()["error"] == "Could not verify passkey."
	assert wbox.deps.failed_logins == ["/auth/webauthn/authenticate/finish"]


def test_authenticate_finish_totp_user_skips_mfa(wbox, soft):
	wbox.deps.add_user("carol@box.example.com", totp="123456")
	enroll(wbox, soft, email="carol@box.example.com")
	_, challenge = pkce_pair()
	r = sign_in(wbox, soft, challenge)
	# A user-verified passkey is itself MFA: validate_mfa is never invoked, so a
	# code is issued directly with no TOTP prompt and no failed login.
	assert r.status_code == 200
	target = r.get_json()["redirect"]
	code = urllib.parse.parse_qs(urllib.parse.urlparse(target).query)["code"][0]
	row = wbox.store.take_code(code)
	assert row["user_email"] == "carol@box.example.com"
	assert wbox.deps.failed_logins == []


# ---------------------------------------------------------------------------
# Task 7: passkey management endpoints (list / rename / revoke)
#
# Reuses the `wbox` fixture (T5/T6) -- the brief's restated fixture is named
# `box`, but this file's actual fixture is `wbox` (see the T6 note above);
# kept as `wbox` here too for a single definition and zero churn on the
# passing T5/T6 suite.
# ---------------------------------------------------------------------------


def _mint_admin_token(wbox, email):
	# A valid admin access token for `email`, carrying the same password_state
	# fingerprint _issue_user_tokens uses so oauth_server.validate_bearer accepts it.
	store = wbox.store
	pw_state = store.password_state(wbox.deps.get_mail_password(email), wbox.deps.get_mfa_state_json(email))
	raw, _ = store.create_token("access", "panel", email, "admin profile", int(time.time()) + 3600, password_state=pw_state)
	return raw


def _seed_credential(wbox, email, credential_id, name, aaguid="00000000-0000-0000-0000-000000000000"):
	# transports=None is a legal NULL for the schema's TEXT column and is not
	# surfaced by the management endpoints, so its encoding is irrelevant here.
	wbox.store.add_webauthn_credential(email, credential_id, b"cose-public-key", 0, None, aaguid, name)
	return next(r["id"] for r in wbox.store.get_webauthn_credentials(email) if r["credential_id"] == credential_id)


def test_list_credentials_scoped_to_caller(wbox):
	wbox.deps.add_user("bob@box.example.com")
	alice_id = _seed_credential(wbox, "alice@box.example.com", b"cred-alice-1", "Alice iPhone", aaguid="fbfc3007-154e-4ecc-8c0b-6e020557d7bd")
	_seed_credential(wbox, "bob@box.example.com", b"cred-bob-1", "Bob Key")
	token = _mint_admin_token(wbox, "alice@box.example.com")

	# A request without a bearer is rejected before any listing happens.
	assert wbox.http.get("/auth/webauthn/credentials").status_code == 401

	r = wbox.http.get("/auth/webauthn/credentials", headers={"Authorization": "Bearer " + token})
	assert r.status_code == 200
	creds = r.get_json()["credentials"]
	assert len(creds) == 1  # only alice's row, never bob's
	c = creds[0]
	assert c["id"] == alice_id
	assert c["name"] == "Alice iPhone"
	assert c["aaguid"] == "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
	assert c["authenticator_name"] == "iCloud Keychain"
	# Verification material and raw ids are never exposed to the browser.
	assert "public_key" not in c
	assert "credential_id" not in c
	assert "sign_count" not in c


def test_rename_credential_and_cross_user_isolation(wbox):
	wbox.deps.add_user("bob@box.example.com")
	alice_id = _seed_credential(wbox, "alice@box.example.com", b"cred-alice-1", "Old Name")
	bob_id = _seed_credential(wbox, "bob@box.example.com", b"cred-bob-1", "Bob Key")
	token = _mint_admin_token(wbox, "alice@box.example.com")
	headers = {"Authorization": "Bearer " + token}

	# Rename own credential.
	r = wbox.http.patch(f"/auth/webauthn/credentials/{alice_id}", json={"name": "New Name"}, headers=headers)
	assert r.status_code == 200
	assert r.get_json() == {"id": alice_id, "name": "New Name"}
	assert wbox.store.get_webauthn_credentials("alice@box.example.com")[0]["name"] == "New Name"

	# Empty/whitespace name -> 400, unchanged.
	r = wbox.http.patch(f"/auth/webauthn/credentials/{alice_id}", json={"name": "   "}, headers=headers)
	assert r.status_code == 400
	assert wbox.store.get_webauthn_credentials("alice@box.example.com")[0]["name"] == "New Name"

	# Renaming another user's credential -> 404, bob's row untouched (no enumeration).
	r = wbox.http.patch(f"/auth/webauthn/credentials/{bob_id}", json={"name": "Hacked"}, headers=headers)
	assert r.status_code == 404
	assert wbox.store.get_webauthn_credentials("bob@box.example.com")[0]["name"] == "Bob Key"


def test_delete_credential_and_cross_user_isolation(wbox):
	wbox.deps.add_user("bob@box.example.com")
	alice_id = _seed_credential(wbox, "alice@box.example.com", b"cred-alice-1", "Alice Key")
	bob_id = _seed_credential(wbox, "bob@box.example.com", b"cred-bob-1", "Bob Key")
	token = _mint_admin_token(wbox, "alice@box.example.com")
	headers = {"Authorization": "Bearer " + token}

	# Deleting another user's credential -> 404, bob's row still present.
	r = wbox.http.delete(f"/auth/webauthn/credentials/{bob_id}", headers=headers)
	assert r.status_code == 404
	assert len(wbox.store.get_webauthn_credentials("bob@box.example.com")) == 1

	# Deleting own credential -> 200, row gone.
	r = wbox.http.delete(f"/auth/webauthn/credentials/{alice_id}", headers=headers)
	assert r.status_code == 200
	assert r.get_json() == {"ok": True}
	assert wbox.store.get_webauthn_credentials("alice@box.example.com") == []


def test_management_endpoints_404_when_feature_disabled(wbox, monkeypatch):
	# Route bodies read is_passkeys_enabled as a module global, so patching the
	# module attribute flips the flag for every endpoint.
	monkeypatch.setattr(webauthn_auth, "is_passkeys_enabled", lambda env: False)
	cred_id = _seed_credential(wbox, "alice@box.example.com", b"cred-alice-1", "Alice Key")
	headers = {"Authorization": "Bearer " + _mint_admin_token(wbox, "alice@box.example.com")}
	assert wbox.http.get("/auth/webauthn/credentials", headers=headers).status_code == 404
	assert wbox.http.patch(f"/auth/webauthn/credentials/{cred_id}", json={"name": "x"}, headers=headers).status_code == 404
	assert wbox.http.delete(f"/auth/webauthn/credentials/{cred_id}", headers=headers).status_code == 404


# --- Unauthenticated begin-endpoint hardening + consolidated feature-flag gate (Task 8) ---


def test_rate_limiter_fixed_window():
	rl = webauthn_auth._RateLimiter(max_requests=3, window_seconds=60)
	now = 1_000.0
	# First 3 requests from one IP in the window are allowed, the 4th is not.
	assert rl.check("203.0.113.4", now=now) is True
	assert rl.check("203.0.113.4", now=now) is True
	assert rl.check("203.0.113.4", now=now) is True
	assert rl.check("203.0.113.4", now=now) is False
	# A different IP has its own independent budget.
	assert rl.check("203.0.113.5", now=now) is True
	# Once the window rolls over, the same IP is allowed again.
	assert rl.check("203.0.113.4", now=now + 60) is True


@pytest.fixture
def guardbox(tmp_path):
	env = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "box.example.com"}
	(tmp_path / "auth").mkdir(mode=0o700)
	deps = SimpleNamespace(log_failed_login=lambda request: None)
	app = Flask("webauthn-guard-test", template_folder=os.path.join(os.path.dirname(__file__), "..", "management", "templates"))
	app.testing = True
	webauthn_auth.init_webauthn(app, env, deps)
	return SimpleNamespace(http=app.test_client(), app=app, env=env, store=oauth_server.current_store(env))


def test_feature_flag_off_hides_entire_namespace(guardbox, monkeypatch):
	# The single before_request guard 404s every /auth/webauthn/* request when
	# the flag is off — including a wrong-method probe (which would otherwise be
	# a 405), so the namespace is indistinguishable from absent.
	monkeypatch.setattr(webauthn_auth, "is_passkeys_enabled", lambda env: False)
	probes = [
		("POST", "/auth/webauthn/register/begin"),
		("POST", "/auth/webauthn/register/finish"),
		("POST", "/auth/webauthn/authenticate/begin"),
		("POST", "/auth/webauthn/authenticate/finish"),
		("GET", "/auth/webauthn/credentials"),
		("PATCH", "/auth/webauthn/credentials/1"),
		("DELETE", "/auth/webauthn/credentials/1"),
		("GET", "/auth/webauthn/register/begin"),  # POST-only route: must 404, not 405
	]
	for method, path in probes:
		r = guardbox.http.open(path, method=method)
		assert r.status_code == 404, (method, path, r.status_code)
