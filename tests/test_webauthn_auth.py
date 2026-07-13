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
# ruff: noqa: S101, SLF001, PLC0415

import base64
import hashlib
import hmac
import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "management"))

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
	from flask import Flask

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


def test_endpoint_stub_reachable_when_flag_enabled(env):
	client = _make_app(env).test_client()  # no settings.yaml -> default enabled
	assert client.post("/auth/webauthn/authenticate/begin").status_code == 501
