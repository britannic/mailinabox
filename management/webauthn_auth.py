#!/usr/local/lib/mailinabox/env/bin/python
# WebAuthn / passkeys support for the management daemon's browser sign-in.
#
# VENV-ONLY: this is the ONLY module that imports py_webauthn, mirroring
# oauth_server.py as the only authlib importer. It runs inside the management
# daemon's virtualenv. Credential and challenge persistence goes through the
# ONE shared OAuthStore (oauth_server.current_store(env)); this module never
# opens auth.sqlite itself.
#
# DEPENDENCIES: py_webauthn 1.8.0 is the newest release compatible with the
# box-wide cryptography==37.0.2 pin. It requires pydantic v1 and cbor2<5.5,
# both pinned alongside pyOpenSSL==22.0.0 in setup/management.sh.

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

from flask import request, jsonify, Response, abort

import oauth_server
import utils
import webauthn
from webauthn.helpers import bytes_to_base64url, options_to_json
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
	AttestationConveyancePreference,
	AuthenticationCredential,
	AuthenticatorSelectionCriteria,
	PublicKeyCredentialDescriptor,
	PublicKeyCredentialUserEntity,
	RegistrationCredential,
	ResidentKeyRequirement,
	UserVerificationRequirement,
)

logger = logging.getLogger("miab.webauthn")


def _json_error(message, status=400):
	# Shared generic error body for the unauthenticated sign-in ceremony
	# (registration's routes predate this helper and keep their existing
	# inline jsonify(...) shape). Never leaks internal detail -- every
	# ceremony failure (unknown credential, wrong user, bad signature, replay,
	# expiry) collapses to the SAME caller-facing message (spec 9.11, no
	# enumeration).
	return Response(json.dumps({"error": message}), status=status, mimetype="application/json")


def is_passkeys_enabled(env):
	# The auth.passkeys switch is read per-request via utils.load_settings so it
	# takes effect without a daemon restart. load_settings returns {} if
	# settings.yaml is missing or cannot be parsed, so a corrupt file fails OPEN
	# (passkeys stay enabled) -- the same deliberate availability choice as
	# auth.is_legacy_basic_enabled. Warn loudly when the file exists with content
	# but parsed to nothing, so the operator notices.
	settings = utils.load_settings(env)
	if not settings:
		fn = os.path.join(env["STORAGE_ROOT"], "settings.yaml")
		if os.path.exists(fn) and os.path.getsize(fn) > 0:
			logger.warning("Mail-in-a-Box Management Daemon: %s exists but could not be parsed; treating auth.passkeys as enabled (fail-open).", fn)
		return True
	return settings.get("auth", {}).get("passkeys", True)


def user_handle(env, user_email, store):  # noqa: ARG001
	# WebAuthn user.id -- the full 32-byte HMAC-SHA256(server_secret, user_email).
	# Deterministic and NEVER stored: recomputed each ceremony, used only for
	# authenticator-side credential grouping/overwrite. Server identity resolution
	# is always credential_id -> webauthn_credentials.user_email, never this handle.
	# The full 32 bytes (well under WebAuthn's 64-byte user.id cap) make cross-user
	# collision cryptographically negligible. `env` is unused today but kept in the
	# signature so callers pass a consistent (env, user_email, store) triple.
	return hmac.new(store.get_server_secret(), user_email.encode("utf-8"), hashlib.sha256).digest()


def _bearer_admin_email(env, deps):
	# Identity on these routes comes ONLY from the access token (blocker B3):
	# they are not wrapped by @authorized_personnel_only, so request.user_email
	# is unset. Require scope 'admin'; return the caller's email, or None.
	header = request.headers.get("Authorization", "")
	if not header.startswith("Bearer "):
		return None
	info = oauth_server.validate_bearer(env, header[len("Bearer ") :].strip(), oauth_server.SCOPE_ADMIN, deps)
	if info is None or info["user_email"] is None:
		return None
	return info["user_email"]


def _b64url_decode(value):
	# WebAuthn encodes base64url WITHOUT padding; restore it before decoding.
	return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _challenge_from_client_data(body):
	# The browser echoes the server-issued challenge (base64url, no padding)
	# inside clientDataJSON. The stored challenge row is keyed by that exact
	# string, so recovering it here lets us both claim the single-use row and
	# feed py_webauthn the raw expected-challenge bytes. Returns the base64url
	# string, or None if the body is malformed.
	try:
		parsed = json.loads(_b64url_decode(body["response"]["clientDataJSON"]))
		challenge = parsed["challenge"]
	except (TypeError, KeyError, ValueError):
		return None
	return challenge if isinstance(challenge, str) else None


def _registration_options(env, store, user_email):
	# Build navigator.credentials.create() options (spec 8.2). Returns the browser
	# JSON plus the base64url challenge to persist (T5) and later match at finish.
	rp_id = env["PRIMARY_HOSTNAME"]
	challenge_bytes = secrets.token_bytes(32)
	exclude = [PublicKeyCredentialDescriptor(id=cred["credential_id"]) for cred in store.get_webauthn_credentials(user_email)]
	options = webauthn.generate_registration_options(
		rp_id=rp_id,
		rp_name="Mail-in-a-Box",
		user_id=user_email,  # placeholder str; replaced with the 32-byte handle below
		user_name=user_email,
		user_display_name=user_email,
		challenge=challenge_bytes,
		attestation=AttestationConveyancePreference.NONE,
		authenticator_selection=AuthenticatorSelectionCriteria(
			resident_key=ResidentKeyRequirement.REQUIRED,
			user_verification=UserVerificationRequirement.REQUIRED,
		),
		exclude_credentials=exclude,
		supported_pub_key_algs=[
			COSEAlgorithmIdentifier.ECDSA_SHA_256,  # ES256 (-7)
			COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # RS256 (-257)
		],
	)
	# py_webauthn 1.8.0's generate_registration_options takes user_id as a *str*
	# and UTF-8-encodes it; our user handle is 32 raw HMAC bytes (not UTF-8), so
	# replace the whole user entity with the real handle before serializing.
	options.user = PublicKeyCredentialUserEntity(
		id=user_handle(env, user_email, store),
		name=user_email,
		display_name=user_email,
	)
	return options_to_json(options), bytes_to_base64url(challenge_bytes)


def _authentication_options(env, store):  # noqa: ARG001
	# Build navigator.credentials.get() options (spec 8.1) for the usernameless,
	# discoverable-credential flow: allowCredentials is empty. `store` is unused
	# in phase 1 but kept for signature symmetry with _registration_options.
	challenge_bytes = secrets.token_bytes(32)
	options = webauthn.generate_authentication_options(
		rp_id=env["PRIMARY_HOSTNAME"],
		challenge=challenge_bytes,
		user_verification=UserVerificationRequirement.REQUIRED,
		allow_credentials=[],
	)
	return options_to_json(options), bytes_to_base64url(challenge_bytes)


def _passkeys_enabled_or_404(env):
	# Shared feature-flag guard for every /auth/webauthn/* endpoint. When the flag
	# is off the whole surface disappears (spec 9.13). T8 consolidates rate
	# limiting here; T4 establishes the 404-when-disabled contract.
	if not is_passkeys_enabled(env):
		abort(404)


def init_webauthn(app, env, deps):
	# Registers the six WebAuthn routes on the Flask app, mirroring init_oauth.
	# Called from daemon.py right after init_oauth (T9). `deps` is consumed by the
	# route bodies: registration (T5, done), sign-in (T6), management (T7).
	# Every endpoint 404s when the feature flag is off.

	@app.route("/auth/webauthn/register/begin", methods=["POST"])
	def webauthn_register_begin():
		_passkeys_enabled_or_404(env)
		user_email = _bearer_admin_email(env, deps)
		if user_email is None:
			return Response("", 401, {"WWW-Authenticate": "Bearer"})
		store = oauth_server.current_store(env)
		options_json, raw_challenge = _registration_options(env, store, user_email)
		store.save_webauthn_challenge(raw_challenge, user_email, "registration")
		return Response(options_json, mimetype="application/json")

	@app.route("/auth/webauthn/register/finish", methods=["POST"])
	def webauthn_register_finish():
		_passkeys_enabled_or_404(env)
		user_email = _bearer_admin_email(env, deps)
		if user_email is None:
			return Response("", 401, {"WWW-Authenticate": "Bearer"})
		store = oauth_server.current_store(env)
		body = request.get_json(silent=True)
		if not isinstance(body, dict):
			return jsonify({"error": "Could not verify passkey."}), 400
		challenge_b64 = _challenge_from_client_data(body)
		if challenge_b64 is None:
			return jsonify({"error": "Could not verify passkey."}), 400
		# Single-use claim FIRST: a failed/forged finish still burns the
		# challenge (row existence is the authoritative anti-replay gate, §9.3).
		row = store.take_webauthn_challenge(challenge_b64, "registration")
		if row is None:
			return jsonify({"error": "This request expired, please try again."}), 400
		if row["user_email"] != user_email:
			# The challenge was issued to a DIFFERENT signed-in user; never bind
			# a credential under a mismatched identity (spec §8.2). Generic error.
			app.logger.warning("passkey registration challenge user mismatch (challenge=%s, caller=%s)", row["user_email"], user_email)
			return jsonify({"error": "Could not verify passkey."}), 400
		try:
			verification = webauthn.verify_registration_response(
				# py_webauthn 1.8.0's verify_registration_response requires an
				# actual RegistrationCredential, not a raw JSON string (verified
				# empirically against the pinned version); parse it here.
				credential=RegistrationCredential.parse_raw(request.get_data(as_text=True)),
				expected_challenge=_b64url_decode(challenge_b64),
				expected_rp_id=env["PRIMARY_HOSTNAME"],
				expected_origin="https://" + env["PRIMARY_HOSTNAME"],
				require_user_verification=True,
			)
		except Exception:  # noqa: BLE001 -- intentionally blind: any verify failure (bad
			# signature, wrong RP/origin, UV absent, malformed attestation) must
			# collapse to the SAME generic error (§11), no internal detail. This
			# endpoint is Bearer-authenticated (the admin's own device), so a
			# failed attestation is NOT fed to fail2ban -- log_failed_login is
			# reserved for the unauthenticated sign-in assertions (T6).
			app.logger.warning("passkey registration verification failed for %s", user_email)
			return jsonify({"error": "Could not verify passkey."}), 400
		transports = body.get("response", {}).get("transports")
		transports_json = json.dumps(transports) if transports else None
		store.add_webauthn_credential(user_email, verification.credential_id, verification.credential_public_key, verification.sign_count, transports_json, verification.aaguid, "Passkey")
		cred = store.get_webauthn_credential_by_id(verification.credential_id)
		app.logger.info("passkey enrolled for %s (cred %s, aaguid %s)", user_email, verification.credential_id.hex()[:16], verification.aaguid)
		return jsonify({"id": cred["id"], "name": cred["name"], "created_at": cred["created_at"], "last_used_at": cred["last_used_at"], "aaguid": cred["aaguid"]})

	@app.route("/auth/webauthn/authenticate/begin", methods=["POST"])
	def webauthn_authenticate_begin():
		_passkeys_enabled_or_404(env)
		# Usernameless (discoverable-credential) sign-in: allowCredentials is
		# empty; the authenticator picks a resident credential for this RP.
		store = oauth_server.current_store(env)
		options_json, raw_challenge = _authentication_options(env, store)
		store.save_webauthn_challenge(raw_challenge, None, "authentication")
		return Response(options_json, mimetype="application/json")

	@app.route("/auth/webauthn/authenticate/finish", methods=["POST"])
	def webauthn_authenticate_finish():
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T6 Step 8

	@app.route("/auth/webauthn/credentials", methods=["GET"])
	def webauthn_list_credentials():
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T7

	@app.route("/auth/webauthn/credentials/<int:cred_id>", methods=["PATCH"])
	def webauthn_rename_credential(cred_id):  # noqa: ARG001
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T7

	@app.route("/auth/webauthn/credentials/<int:cred_id>", methods=["DELETE"])
	def webauthn_delete_credential(cred_id):  # noqa: ARG001
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T7
