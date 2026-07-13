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

import hashlib
import hmac
import logging
import os
import secrets

from flask import abort, jsonify

import utils
import webauthn
from webauthn.helpers import bytes_to_base64url, options_to_json
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
	AttestationConveyancePreference,
	AuthenticatorSelectionCriteria,
	PublicKeyCredentialDescriptor,
	PublicKeyCredentialUserEntity,
	ResidentKeyRequirement,
	UserVerificationRequirement,
)

logger = logging.getLogger("miab.webauthn")


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


def init_webauthn(app, env, deps):  # noqa: ARG001
	# Registers the six WebAuthn routes on the Flask app, mirroring init_oauth.
	# Called from daemon.py right after init_oauth (T9). `deps` is consumed by the
	# route bodies added in later tasks: registration (T5), sign-in (T6),
	# management (T7). Every endpoint 404s when the feature flag is off.

	@app.route("/auth/webauthn/register/begin", methods=["POST"])
	def webauthn_register_begin():
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T5

	@app.route("/auth/webauthn/register/finish", methods=["POST"])
	def webauthn_register_finish():
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T5

	@app.route("/auth/webauthn/authenticate/begin", methods=["POST"])
	def webauthn_authenticate_begin():
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T6

	@app.route("/auth/webauthn/authenticate/finish", methods=["POST"])
	def webauthn_authenticate_finish():
		_passkeys_enabled_or_404(env)
		return jsonify({"error": "not implemented"}), 501  # body: T6

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
