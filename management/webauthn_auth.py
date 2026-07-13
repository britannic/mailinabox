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
import threading
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

# --- Unauthenticated begin-endpoint hardening (spec §9.14/§10) ---
#
# SHARED-LOCK CONTENTION: every WebAuthn ceremony reaches auth.sqlite through
# the ONE lock-serialized sqlite connection owned by oauth_server.current_store
# — the same connection that serializes every Bearer-token validation on the
# box. The two *unauthenticated* begin endpoints each INSERT a challenge row,
# so unthrottled begin spam is a write-amplification + lock-contention vector,
# and fail2ban only ever sees failed *finish* assertions, never begin abuse.
# Two in-daemon controls bound that surface: (1) a per-IP request cap enforced
# by an in-memory _RateLimiter whose OWN lock is independent of auth.sqlite's,
# so throttled clients are refused without ever queuing on the shared DB lock;
# and (2) a ceiling on the number of live unconsumed `authentication`
# challenges, capping the auth.sqlite backlog under distributed (many-IP) begin
# spam. Both run in a before_request guard that short-circuits before any route
# body — and its challenge write — executes. The daemon runs a single gunicorn
# worker (see daemon.py), so one in-process _RateLimiter is the whole box's
# authoritative view.

_BEGIN_RATE_MAX = 20             # allowed begin requests per IP per window
_BEGIN_RATE_WINDOW = 60          # seconds
_BEGIN_RATE_PRUNE_AT = 4096      # sweep stale IP entries once the map grows past this
_MAX_OUTSTANDING_AUTH_CHALLENGES = 200  # live unconsumed `authentication` challenges

_BEGIN_PATHS = ("/auth/webauthn/register/begin", "/auth/webauthn/authenticate/begin")
_AUTHENTICATE_BEGIN_PATH = "/auth/webauthn/authenticate/begin"


class _RateLimiter:
	# Per-IP fixed-window request counter, entirely in-process. Its lock is
	# deliberately NOT auth.sqlite's lock: a throttled caller never touches the
	# shared connection. A flood of distinct IPs cannot grow the map without
	# bound — stale windows are swept once it crosses _BEGIN_RATE_PRUNE_AT.
	def __init__(self, max_requests, window_seconds):
		self.max_requests = max_requests
		self.window_seconds = window_seconds
		self._windows = {}  # ip -> [window_start_epoch, count]
		self._lock = threading.Lock()

	def check(self, ip, now=None):
		# Record and allow the request, or return False if `ip` is over the cap
		# for the current window. O(1) amortized.
		now = time.time() if now is None else now
		with self._lock:
			if len(self._windows) > _BEGIN_RATE_PRUNE_AT:
				horizon = now - self.window_seconds
				self._windows = {k: v for k, v in self._windows.items() if v[0] > horizon}
			window = self._windows.get(ip)
			if window is None or now - window[0] >= self.window_seconds:
				self._windows[ip] = [now, 1]
				return True
			if window[1] >= self.max_requests:
				return False
			window[1] += 1
			return True


def _client_ip():
	# Same source of truth as daemon.log_failed_login: nginx sets
	# X-Forwarded-For on every proxied request; fall back to remote_addr for
	# direct localhost callers (setup-time / tests).
	forwarded = request.headers.getlist("X-Forwarded-For")
	return forwarded[0] if forwarded else request.remote_addr


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


# Display-only AAGUID -> friendly authenticator name. Attestation is "none"
# (spec 5), so this is a best-effort UI label, never a security control.
_AAGUID_NAMES = {
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
}


def _friendly_authenticator_name(aaguid):
	# Unknown authenticators and the all-zero "no attestation" AAGUID fall back
	# to the generic label; the row's own `name` column is the user-facing label.
	if not aaguid or aaguid == "00000000-0000-0000-0000-000000000000":
		return "Passkey"
	return _AAGUID_NAMES.get(aaguid.lower(), "Passkey")


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
		store = oauth_server.current_store(env)
		# The OAuth request params are read ONLY from the query string (the
		# ceremony fetch preserves the authorize query); the body carries only
		# the WebAuthn assertion -- hidden fields are never trusted (blocker B1).
		p = oauth_server._authorize_request_params()  # noqa: SLF001 -- intentional cross-module reuse (blocker B1); part of oauth_server's documented Task 6 interface
		now = int(time.time())
		try:
			credential = AuthenticationCredential.parse_raw(request.get_data(as_text=True))
			challenge_b64 = json.loads(credential.response.client_data_json)["challenge"]
		except (ValueError, KeyError, TypeError) as exc:
			app.logger.warning("passkey sign-in: malformed assertion: %s", exc)
			deps.log_failed_login(request)
			return _json_error("Could not verify passkey.")
		# Single-use, typed, unexpired challenge row existence is the
		# authoritative anti-replay gate; a replayed/expired/wrong-type finish
		# claims nothing and gets None.
		if store.take_webauthn_challenge(challenge_b64, "authentication", now) is None:
			deps.log_failed_login(request)
			return _json_error("This request expired, please try again.")
		# Identity is resolved from the stored credential, never client input;
		# an unknown credential yields the same generic error (no enumeration).
		cred_row = store.get_webauthn_credential_by_id(credential.raw_id)
		if cred_row is None:
			deps.log_failed_login(request)
			return _json_error("Could not verify passkey.")
		try:
			verification = webauthn.verify_authentication_response(
				credential=credential,
				expected_challenge=_b64url_decode(challenge_b64),
				expected_rp_id=env["PRIMARY_HOSTNAME"],
				expected_origin="https://" + env["PRIMARY_HOSTNAME"],
				credential_public_key=cred_row["public_key"],
				credential_current_sign_count=cred_row["sign_count"],
				require_user_verification=True,
			)
		except Exception:  # noqa: BLE001 -- intentionally blind: any verify failure (bad
			# signature, wrong RP/origin, UV absent, malformed assertion) must
			# collapse to the SAME generic error (§11), no internal detail. This
			# endpoint is unauthenticated sign-in, so every failure here also
			# feeds fail2ban (unlike the Bearer-authenticated registration
			# ceremony, where a failed attestation is the admin's own device).
			app.logger.warning("passkey sign-in verification failed for credential %s", cred_row["id"])
			deps.log_failed_login(request)
			return _json_error("Could not verify passkey.")
		# Signature-counter clone detection (defense in depth -- py_webauthn also
		# rejects a regression internally). 0/0 means the authenticator does not
		# report a counter and is allowed.
		stored_count = cred_row["sign_count"]
		new_count = verification.new_sign_count
		if not (new_count == 0 and stored_count == 0) and new_count <= stored_count:
			app.logger.warning("passkey sign-in rejected: sign-count regression for credential %s (stored=%d asserted=%d) -- possible clone", cred_row["id"], stored_count, new_count)
			deps.log_failed_login(request)
			return _json_error("Could not verify passkey.")
		store.update_webauthn_sign_count(cred_row["id"], new_count, now)
		user_email = cred_row["user_email"]
		# Enforce every authorize invariant except the discrete validate_mfa
		# step (a user-verified passkey is itself MFA): unknown client_id/
		# redirect_uri -> fatal (never a redirect), scope subset of
		# client.allowed_scopes, mandatory PKCE-S256. Mirrors oauth_authorize,
		# which returns this response as-is (a client-config error, not a
		# failed login -- the ceremony itself already succeeded).
		error_response = oauth_server.validate_authorize_request(p, env)
		if error_response is not None:
			return error_response
		raw_code = secrets.token_urlsafe(32)
		store.save_code(raw_code, p["client_id"], user_email, p["scope"], p["redirect_uri"], p["code_challenge"], "S256", now)
		app.logger.info("passkey sign-in success: user=%s credential=%s client=%s", user_email, cred_row["id"], p["client_id"])
		return jsonify({"redirect": oauth_server.build_code_redirect(p, raw_code)})

	@app.route("/auth/webauthn/credentials", methods=["GET"])
	def webauthn_list_credentials():
		_passkeys_enabled_or_404(env)
		user_email = _bearer_admin_email(env, deps)
		if user_email is None:
			return Response("", 401, {"WWW-Authenticate": 'Bearer error="invalid_token"'})
		store = oauth_server.current_store(env)
		creds = [
			{
				"id": c["id"],
				"name": c["name"],
				"created_at": c["created_at"],
				"last_used_at": c["last_used_at"],
				"aaguid": c["aaguid"],
				"authenticator_name": _friendly_authenticator_name(c["aaguid"]),
			}
			for c in store.get_webauthn_credentials(user_email)
		]
		return jsonify({"credentials": creds})

	@app.route("/auth/webauthn/credentials/<int:cred_id>", methods=["PATCH"])
	def webauthn_rename_credential(cred_id):
		_passkeys_enabled_or_404(env)
		user_email = _bearer_admin_email(env, deps)
		if user_email is None:
			return Response("", 401, {"WWW-Authenticate": 'Bearer error="invalid_token"'})
		store = oauth_server.current_store(env)
		data = request.get_json(silent=True) or {}
		name = (data.get("name") or "").strip()
		if not name or len(name) > 100:
			return Response(json.dumps({"error": "Please provide a name between 1 and 100 characters."}), status=400, mimetype="application/json")
		# rename is scoped by user_email in the store; a foreign/unknown id
		# changes nothing and returns False -> 404 (no cross-user enumeration).
		if not store.rename_webauthn_credential(cred_id, user_email, name):
			abort(404)
		return jsonify({"id": cred_id, "name": name})

	@app.route("/auth/webauthn/credentials/<int:cred_id>", methods=["DELETE"])
	def webauthn_delete_credential(cred_id):
		_passkeys_enabled_or_404(env)
		user_email = _bearer_admin_email(env, deps)
		if user_email is None:
			return Response("", 401, {"WWW-Authenticate": 'Bearer error="invalid_token"'})
		store = oauth_server.current_store(env)
		owned = {c["id"]: c for c in store.get_webauthn_credentials(user_email)}
		if cred_id not in owned:
			# Unknown id, or one belonging to another user -> 404 (no enumeration).
			abort(404)
		store.delete_webauthn_credential(cred_id, user_email)
		app.logger.info("Passkey revoked for %s (credential %s)", user_email, owned[cred_id]["credential_id"].hex()[:16])
		return jsonify({"ok": True})
