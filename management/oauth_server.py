# OAuth 2.0 authorization server for the Mail-in-a-Box management daemon.
#
# This is the ONLY module that imports authlib; it runs inside the management
# daemon's virtualenv. Token/code storage is management/oauth_store.py
# (stdlib-only), the fixed first-party client registry is
# management/oauth_clients.py. nginx proxies /admin/* to the daemon with the
# /admin prefix stripped, so the daemon-side route paths below are /oauth/*.
#
# Operator notes: expect one introspection POST per Dovecot OAuth login
# (briefly cached by Dovecot's auth cache) and token-endpoint traffic
# dominated by hourly refreshes per active session. For debugging, the
# auth.sqlite tables are oauth_config, oauth_codes and oauth_tokens (key
# fields: token_type, client_id, user_email, scopes, expires_at, revoked_at,
# parent_id); token values are stored hashed, so rows identify sessions but
# can never be replayed.

import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import ClientMixin, grants
from authlib.oauth2.rfc6749.errors import InvalidGrantError, InvalidRequestError, InvalidScopeError, UnauthorizedClientError
from authlib.oauth2.rfc7636 import CodeChallenge
from flask import Response, abort, jsonify, redirect, render_template, request

import oauth_clients
from oauth_store import OAuthStore, db_path

# The daemon is only ever reached through nginx, which terminates TLS and
# reverse-proxies plain HTTP to 127.0.0.1:10222 (conf/nginx-primaryonly.conf);
# it never accepts connections directly from the internet. Authlib's
# InsecureTransportError inspects the scheme of the request URL it sees at
# the WSGI layer, which is always http:// in this topology even though the
# browser-facing connection is https://, so the check is a false positive
# here — the same reason Authlib's own documentation disables it behind a
# reverse proxy. (It also can't be satisfied by request.url alone: Authlib
# special-cases "http://localhost:<port>", but neither the real proxy target
# nor Flask's test client produce that exact host:port form.)
os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "true")

# Global constants — single source of truth; other modules import these from here.
ACCESS_TOKEN_TTL = 3600          # seconds
REFRESH_TOKEN_TTL = 30 * 86400   # seconds, per-rotation
CHAIN_LIFETIME_CAP = 30 * 86400  # seconds from auth_time; rotation never extends past auth_time + this
CODE_TTL = 60                    # seconds
AUTHZ_FORM_TTL = 600             # seconds, authorize form binding token validity
SCOPE_MAIL, SCOPE_ADMIN, SCOPE_PROFILE = "mail", "admin", "profile"

_stores = {}

def current_store(env):
	# One OAuthStore per database path (sqlite connection is shared; the store
	# opens it with check_same_thread=False and autocommit).
	path = db_path(env)
	if path not in _stores:
		_stores[path] = OAuthStore(path)
	return _stores[path]


class ClientAdapter(ClientMixin):
	# Adapts an oauth_clients.OAuthClient to the interface authlib expects.
	def __init__(self, client):
		self._client = client

	@property
	def is_public(self):
		return self._client.is_public

	@property
	def allowed_scopes(self):
		return self._client.allowed_scopes

	def get_client_id(self):
		return self._client.client_id

	def get_default_redirect_uri(self):
		return self._client.redirect_uris[0] if self._client.redirect_uris else None

	def get_allowed_scope(self, scope):
		if not scope:
			return " ".join(sorted(self._client.allowed_scopes))
		return " ".join(s for s in scope.split() if s in self._client.allowed_scopes)

	def check_redirect_uri(self, redirect_uri):
		# Exact-match only; the registry contains full URLs, no wildcards.
		return redirect_uri in self._client.redirect_uris

	def check_client_secret(self, client_secret):
		return oauth_clients.verify_secret(self._client, client_secret)

	def check_endpoint_auth_method(self, method, _endpoint):
		if self._client.is_public:
			return method == "none"
		return method in {"client_secret_basic", "client_secret_post"}

	def check_grant_type(self, grant_type):
		return grant_type in self._client.grant_types

	def check_response_type(self, response_type):
		return response_type == "code" and "authorization_code" in self._client.grant_types


def _issue_user_tokens(store, deps, client_id, user_email, scopes, auth_time, origin_code_hash, parent_id=None):
	# Mints the linked access+refresh pair for user-bound grants (code exchange
	# and refresh rotation). Both tokens inherit auth_time (anchors the chain
	# cap) and origin_code_hash (enables code-replay/family revocation), and
	# carry the current password/MFA-state fingerprint.
	now = int(time.time())
	stored_hash = deps.get_mail_password(user_email)
	if stored_hash is None:
		raise InvalidGrantError
	pw_state = store.password_state(stored_hash, deps.get_mfa_state_json(user_email))
	access_raw, _ = store.create_token("access", client_id, user_email, scopes, now + ACCESS_TOKEN_TTL, auth_time=auth_time, origin_code_hash=origin_code_hash, password_state=pw_state)
	refresh_expires = min(now + REFRESH_TOKEN_TTL, auth_time + CHAIN_LIFETIME_CAP)
	refresh_raw, _ = store.create_token("refresh", client_id, user_email, scopes, refresh_expires, auth_time=auth_time, origin_code_hash=origin_code_hash, parent_id=parent_id, password_state=pw_state)
	return {"access_token": access_raw, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL, "refresh_token": refresh_raw, "scope": scopes}


class _AuthCode:
	# Minimal object shape authlib's AuthorizationCodeGrant and the
	# CodeChallenge extension expect, wrapping an oauth_codes row dict.
	def __init__(self, row):
		self.row = row
		self.code_challenge = row["code_challenge"]
		self.code_challenge_method = row["code_challenge_method"]

	def get_redirect_uri(self):
		return self.row["redirect_uri"]

	def get_scope(self):
		return self.row["scopes"]

	@staticmethod
	def is_expired():
		return False  # take_code() already rejected expired codes

	def get_auth_time(self):
		return self.row["auth_time"]

	@staticmethod
	def get_nonce():
		return None

	@staticmethod
	def get_acr():
		return None

	@staticmethod
	def get_amr():
		return None


class MiabAuthorizationCodeGrant(grants.AuthorizationCodeGrant):
	# PKCE S256 is enforced for ALL code clients (public and confidential) via
	# the CodeChallenge(required=True) extension registered in init_oauth.
	TOKEN_ENDPOINT_AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")

	def save_authorization_code(self, code, request):
		pass  # codes are saved by the /oauth/authorize route, never through authlib

	def query_authorization_code(self, code, client):
		result = self.server.miab_store.take_code(code)
		if result is None:
			return None
		if result.get("replayed"):
			# RFC 9700 §3: replay of a used code revokes every token issued
			# from it. The route-level handler logs the resulting invalid_grant.
			self.server.miab_store.revoke_family_by_origin(result["code_hash"])
			return None
		if result["client_id"] != client.get_client_id():
			return None
		if result["code_challenge_method"] != "S256":
			# Defense in depth: CodeChallenge(required=True) below defaults an
			# absent method to "plain" and would otherwise fall back to a
			# trivial verifier == challenge compare instead of a SHA-256 check.
			# This grant's whole job is enforcing PKCE, so it must not trust
			# that every stored code was created with method="S256" — the
			# /oauth/authorize route also validates this at creation time, but
			# this check must hold even if that one is ever bypassed.
			raise InvalidGrantError
		self._code = _AuthCode(result)
		return self._code

	def delete_authorization_code(self, authorization_code):
		pass  # take_code() already marked the code used (single-use)

	@staticmethod
	def authenticate_user(authorization_code):
		return authorization_code.row["user_email"]

	def create_token_response(self):
		client = self.request.client
		code = self._code
		scopes = code.get_scope()
		requested = request.form.get("scope")
		if requested:
			# Scope subsetting: never broader than the code's scopes.
			if not set(requested.split()) <= set(scopes.split()):
				raise InvalidScopeError
			scopes = " ".join(sorted(set(requested.split())))
		token = _issue_user_tokens(self.server.miab_store, self.server.miab_deps, client.get_client_id(), code.row["user_email"], scopes, code.row["auth_time"], code.row["code_hash"])
		return 200, token, self.TOKEN_RESPONSE_HEADER


class MiabRefreshTokenGrant(grants.RefreshTokenGrant):
	TOKEN_ENDPOINT_AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")

	# The base-class hook methods are unused because validate_token_request is
	# fully overridden below (our store model needs reuse detection and the
	# chain cap, which authlib's default flow has no seams for).
	@staticmethod
	def authenticate_refresh_token(_refresh_token):
		return None

	@staticmethod
	def authenticate_user(_credential):
		return None

	def revoke_old_credential(self, credential):
		pass

	def validate_token_request(self):
		client = self.authenticate_token_endpoint_client()
		if not client.check_grant_type(self.GRANT_TYPE):
			raise UnauthorizedClientError
		raw = request.form.get("refresh_token")
		if not raw:
			raise InvalidRequestError(description='Missing "refresh_token" in request.')
		store = self.server.miab_store
		deps = self.server.miab_deps
		now = int(time.time())
		row = store.lookup_token(raw, "refresh")
		if row is None or row["client_id"] != client.get_client_id():
			raise InvalidGrantError
		if row["revoked_at"] is not None:
			# Reuse of a rotated-out refresh token: revoke the whole family.
			# The route-level handler logs the resulting invalid_grant.
			if row["origin_code_hash"]:
				store.revoke_family_by_origin(row["origin_code_hash"])
			raise InvalidGrantError
		if row["expires_at"] <= now:
			raise InvalidGrantError
		if row["auth_time"] is not None and row["auth_time"] + CHAIN_LIFETIME_CAP <= now:
			# Absolute chain cap reached: force full interactive re-auth.
			raise InvalidGrantError
		requested = request.form.get("scope")
		granted = set((row["scopes"] or "").split())
		if requested:
			if not set(requested.split()) <= granted:
				raise InvalidScopeError
			self._new_scopes = " ".join(sorted(set(requested.split())))
		else:
			self._new_scopes = row["scopes"]
		# Fresh password/MFA-state check before rotating.
		stored_hash = deps.get_mail_password(row["user_email"])
		if stored_hash is None:
			raise InvalidGrantError
		expected = store.password_state(stored_hash, deps.get_mfa_state_json(row["user_email"]))
		if not hmac.compare_digest(expected, row["password_state"] or ""):
			store.revoke_token(row["id"])
			raise InvalidGrantError
		self._row = row

	def create_token_response(self):
		store = self.server.miab_store
		row = self._row
		# Rotate: retire the old refresh token, chain the new pair to it.
		store.revoke_token(row["id"])
		token = _issue_user_tokens(store, self.server.miab_deps, row["client_id"], row["user_email"], self._new_scopes, row["auth_time"], row["origin_code_hash"], parent_id=row["id"])
		return 200, token, self.TOKEN_RESPONSE_HEADER


class MiabClientCredentialsGrant(grants.ClientCredentialsGrant):
	# Used by the 'system' client (management/cli.py, tools/dns_update,
	# tools/web_update). Access token only; no user, no refresh token, no
	# password_state fingerprint (startup revocation in daemon.py covers
	# api.key rotation semantics).
	TOKEN_ENDPOINT_AUTH_METHODS = ("client_secret_basic", "client_secret_post")

	def create_token_response(self):
		client = self.request.client
		requested = request.form.get("scope")
		if requested:
			if not set(requested.split()) <= set(client.allowed_scopes):
				raise InvalidScopeError
			scopes = " ".join(sorted(set(requested.split())))
		else:
			scopes = " ".join(sorted(client.allowed_scopes))
		now = int(time.time())
		raw, _ = self.server.miab_store.create_token("access", client.get_client_id(), None, scopes, now + ACCESS_TOKEN_TTL)
		token = {"access_token": raw, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL, "scope": scopes}
		return 200, token, self.TOKEN_RESPONSE_HEADER


def _oauth_error(error_code, status):
	# Minimal RFC 6749 error body; never include internal detail.
	return Response(json.dumps({"error": error_code}), status=status, mimetype="application/json")


def _check_access_token(env, raw_token, required_scope, deps):
	# Shared access-token validity check (used by validate_bearer and the
	# introspection endpoint). Returns the full store row, or None.
	if not raw_token:
		return None
	store = current_store(env)
	row = store.lookup_token(raw_token, "access")
	if row is None:
		return None
	now = int(time.time())
	if row["revoked_at"] is not None or row["expires_at"] <= now:
		return None
	if row["user_email"]:
		# Password/MFA-state fingerprint: a password or MFA change through ANY
		# writer (management API, Roundcube's direct-SQL password plugin)
		# invalidates the user's tokens immediately.
		stored_hash = deps.get_mail_password(row["user_email"])
		if stored_hash is None:
			return None
		expected = store.password_state(stored_hash, deps.get_mfa_state_json(row["user_email"]))
		if not hmac.compare_digest(expected, row["password_state"] or ""):
			return None
	if required_scope not in set((row["scopes"] or "").split()):
		return None
	return row


def validate_bearer(env, raw_token, required_scope, deps):
	# Public helper: access-token check shared by /oauth/userinfo and the
	# auth.py Bearer middleware (Task 9).
	row = _check_access_token(env, raw_token, required_scope, deps)
	if row is None:
		return None
	return {"user_email": row["user_email"], "scopes": set(row["scopes"].split()), "client_id": row["client_id"]}


def _client_auth_from_request():
	# client_secret_basic or client_secret_post; query-string credentials are
	# rejected by the callers before this runs.
	auth = request.authorization
	if auth is not None and auth.type == "basic":
		return auth.username or "", auth.password or ""
	return request.form.get("client_id", ""), request.form.get("client_secret", "")


_CLIENT_DISPLAY_NAMES = {"panel": "the Mail-in-a-Box control panel", "roundcube": "webmail"}


def _authorize_request_params():
	# The OAuth parameters are ALWAYS read from the query string — on POST the
	# form action preserves it — and re-validated on every request; hidden form
	# fields are never trusted for them.
	return {
		"client_id": request.args.get("client_id", ""),
		"redirect_uri": request.args.get("redirect_uri", ""),
		"response_type": request.args.get("response_type", ""),
		"scope": request.args.get("scope", ""),
		"state": request.args.get("state", ""),
		"code_challenge": request.args.get("code_challenge", ""),
		"code_challenge_method": request.args.get("code_challenge_method", ""),
	}


def _redirect_error(p, error_code):
	# RFC 6749 §4.1.2.1 — only reached AFTER client_id and redirect_uri have
	# been validated against the registry.
	q = {"error": error_code}
	if p["state"]:
		q["state"] = p["state"]
	sep = "&" if "?" in p["redirect_uri"] else "?"
	return redirect(p["redirect_uri"] + sep + urllib.parse.urlencode(q))


def init_oauth(app, env, deps):
	# Registers all OAuth routes on the Flask app. `deps` is the plain object
	# daemon.py constructs (Task 9): check_user_password, get_mail_password,
	# get_mfa_state_json, validate_mfa, get_user_privileges, log_failed_login.
	store = current_store(env)

	def query_client(client_id):
		client = oauth_clients.get_client(env, client_id)
		return ClientAdapter(client) if client is not None else None

	authorization = AuthorizationServer()
	authorization.init_app(app, query_client=query_client, save_token=lambda _token, _req: None)
	# Our grant subclasses mint and persist tokens themselves through these:
	authorization.miab_store = store
	authorization.miab_deps = deps
	authorization.miab_env = env
	authorization.register_grant(MiabClientCredentialsGrant)
	authorization.register_grant(MiabAuthorizationCodeGrant, [CodeChallenge(required=True)])
	authorization.register_grant(MiabRefreshTokenGrant)

	@app.route("/oauth/token", methods=["POST"])
	def oauth_token():
		# RFC 9700: never accept client credentials in the query string — they
		# leak into access logs, error lines and referrers.
		if "client_id" in request.args or "client_secret" in request.args:
			# Not a credential failure (no fail2ban line), but leave an operator
			# hint for debugging a misconfigured client.
			app.logger.info("Rejected /oauth/token request carrying client credentials in the query string")
			return _oauth_error("invalid_request", 400)
		try:
			response = authorization.create_token_response()
		except Exception:
			# Defense in depth: an internal failure must never leak a stack
			# trace or an HTML error page from the token endpoint.
			app.logger.exception("Unhandled error in /oauth/token")
			return _oauth_error("server_error", 500)
		if response.status_code != 200:
			# Exactly one fail2ban-visible log line per failed credentialed
			# attempt: bad client secret (invalid_client) or bad/expired/
			# replayed code / bad/expired/reused refresh token (invalid_grant).
			try:
				error = json.loads(response.get_data(as_text=True)).get("error")
			except ValueError:
				error = None
			if error in {"invalid_client", "invalid_grant"}:
				deps.log_failed_login(request)
		return response

	@app.route("/oauth/introspect", methods=["POST"])
	def oauth_introspect():
		# Layer-2 isolation (layer 1 is nginx's `return 404`, Task 11): nginx
		# always sets X-Forwarded-For on proxied requests; legitimate direct
		# localhost callers (Dovecot) never send it. Checked FIRST.
		if "X-Forwarded-For" in request.headers:
			abort(404)
		# All failure modes below return 200 {"active": false} with no detail.
		if "client_id" in request.args or "client_secret" in request.args:
			app.logger.info("Rejected /oauth/introspect request carrying client credentials in the query string")
			return jsonify({"active": False})
		client_id, client_secret = _client_auth_from_request()
		dovecot = oauth_clients.get_client(env, "dovecot")
		if client_id != "dovecot" or dovecot is None or not oauth_clients.verify_secret(dovecot, client_secret):
			deps.log_failed_login(request)
			return jsonify({"active": False})
		row = _check_access_token(env, request.form.get("token", ""), SCOPE_MAIL, deps)
		if row is None or row["user_email"] is None:
			return jsonify({"active": False})
		return jsonify({"active": True, "username": row["user_email"], "scope": row["scopes"], "client_id": row["client_id"], "exp": row["expires_at"], "token_type": "Bearer"})

	@app.route("/oauth/revoke", methods=["POST"])
	def oauth_revoke():
		# RFC 7009. The public 'panel' client may revoke its own tokens with
		# client_id alone (browser logout has no secret); confidential clients
		# must authenticate. Unknown/foreign tokens still yield 200.
		if "client_id" in request.args or "client_secret" in request.args:
			app.logger.info("Rejected /oauth/revoke request carrying client credentials in the query string")
			return _oauth_error("invalid_request", 400)
		client_id, client_secret = _client_auth_from_request()
		client = oauth_clients.get_client(env, client_id)
		if client is None or (not client.is_public and not oauth_clients.verify_secret(client, client_secret)):
			deps.log_failed_login(request)
			return _oauth_error("invalid_client", 401)
		raw = request.form.get("token", "")
		hint = request.form.get("token_type_hint", "")
		row = None
		for token_type in (("access", "refresh") if hint == "access_token" else ("refresh", "access")):
			row = store.lookup_token(raw, token_type)
			if row is not None:
				break
		if row is not None and row["client_id"] == client_id and row["revoked_at"] is None:
			kind = row["token_type"]
			if kind == "refresh" and row["origin_code_hash"]:
				# Revoking a refresh token revokes its whole family.
				store.revoke_family_by_origin(row["origin_code_hash"])
			else:
				store.revoke_token(row["id"])
		return Response("", 200)

	def form_binding(p, binding_expires):
		# Request-binding token: ties a rendered form to the exact authorization
		# request it was rendered for, so a captured form POST cannot be replayed
		# against a different client/redirect/scope/challenge.
		#
		# state and code_challenge are arbitrary, client-controlled strings, so a
		# plain "|".join(...) of the raw fields would be ambiguous (a "|" inside
		# one field could be confused with the delimiter, letting distinct field
		# tuples hash identically). Hash each field to a fixed-length digest
		# before joining so no field's contents can be mistaken for a delimiter.
		fields = (p["client_id"], p["redirect_uri"], p["scope"], p["state"], p["code_challenge"], str(binding_expires))
		message = "authz|" + "|".join(hashlib.sha256(field.encode()).hexdigest() for field in fields)
		return hmac.new(store.get_server_secret(), message.encode(), hashlib.sha256).hexdigest()

	def render_authorize_form(p, error=None, show_totp=False, email=""):
		binding_expires = int(time.time()) + AUTHZ_FORM_TTL
		return render_template("oauth-authorize.html", hostname=env["PRIMARY_HOSTNAME"], client_name=_CLIENT_DISPLAY_NAMES.get(p["client_id"], p["client_id"]), fatal_error=None, error=error, show_totp=show_totp, email=email, binding=form_binding(p, binding_expires), binding_expires=binding_expires)

	def render_authorize_fatal(message):
		# Invalid client_id/redirect_uri: a 400 HTML page, NEVER a redirect
		# (redirecting would create an open redirector).
		return render_template("oauth-authorize.html", hostname=env["PRIMARY_HOSTNAME"], client_name=None, fatal_error=message, error=None, show_totp=False, email="", binding="", binding_expires=0), 400

	def validate_authorize_request(p):
		# Returns None if the request is acceptable, else a complete response.
		client = oauth_clients.get_client(env, p["client_id"])
		if client is None or "authorization_code" not in client.grant_types:
			return render_authorize_fatal("This sign-in request came from an unknown application (invalid client_id).")
		if p["redirect_uri"] not in client.redirect_uris:
			return render_authorize_fatal("This sign-in request has an invalid redirect URI.")
		if p["response_type"] != "code":
			return _redirect_error(p, "unsupported_response_type")
		scopes = set(p["scope"].split())
		if not scopes or not scopes <= client.allowed_scopes:
			return _redirect_error(p, "invalid_scope")
		if not p["code_challenge"] or p["code_challenge_method"] != "S256":
			# PKCE S256 is mandatory for every code client, public or confidential.
			return _redirect_error(p, "invalid_request")
		return None

	@app.route("/oauth/authorize", methods=["GET", "POST"])
	def oauth_authorize():
		p = _authorize_request_params()
		error_response = validate_authorize_request(p)
		if error_response is not None:
			return error_response
		if request.method == "GET":
			return render_authorize_form(p)
		# POST: the OAuth params were just re-validated from the query string;
		# the binding proves this POST belongs to a form we rendered for exactly
		# these parameters and that it is not stale.
		try:
			binding_expires = int(request.form.get("binding_expires", ""))
		except ValueError:
			binding_expires = 0
		now = int(time.time())
		if binding_expires <= now or not hmac.compare_digest(form_binding(p, binding_expires), request.form.get("binding", "")):
			return render_authorize_form(p, error="This sign-in form has expired. Please try again.")
		email = request.form.get("email", "").strip()
		password = request.form.get("password", "")
		totp_token = request.form.get("totp_token", "").strip() or None
		if not email or not password or not deps.check_user_password(email, password):
			deps.log_failed_login(request)
			return render_authorize_form(p, error="Incorrect email address or password.", email=email)
		mfa_status = deps.validate_mfa(email, totp_token)
		if mfa_status == "missing-totp-token":
			# Two-step UX like the existing login page: re-render with the TOTP
			# field visible and the email preserved (the password is deliberately
			# never echoed back into HTML and must be re-entered).
			return render_authorize_form(p, show_totp=True, email=email)
		if mfa_status == "invalid-totp-token":
			deps.log_failed_login(request)
			return render_authorize_form(p, error="Incorrect two factor authentication token.", show_totp=True, email=email)
		raw_code = secrets.token_urlsafe(32)
		store.save_code(raw_code, p["client_id"], email, p["scope"], p["redirect_uri"], p["code_challenge"], "S256", now)
		q = {"code": raw_code}
		if p["state"]:
			q["state"] = p["state"]
		sep = "&" if "?" in p["redirect_uri"] else "?"
		return redirect(p["redirect_uri"] + sep + urllib.parse.urlencode(q))

	@app.route("/oauth/userinfo", methods=["GET"])
	def oauth_userinfo():
		header = request.headers.get("Authorization", "")
		if not header.startswith("Bearer "):
			return Response("", 401, {"WWW-Authenticate": "Bearer"})
		info = validate_bearer(env, header[len("Bearer "):].strip(), SCOPE_PROFILE, deps)
		if info is None or info["user_email"] is None:
			return Response("", 401, {"WWW-Authenticate": 'Bearer error="invalid_token"'})
		return jsonify({"email": info["user_email"], "privileges": deps.get_user_privileges(info["user_email"])})

	@app.route("/.well-known/oauth-authorization-server", methods=["GET"])
	def oauth_metadata():
		# RFC 8414. nginx proxies exactly this public path to the daemon
		# unchanged (Task 11); the /admin-prefixed endpoints below are the
		# public URLs (nginx strips /admin before proxying those).
		base = "https://" + env["PRIMARY_HOSTNAME"]
		return jsonify({
			"issuer": base,
			"authorization_endpoint": base + "/admin/oauth/authorize",
			"token_endpoint": base + "/admin/oauth/token",
			"revocation_endpoint": base + "/admin/oauth/revoke",
			"userinfo_endpoint": base + "/admin/oauth/userinfo",
			"scopes_supported": [SCOPE_MAIL, SCOPE_ADMIN, SCOPE_PROFILE],
			"response_types_supported": ["code"],
			"grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
			"code_challenge_methods_supported": ["S256"],
			"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
		})
