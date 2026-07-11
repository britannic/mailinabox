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

import json
import os
import time

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import ClientMixin, grants
from authlib.oauth2.rfc6749.errors import InvalidScopeError
from flask import Response, request

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
