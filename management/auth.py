import base64, hmac, json, os, sys, secrets, time
from datetime import timedelta

from expiringdict import ExpiringDict
from flask import Response

import oauth_server
import utils
from mailconfig import get_mail_password, get_mail_user_privileges
from mfa import get_hash_mfa_state, validate_auth_mfa

DEFAULT_KEY_PATH   = '/var/lib/mailinabox/api.key'
DEFAULT_AUTH_REALM = 'Mail-in-a-Box Management Server'

class OAuthDeps:
	"""Callables the OAuth authorization server (management/oauth_server.py) needs
	from the rest of the system. Built via AuthService.deps(env); daemon.py passes
	the instance to oauth_server.init_oauth()."""

	def __init__(self, env, log_failed_login=None):
		self.env = env
		self._log_failed_login = log_failed_login

	def check_user_password(self, email, password):
		# Validate a user's password with 'doveadm pw' against the stored hash,
		# exactly like AuthService.check_user_auth does. Returns a bool instead
		# of raising so the OAuth server can shape its own RFC 6749 errors.
		try:
			pw_hash = get_mail_password(email, self.env)
			utils.shell('check_call', [
				"/usr/bin/doveadm", "pw",
				"-p", password,
				"-t", pw_hash,
				])
		except:
			return False
		return True

	def get_mail_password(self, email):
		# The stored password hash, or None if the email address is not a user.
		try:
			return get_mail_password(email, self.env)
		except ValueError:
			return None

	def get_mfa_state_json(self, email):
		# Canonical JSON of the user's MFA state --- byte-identical to the MFA half
		# of AuthService.create_user_password_state_token's input, so OAuth
		# password_state fingerprints invalidate in exactly the same situations
		# as legacy sessions do.
		return json.dumps(get_hash_mfa_state(email, self.env), sort_keys=True)

	def validate_mfa(self, email, totp_code):
		# Returns "ok", "missing-totp-token" or "invalid-totp-token". Reuses
		# mfa.validate_auth_mfa (including its mru_token replay protection) by
		# presenting the code the way that function reads it: an x-auth-token header.
		class _TokenCarrier:
			headers = {"x-auth-token": totp_code}
		status, hints = validate_auth_mfa(email, _TokenCarrier(), self.env)
		if status:
			return "ok"
		if "invalid-totp-token" in hints:
			return "invalid-totp-token"
		return "missing-totp-token"

	def get_user_privileges(self, email):
		return get_mail_user_privileges(email, self.env, empty_on_error=True)

	def log_failed_login(self, request):
		# Pass-through to daemon.py's log_failed_login --- THE fail2ban-matched
		# logging function. Never reimplemented here (byte-exact log contract).
		if self._log_failed_login is not None:
			self._log_failed_login(request)

class AuthService:
	def __init__(self):
		self.auth_realm = DEFAULT_AUTH_REALM
		self.key_path = DEFAULT_KEY_PATH
		self.max_session_duration = timedelta(days=2)

		self.init_system_api_key()
		self.sessions = ExpiringDict(max_len=64, max_age_seconds=self.max_session_duration.total_seconds())

		# Rate limiter state for deprecation/parse warnings: {key: "YYYY-MM-DD" of last emission}.
		self.deprecation_log_dates = {}

	def init_system_api_key(self):
		"""Write an API key to a local file so local processes can use the API"""

		with open(self.key_path, encoding='utf-8') as file:
			self.key = file.read()

	def authenticate(self, request, env, login_only=False, logout=False):
		"""Test if the HTTP Authorization header is a valid OAuth bearer token, the system
		API key, a session key, or a username/password pair for a local user.
		Returns a tuple of the user's email address and list of user privileges (e.g.
		('my@email', []) or ('my@email', ['admin']); raises a ValueError on login failure.
		If the user used the system API key or a client-credentials bearer token, the user's
		email is returned as None since these are not associated with a user."""

		header = request.headers.get('Authorization', '')

		# OAuth 2.0 Bearer tokens are the primary authentication scheme. /login and
		# /logout manage legacy sessions only, so Bearer is not accepted there.
		if header.startswith("Bearer ") and not login_only and not logout:
			info = oauth_server.validate_bearer(env, header[len("Bearer "):].strip(), required_scope="admin", deps=self.deps(env))
			if info is None:
				msg = "Invalid API token."
				raise ValueError(msg)
			if info["user_email"] is None:
				# A client-credentials token (the 'system' client); not associated with a user.
				return (None, ["admin"])
			privs = get_mail_user_privileges(info["user_email"], env)
			if isinstance(privs, tuple): raise ValueError(privs[0])
			return (info["user_email"], privs)

		def parse_http_authorization_basic(header):
			def decode(s):
				return base64.b64decode(s.encode('ascii')).decode('ascii')
			if " " not in header:
				return None, None
			scheme, credentials = header.split(maxsplit=1)
			if scheme != 'Basic':
				return None, None
			credentials = decode(credentials)
			if ":" not in credentials:
				return None, None
			username, password = credentials.split(':', maxsplit=1)
			return username, password

		username, password = parse_http_authorization_basic(header)
		if username in {None, ""}:
			msg = "Authorization header invalid."
			raise ValueError(msg)

		if username.strip() == "" and password.strip() == "":
			msg = "No email address, password, session key, or API key provided."
			raise ValueError(msg)

		# Everything below is legacy HTTP Basic authentication, which the operator can
		# turn off with the settings.yaml key auth.legacy_basic (default: enabled).
		if not self.is_legacy_basic_enabled(env):
			msg = "Basic authentication is disabled on this box. Use an OAuth bearer token."
			raise ValueError(msg)

		# If user passed the system API key, grant administrative privs. This key
		# is not associated with a user.
		if username == self.key and not login_only:
			self.log_deprecated_basic("api_key")
			return (None, ["admin"])

		# If the password corresponds with a session token for the user, grant access for that user.
		if self.get_session(username, password, "login", env) and not login_only:
			sessionid = password
			session = self.sessions[sessionid]
			self.log_deprecated_basic("session_token")
			if logout:
				# Clear the session.
				del self.sessions[sessionid]
			else:
				# Re-up the session so that it does not expire.
				self.sessions[sessionid] = session

		# If no password was given, but a username was given, we're missing some information.
		elif password.strip() == "":
			msg = "Enter a password."
			raise ValueError(msg)

		else:
			# The user is trying to log in with a username and a password
			# (and possibly a MFA token). On failure, an exception is raised.
			self.check_user_auth(username, password, request, env)
			self.log_deprecated_basic("user_password")

		# Get privileges for authorization. This call should never fail because by this
		# point we know the email address is a valid user --- unless the user has been
		# deleted after the session was granted. On error the call will return a tuple
		# of an error message and an HTTP status code.
		privs = get_mail_user_privileges(username, env)
		if isinstance(privs, tuple): raise ValueError(privs[0])

		# Return the authorization information.
		return (username, privs)

	def check_user_auth(self, email, pw, request, env):
		# Validate a user's login email address and password. If MFA is enabled,
		# check the MFA token in the X-Auth-Token header.
		#
		# On login failure, raises a ValueError with a login error message. On
		# success, nothing is returned.

		# Authenticate.
		try:
			# Get the hashed password of the user. Raise a ValueError if the
			# email address does not correspond to a user. But wrap it in the
			# same exception as if a password fails so we don't easily reveal
			# if an email address is valid.
			pw_hash = get_mail_password(email, env)

			# Use 'doveadm pw' to check credentials. doveadm will return
			# a non-zero exit status if the credentials are no good,
			# and check_call will raise an exception in that case.
			utils.shell('check_call', [
				"/usr/bin/doveadm", "pw",
				"-p", pw,
				"-t", pw_hash,
				])
		except:
			# Login failed.
			msg = "Incorrect email address or password."
			raise ValueError(msg)

		# If MFA is enabled, check that MFA passes.
		status, hints = validate_auth_mfa(email, request, env)
		if not status:
			# Login valid. Hints may have more info.
			raise ValueError(",".join(hints))

	def is_legacy_basic_enabled(self, env):
		# The auth.legacy_basic switch is read per-request via utils.load_settings so it
		# takes effect without a daemon restart. load_settings returns {} if settings.yaml
		# is missing or cannot be parsed, so a corrupt file fails OPEN (legacy Basic stays
		# enabled) --- a deliberate availability choice. Warn loudly (rate-limited) when
		# the file exists with content but parsed to nothing, so the operator notices.
		settings = utils.load_settings(env)
		if not settings:
			fn = os.path.join(env["STORAGE_ROOT"], "settings.yaml")
			if os.path.exists(fn) and os.path.getsize(fn) > 0:
				self._log_warning_once("settings_parse_warning", f"Mail-in-a-Box Management Daemon: {fn} exists but could not be parsed; treating auth.legacy_basic as enabled (fail-open).")
		return settings.get("auth", {}).get("legacy_basic", True)

	def log_deprecated_basic(self, form):
		# Log each legacy-Basic use, rate-limited to once per credential form per day.
		# The rate limit applies ONLY to this deprecation notice --- log_failed_login in
		# daemon.py is always emitted unconditionally on failures (fail2ban contract).
		# This line must never contain the substring "Failed login attempt".
		self._log_warning_once(form, f"Mail-in-a-Box Management Daemon: Deprecated Basic authentication used (form={form})")

	def _log_warning_once(self, key, message):
		today = time.strftime("%Y-%m-%d")
		if self.deprecation_log_dates.get(key) == today:
			return
		self.deprecation_log_dates[key] = today
		self._log_warning(message)

	def _log_warning(self, message):
		# Use the Flask app logger --- the same syslog channel as daemon.py's
		# log_failed_login --- when inside a request; fall back to stderr otherwise
		# (e.g. in unit tests).
		try:
			from flask import current_app
			current_app.logger.warning(message)
		except RuntimeError:
			print(message, file=sys.stderr)

	def make_unauthorized_response(self, env=None):
		# 401 challenge response. Fixes the latent bug where daemon.py's 401 error
		# handler called a method that did not exist. Bearer is always advertised;
		# Basic only while legacy Basic auth is enabled (fail-open when env is not
		# available to read settings from).
		challenge = f'Bearer realm="{self.auth_realm}"'
		if env is None or self.is_legacy_basic_enabled(env):
			challenge += f', Basic realm="{self.auth_realm}"'
		return Response("", 401, {"WWW-Authenticate": challenge})

	def deps(self, env, log_failed_login=None):
		# Build the callables object consumed by oauth_server.init_oauth/validate_bearer.
		return OAuthDeps(env, log_failed_login=log_failed_login)

	def create_user_password_state_token(self, email, env):
		# Create a token that changes if the user's password or MFA options change
		# so that sessions become invalid if any of that information changes.
		msg = get_mail_password(email, env).encode("utf8")

		# Add to the message the current MFA state, which is a list of MFA information.
		# Turn it into a string stably.
		msg += b" " + json.dumps(get_hash_mfa_state(email, env), sort_keys=True).encode("utf8")

		# Make a HMAC using the system API key as a hash key.
		hash_key = self.key.encode('ascii')
		return hmac.new(hash_key, msg, digestmod="sha256").hexdigest()

	def create_session_key(self, username, env, type=None):
		# Create a new session.
		token = secrets.token_hex(32)
		self.sessions[token] = {
			"email": username,
			"password_token": self.create_user_password_state_token(username, env),
			"type": type,
		}
		return token

	def get_session(self, user_email, session_key, session_type, env):
		if session_key not in self.sessions: return None
		session = self.sessions[session_key]
		if session_type == "login" and session["email"] != user_email: return None
		if session["type"] != session_type: return None
		if session["password_token"] != self.create_user_password_state_token(session["email"], env): return None
		return session
