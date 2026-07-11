# Fixed, first-party OAuth client registry. Defined in code, never in the
# database; secrets live in root-only files (see setup/oauth.sh) and are
# compared with hmac.compare_digest.
#
# STDLIB ONLY: imported by oauth_server.py inside the venv, but must not
# require anything outside the standard library.

import hmac
import os
from pathlib import Path

from oauth_store import auth_dir


class OAuthClient:
	def __init__(self, client_id, is_public, grant_types, allowed_scopes, redirect_uris, secret_path):
		self.client_id = client_id
		self.is_public = is_public
		self.grant_types = grant_types
		self.allowed_scopes = allowed_scopes
		self.redirect_uris = redirect_uris
		self.secret_path = secret_path


def registry(env):
	h = env["PRIMARY_HOSTNAME"]
	a = auth_dir(env)
	return {
		# The control panel SPA: public client, PKCE S256 required, no client secret.
		"panel": OAuthClient("panel", True, frozenset({"authorization_code", "refresh_token"}), frozenset({"admin", "profile"}), ("https://" + h + "/admin",), None),
		# Roundcube's server-side generic OAuth provider. The redirect path is
		# Roundcube 1.6's OAuth callback; re-verified against the shipped
		# Roundcube version in the webmail setup task (Task 14). If the
		# callback path ever changes, update this registry entry AND
		# tests/test_auth_oauth.py in the same commit.
		"roundcube": OAuthClient("roundcube", False, frozenset({"authorization_code", "refresh_token"}), frozenset({"mail", "profile"}), ("https://" + h + "/mail/index.php/login/oauth",), os.path.join(a, "roundcube_client_secret.txt")),
		# Local tooling (cli.py, tools/dns_update, tools/web_update): the live
		# api.key file is the client secret, so key rotation on daemon restart
		# invalidates the credential exactly as today.
		"system": OAuthClient("system", False, frozenset({"client_credentials"}), frozenset({"admin"}), (), "/var/lib/mailinabox/api.key"),
		# Dovecot authenticates to the introspection endpoint only; it holds
		# no grants and no scopes of its own.
		"dovecot": OAuthClient("dovecot", False, frozenset(), frozenset(), (), os.path.join(a, "dovecot_client_secret.txt")),
	}


def get_client(env, client_id):
	return registry(env).get(client_id)


def verify_secret(client, presented):
	# Constant-time check of a presented client secret against the client's
	# root-only secret file. Public clients, clients without a secret file,
	# and unreadable/missing files all verify False.
	if client is None or client.is_public or not client.secret_path:
		return False
	if not isinstance(presented, str):
		return False
	try:
		stored = Path(client.secret_path).read_text(encoding="utf-8").strip()
	except OSError:
		return False
	if not stored:
		return False
	return hmac.compare_digest(stored, presented)
