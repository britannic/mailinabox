#!/usr/bin/env python3
# Integration tests for the Mail-in-a-Box OAuth 2.0 authorization server.
#
# Usage:
#   tests/test_auth_oauth.py hostname emailaddress password
#   sudo tests/test_auth_oauth.py hostname emailaddress password              (on the box: also runs root-only cases)
#   sudo tests/test_auth_oauth.py hostname emailaddress password --daemon-down
#
# The plain mode exercises the public OAuth surface: the authorization-code
# + PKCE flow, refresh rotation and reuse detection, scope subsetting,
# revocation, introspection isolation, userinfo, security headers, XOAUTH2
# negative cases, and legacy Basic auth. When run as root ON the box it also
# exercises the confidential clients (roundcube, system, dovecot) whose
# secrets live in root-only files, the refresh-chain lifetime cap, and the
# auth.legacy_basic settings toggle (settings.yaml is edited and restored).
#
# --daemon-down (root on the box only): obtains a mail-scoped token, STOPS
# the management daemon, verifies OAuth IMAP fails closed while password
# IMAP keeps working, then restarts the daemon. It is a separate mode
# because stopping the daemon kills the OAuth endpoints every other subtest
# needs. Run it last; it briefly interrupts OAuth logins for all users.
#
# The test account must NOT have TOTP enrolled (this script cannot mint
# TOTP codes); it fails fast with a clear message if it does.
#
# ruff: noqa: S310, S404, S603

import sys, os, json, ssl, time, base64, hashlib, secrets, subprocess, sqlite3
import urllib.request, urllib.parse, urllib.error
import imaplib, smtplib
from html.parser import HTMLParser

if len(sys.argv) < 4:
	print("Usage: tests/test_auth_oauth.py hostname emailaddress password [--daemon-down]")
	sys.exit(1)

host, emailaddress, pw = sys.argv[1:4]
daemon_down_mode = "--daemon-down" in sys.argv[4:]

is_root = hasattr(os, "geteuid") and os.geteuid() == 0
on_box = os.path.exists("/etc/mailinabox.conf")

# The box may be mid-setup with a self-signed certificate; certificate
# validity is tests/tls.py's job, not ours.
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
	def redirect_request(self, req, fp, code, msg, headers, newurl):
		return None  # surface 3xx responses to the caller instead of following them

opener = urllib.request.build_opener(NoRedirectHandler(), urllib.request.HTTPSHandler(context=ssl_ctx))

def http(method, url, data=None, headers=None, basic=None, bearer=None):
	# Returns (status, headers-dict, body-str) and never raises on HTTP error codes.
	body = urllib.parse.urlencode(data).encode("utf8") if isinstance(data, dict) else data
	req = urllib.request.Request(url, body, method=method)
	for k, v in (headers or {}).items():
		req.add_header(k, v)
	if basic:
		req.add_header("Authorization", "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode())
	if bearer:
		req.add_header("Authorization", "Bearer " + bearer)
	try:
		resp = opener.open(req, timeout=15)
		return resp.status, dict(resp.headers), resp.read().decode("utf8", "replace")
	except urllib.error.HTTPError as e:
		return e.code, dict(e.headers), e.read().decode("utf8", "replace")

CHECKS_PASSED = 0

def ok(msg):
	# Numbered so a failure report ("FAIL after NN passing checks") pinpoints
	# exactly which check broke in this long acceptance run.
	global CHECKS_PASSED
	CHECKS_PASSED += 1
	print("OK[%02d]:" % CHECKS_PASSED, msg)

def skip(msg):
	print("SKIP:", msg)

def die(msg):
	print("FAIL (after %d passing checks):" % CHECKS_PASSED, msg)
	sys.exit(1)

def expect(cond, msg):
	if not cond:
		die(msg)
	ok(msg)

class FormFieldParser(HTMLParser):
	# Collects <input name=... value=...> fields from the authorize form.
	def __init__(self):
		super().__init__()
		self.fields = {}
	def handle_starttag(self, tag, attrs):
		if tag == "input":
			a = dict(attrs)
			if a.get("name"):
				self.fields[a["name"]] = a.get("value", "")

def make_pkce():
	verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
	challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
	return verifier, challenge

def authorize(client_id, redirect_uri, scope):
	# Drives the interactive authorization-code + PKCE flow: GET the form,
	# parse the hidden binding fields out of the HTML, POST credentials.
	# Returns (code, verifier).
	verifier, challenge = make_pkce()
	state = secrets.token_hex(16)
	authz_url = "https://%s/admin/oauth/authorize?%s" % (host, urllib.parse.urlencode({
		"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
		"scope": scope, "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}))
	status, hdrs, page = http("GET", authz_url)
	if status != 200:
		die(f"authorize GET for client {client_id} returned {status}, expected the login form (200)")
	p = FormFieldParser()
	p.feed(page)
	if "binding" not in p.fields or "binding_expires" not in p.fields:
		die("authorize form is missing the hidden binding/binding_expires fields")
	form = {"email": emailaddress, "password": pw, "binding": p.fields["binding"], "binding_expires": p.fields["binding_expires"]}
	status, hdrs, page = http("POST", authz_url, form)
	if status == 200 and "totp" in page.lower():
		die("the test account appears to have TOTP enrolled; use a test account without TOTP")
	if status != 302:
		die(f"authorize POST for client {client_id} returned {status}, expected a 302 redirect")
	loc = hdrs.get("Location", "")
	if not loc.startswith(redirect_uri):
		die(f"authorize redirected to {loc}, expected it to start with {redirect_uri}")
	qs = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
	if qs.get("state", [None])[0] != state:
		die("state was not echoed back faithfully on the authorize redirect")
	return qs["code"][0], verifier

def token_post(data, basic=None):
	status, hdrs, body = http("POST", f"https://{host}/admin/oauth/token", data, basic=basic)
	try:
		payload = json.loads(body)
	except ValueError:
		payload = {}
	return status, payload

def panel_login():
	code, verifier = authorize("panel", f"https://{host}/admin", "admin profile")
	status, tok = token_post({"grant_type": "authorization_code", "client_id": "panel", "code": code, "redirect_uri": f"https://{host}/admin", "code_verifier": verifier})
	if status != 200 or "access_token" not in tok or "refresh_token" not in tok:
		die(f"panel code exchange failed: HTTP {status} {tok}")
	return tok

def load_box_env():
	env = {}
	with open("/etc/mailinabox.conf") as f:
		for line in f:
			if "=" in line:
				k, v = line.strip().split("=", 1)
				env[k] = v
	return env

def read_secret(path):
	with open(path) as f:
		return f.read().strip()

def get_mail_token():
	# Confidential roundcube client: code flow + PKCE + client_secret_post.
	# Requires root on the box (reads the roundcube client secret file).
	env = load_box_env()
	secret = read_secret(os.path.join(env["STORAGE_ROOT"], "auth", "roundcube_client_secret.txt"))
	redirect_uri = f"https://{host}/mail/index.php/login/oauth"
	code, verifier = authorize("roundcube", redirect_uri, "mail profile")
	status, tok = token_post({"grant_type": "authorization_code", "client_id": "roundcube", "client_secret": secret, "code": code, "redirect_uri": redirect_uri, "code_verifier": verifier})
	if status != 200 or "access_token" not in tok:
		die(f"roundcube code exchange failed: HTTP {status} {tok}")
	return tok

def imap_xoauth2(user, token):
	# Returns True when IMAP accepts the token, False when it rejects it.
	M = imaplib.IMAP4_SSL(host, ssl_context=ssl_ctx)
	try:
		M.authenticate("XOAUTH2", lambda challenge: f"user={user}\x01auth=Bearer {token}\x01\x01".encode())
	except imaplib.IMAP4.error:
		try:
			M.shutdown()
		except OSError:
			pass
		return False
	M.logout()
	return True

def smtp_xoauth2(user, token):
	# Returns True when SMTP submission (587) accepts the token.
	server = smtplib.SMTP(host, 587, timeout=15)
	try:
		server.starttls(context=ssl_ctx)
		server.ehlo_or_helo_if_needed()
		server.auth("XOAUTH2", lambda challenge=None: f"user={user}\x01auth=Bearer {token}\x01\x01")
	except smtplib.SMTPException:
		return False
	finally:
		try:
			server.quit()
		except smtplib.SMTPException:
			pass
	return True

def imap_password(user, password):
	M = imaplib.IMAP4_SSL(host, ssl_context=ssl_ctx)
	try:
		M.login(user, password)
	except imaplib.IMAP4.error:
		return False
	M.logout()
	return True

def run_public_tests():
	# 1. Security headers on the panel (compensating controls for web-storage tokens).
	status, hdrs, _body = http("GET", f"https://{host}/admin")
	csp = hdrs.get("Content-Security-Policy", "")
	expect("script-src 'self'" in csp and "object-src 'none'" in csp and "base-uri 'none'" in csp, "panel sends the strict Content-Security-Policy")
	expect(hdrs.get("Referrer-Policy") == "same-origin", "panel sends Referrer-Policy: same-origin")

	# 2. Introspection is unreachable from the public interface.
	status, _hdrs, _body = http("POST", f"https://{host}/admin/oauth/introspect", {"token": "x"})
	expect(status == 404, "public POST /admin/oauth/introspect returns 404")
	status, _hdrs, _body = http("GET", f"https://{host}/admin/oauth/introspect")
	expect(status == 404, "public GET /admin/oauth/introspect returns 404")

	# 3. RFC 8414 metadata.
	status, _hdrs, body = http("GET", f"https://{host}/.well-known/oauth-authorization-server")
	meta = json.loads(body) if status == 200 else {}
	expect(status == 200 and meta.get("issuer") == f"https://{host}" and meta.get("token_endpoint") == f"https://{host}/admin/oauth/token", "authorization-server metadata is served with the right endpoints")

	# 4. Panel authorization-code + PKCE flow (state echo is asserted inside authorize()).
	tok = panel_login()
	access, refresh = tok["access_token"], tok["refresh_token"]
	ok("panel authorization-code + PKCE flow issues access and refresh tokens")

	# 5. userinfo (scope profile).
	status, _hdrs, body = http("GET", f"https://{host}/admin/oauth/userinfo", bearer=access)
	info = json.loads(body) if status == 200 else {}
	expect(status == 200 and info.get("email") == emailaddress and info.get("sub") == emailaddress and "privileges" in info, "userinfo returns sub, email and privileges for a profile-scoped token")

	# 6. Bearer access to the management API (meaningful for admin accounts only).
	if "admin" in info.get("privileges", []):
		status, _hdrs, _body = http("GET", f"https://{host}/admin/mail/users?format=json", bearer=access)
		expect(status == 200, "admin API accepts the panel Bearer token")
	else:
		skip("admin API positive test — the test account has no admin privilege")

	# 7. Garbage Bearer tokens are rejected with a Bearer challenge.
	status, hdrs, _body = http("GET", f"https://{host}/admin/mail/users?format=json", bearer="not-a-real-token")
	expect(status == 401 and "Bearer" in hdrs.get("WWW-Authenticate", ""), "invalid Bearer token gets 401 with WWW-Authenticate: Bearer")

	# 8. Scope broadening on refresh is rejected.
	status, resp = token_post({"grant_type": "refresh_token", "client_id": "panel", "refresh_token": refresh, "scope": "admin profile mail"})
	expect(status == 400 and resp.get("error") == "invalid_scope", "refresh with a broadened scope fails with invalid_scope")

	# 9. Refresh rotation.
	status, rotated = token_post({"grant_type": "refresh_token", "client_id": "panel", "refresh_token": refresh})
	expect(status == 200 and rotated.get("refresh_token") not in (None, refresh), "refresh rotates the refresh token")

	# 10. Reuse of the rotated-out refresh token revokes the whole family.
	status, resp = token_post({"grant_type": "refresh_token", "client_id": "panel", "refresh_token": refresh})
	expect(status == 400 and resp.get("error") == "invalid_grant", "reusing a rotated-out refresh token fails with invalid_grant")
	status, resp = token_post({"grant_type": "refresh_token", "client_id": "panel", "refresh_token": rotated["refresh_token"]})
	expect(status == 400 and resp.get("error") == "invalid_grant", "reuse detection revoked the whole refresh-token family")

	# 11. Revocation (public client revoking its own token, no secret).
	tok2 = panel_login()
	status, _hdrs, _body = http("POST", f"https://{host}/admin/oauth/revoke", {"token": tok2["refresh_token"], "client_id": "panel"})
	expect(status == 200, "revocation endpoint accepts the panel's own refresh token")
	status, resp = token_post({"grant_type": "refresh_token", "client_id": "panel", "refresh_token": tok2["refresh_token"]})
	expect(status == 400 and resp.get("error") == "invalid_grant", "a revoked refresh token can no longer be used")

	# 12. Client credentials may not travel in the query string.
	status, _hdrs, _body = http("POST", f"https://{host}/admin/oauth/token?client_id=system&client_secret=xyz", {"grant_type": "client_credentials"})
	expect(status == 400, "client credentials in the query string are rejected")

	# 13. XOAUTH2 negative cases (need no server-side secrets).
	tok3 = panel_login()
	expect(not imap_xoauth2(emailaddress, tok3["access_token"]), "IMAP rejects a panel token (no mail scope)")
	expect(not imap_xoauth2(emailaddress, "garbagetoken"), "IMAP rejects a garbage XOAUTH2 token")
	expect(not smtp_xoauth2(emailaddress, "garbagetoken"), "SMTP submission rejects a garbage XOAUTH2 token")

	# 14. Passwords still work everywhere (legacy default).
	expect(imap_password(emailaddress, pw), "IMAP password (PLAIN) login still works")
	status, _hdrs, _body = http("POST", f"https://{host}/admin/login", basic=(emailaddress, pw))
	expect(status == 200, "legacy Basic /login still works by default")

	# 15. A password change invalidates existing tokens (the password_state
	# fingerprint — the compensating control for Roundcube's out-of-band, direct-
	# SQL password writes). Uses only the provided credentials, so it stays in the
	# main run, and is kept LAST so its brief password change can never disturb the
	# earlier checks. It needs an admin account to drive the password API and
	# legacy Basic (default on) to authenticate the change/restore; SKIPs otherwise.
	tok4 = panel_login()
	old_token = tok4["access_token"]
	status, _hdrs, body = http("GET", f"https://{host}/admin/oauth/userinfo", bearer=old_token)
	info = json.loads(body) if status == 200 else {}
	expect(status == 200, "a fresh token is accepted at userinfo before the password change")
	if "admin" not in info.get("privileges", []):
		skip("password-change token invalidation — the test account has no admin privilege to drive the password API")
	else:
		temp_pw = pw + "_pwchg_tmp"
		status, hdrs, _body = http("POST", f"https://{host}/admin/mail/users/password", {"email": emailaddress, "password": temp_pw}, basic=(emailaddress, pw))
		challenge = hdrs.get("WWW-Authenticate", "")
		if status == 401 and "Bearer" in challenge and "Basic" not in challenge:
			skip("password-change token invalidation — legacy Basic is disabled, cannot drive the password API with a password")
		elif status != 200:
			die(f"changing the test account password failed: HTTP {status}")
		else:
			# The account password is now temp_pw; the restore MUST always run,
			# even if the assertion below fails (die() raises SystemExit, which
			# the finally still executes).
			try:
				status, _hdrs, _body = http("GET", f"https://{host}/admin/oauth/userinfo", bearer=old_token)
				expect(status == 401, "the pre-change Bearer token is rejected after the password changes (password_state fingerprint)")
			finally:
				# The original password no longer authenticates, so restore using temp_pw.
				status, _hdrs, _body = http("POST", f"https://{host}/admin/mail/users/password", {"email": emailaddress, "password": pw}, basic=(emailaddress, temp_pw))
				if status != 200:
					print(f"FAIL: could not restore password for {emailaddress}; it is currently set to: {temp_pw}", file=sys.stderr)
					die(f"could not restore the test account password (HTTP {status}); it is currently set to: {temp_pw}")
				ok("test account password restored to the original after the invalidation check")

def run_root_tests():
	env = load_box_env()

	# R1. client_credentials with the live api.key (system client).
	api_key = read_secret("/var/lib/mailinabox/api.key")
	status, tok = token_post({"grant_type": "client_credentials", "client_id": "system", "client_secret": api_key, "scope": "admin"})
	expect(status == 200 and "access_token" in tok and "refresh_token" not in tok, "client_credentials grant issues an access token and no refresh token")
	status, _hdrs, _body = http("GET", f"https://{host}/admin/mail/users?format=json", bearer=tok["access_token"])
	expect(status == 200, "system-client access token reaches the admin API")

	# R1b. Regression (whole-branch review critical): the local root tooling
	# (cli.py, tools/dns_update, tools/web_update) reaches the token endpoint
	# DIRECTLY on 127.0.0.1:10222 over plain http, bypassing nginx and its
	# X-Forwarded-Proto header. The daemon must treat this no-proxy-header loopback
	# request as a secure transport so Authlib does not reject the grant with
	# insecure_transport (which would abort setup/start.sh and break every install).
	status, _hdrs, body = http("POST", "http://127.0.0.1:10222/oauth/token", {"grant_type": "client_credentials", "client_id": "system", "client_secret": api_key, "scope": "admin"})
	try:
		direct = json.loads(body)
	except ValueError:
		direct = {}
	expect(status == 200 and "access_token" in direct, "client_credentials over the direct http://127.0.0.1:10222 loopback path (the tooling path) issues a token")

	# R2. A wrong system secret fails with a plain RFC 6749 error.
	status, resp = token_post({"grant_type": "client_credentials", "client_id": "system", "client_secret": "0" * 32})
	expect(status in (400, 401) and resp.get("error") == "invalid_client", "a wrong system client secret fails with invalid_client")

	# R3. Roundcube confidential-client flow; the token is mail-scoped, not admin.
	rc = get_mail_token()
	mail_access = rc["access_token"]
	ok("roundcube confidential client completes the code flow")
	status, _hdrs, _body = http("GET", f"https://{host}/admin/mail/users?format=json", bearer=mail_access)
	expect(status in (401, 403), "admin API rejects a mail-scoped (roundcube) token")

	# R4. XOAUTH2 positive: IMAP and SMTP submission with the mail token.
	expect(imap_xoauth2(emailaddress, mail_access), "IMAP XOAUTH2 accepts the mail-scoped access token")
	expect(smtp_xoauth2(emailaddress, mail_access), "SMTP submission XOAUTH2 accepts the mail-scoped access token")

	# R5. Introspection from localhost with the dovecot credential.
	dovecot_secret = read_secret(os.path.join(env["STORAGE_ROOT"], "auth", "dovecot_client_secret.txt"))
	status, _hdrs, body = http("POST", "http://127.0.0.1:10222/oauth/introspect", {"token": mail_access}, basic=("dovecot", dovecot_secret))
	r = json.loads(body)
	expect(status == 200 and r.get("active") is True and r.get("username") == emailaddress and "mail" in r.get("scope", "").split(), "introspection returns active:true with username and mail scope for a valid token")
	status, _hdrs, body = http("POST", "http://127.0.0.1:10222/oauth/introspect", {"token": "garbage"}, basic=("dovecot", dovecot_secret))
	expect(status == 200 and json.loads(body) == {"active": False}, "introspection returns exactly {'active': false} for a bad token")
	status, _hdrs, body = http("POST", "http://127.0.0.1:10222/oauth/introspect", {"token": mail_access}, basic=("dovecot", "wrongsecret"))
	expect(status == 200 and json.loads(body) == {"active": False}, "introspection with a wrong dovecot secret returns {'active': false}")
	# A request with NO client credentials at all must be indistinguishable from a
	# wrong-secret one: exactly {'active': false}, not a 401 that would reveal the
	# difference between "unauthenticated" and "authenticated-but-bad-token".
	status, _hdrs, body = http("POST", "http://127.0.0.1:10222/oauth/introspect", {"token": mail_access})
	expect(status == 200 and json.loads(body) == {"active": False}, "introspection with no client credentials returns {'active': false}")

	# R6. Refresh-chain lifetime cap, asserted clock-independently from stored token metadata.
	con = sqlite3.connect(os.path.join(env["STORAGE_ROOT"], "auth", "auth.sqlite"))
	n = con.execute("SELECT COUNT(*) FROM oauth_tokens WHERE token_type='refresh' AND auth_time IS NOT NULL AND expires_at > auth_time + 30*86400").fetchone()[0]
	con.close()
	expect(n == 0, "no refresh token expires later than auth_time + 30 days (chain cap)")

	# R7. auth.legacy_basic: false disables Basic user auth but never OAuth client auth.
	# settings.yaml is edited via the management venv (rtyaml) and restored afterwards.
	settings_path = os.path.join(env["STORAGE_ROOT"], "settings.yaml")
	with open(settings_path, "rb") as f:
		original_settings = f.read()
	set_legacy = 'import sys, rtyaml\np = sys.argv[1]\nwith open(p) as f:\n\tcfg = rtyaml.load(f) or {}\ncfg.setdefault("auth", {})["legacy_basic"] = (sys.argv[2] == "true")\nwith open(p, "w") as f:\n\tf.write(rtyaml.dump(cfg))\n'
	try:
		subprocess.check_call(["/usr/local/lib/mailinabox/env/bin/python", "-c", set_legacy, settings_path, "false"])
		status, _hdrs, _body = http("GET", f"https://{host}/admin/mail/users?format=json", basic=(emailaddress, pw))
		expect(status == 401, "auth.legacy_basic: false rejects Basic user auth on API routes")
		status, tok = token_post({"grant_type": "client_credentials", "client_id": "system", "client_secret": api_key, "scope": "admin"})
		expect(status == 200 and "access_token" in tok, "OAuth client auth (client_secret_post) is exempt from the legacy_basic switch")
	finally:
		with open(settings_path, "wb") as f:
			f.write(original_settings)
	status, _hdrs, _body = http("POST", f"https://{host}/admin/login", basic=(emailaddress, pw))
	expect(status == 200, "legacy Basic works again after restoring settings.yaml")

def run_daemon_down():
	# Separate mode: stopping the daemon kills the OAuth endpoints that
	# every other subtest needs, so the token is fetched first, then the
	# daemon is stopped, checked against, and restarted.
	print("Daemon-down mode: OAuth IMAP must fail closed while password IMAP keeps working.")
	rc = get_mail_token()
	mail_access = rc["access_token"]
	expect(imap_xoauth2(emailaddress, mail_access), "sanity: XOAUTH2 works while the daemon is up")
	print("Stopping the management daemon...")
	subprocess.check_call(["/usr/sbin/service", "mailinabox", "stop"])
	try:
		time.sleep(3)
		expect(not imap_xoauth2(emailaddress, mail_access), "XOAUTH2 IMAP fails while the daemon is down")
		expect(imap_password(emailaddress, pw), "password IMAP still works while the daemon is down")
	finally:
		print("Restarting the management daemon...")
		subprocess.check_call(["/usr/sbin/service", "mailinabox", "start"])
	print("Daemon-down test passed.")

if __name__ == "__main__":
	if daemon_down_mode:
		if not (is_root and on_box):
			die("--daemon-down must be run as root on the box itself")
		run_daemon_down()
	else:
		run_public_tests()
		if is_root and on_box:
			run_root_tests()
		else:
			skip("root-only cases (roundcube/system/dovecot clients, chain cap, legacy_basic toggle) — rerun as root on the box")
		print("All OAuth tests passed.")
