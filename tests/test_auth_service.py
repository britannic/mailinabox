# Local unit tests for management/auth.py (OAuth Bearer branch, legacy_basic gate,
# make_unauthorized_response, deprecation rate limiting). These run WITHOUT a
# Mail-in-a-Box: the heavy sibling modules (expiringdict, mailconfig, mfa,
# oauth_server) are stubbed in sys.modules before management/auth.py is imported.
# Requires: pip install flask pytest
# Run: python3 -m pytest tests/test_auth_service.py -q
#
# ruff: noqa: ARG002, ARG005, FURB189, RUF043, RUF070, S101

import base64
import importlib
import sys
import types
from pathlib import Path

import pytest

MGMT_DIR = str(Path(__file__).resolve().parent.parent / "management")


class FakeRequest:
	def __init__(self, headers=None):
		self.headers = headers or {}


def basic_auth_header(username, password):
	return "Basic " + base64.b64encode(f"{username}:{password}".encode("ascii")).decode("ascii")


@pytest.fixture
def auth_module(monkeypatch):
	fake_expiringdict = types.ModuleType("expiringdict")
	class ExpiringDict(dict):
		def __init__(self, max_len=None, max_age_seconds=None):
			super().__init__()
	fake_expiringdict.ExpiringDict = ExpiringDict

	fake_mailconfig = types.ModuleType("mailconfig")
	fake_mailconfig.get_mail_password = lambda email, env: "{SHA512-CRYPT}$6$stubhash"
	fake_mailconfig.get_mail_user_privileges = lambda email, env, empty_on_error=False: ["admin"]

	fake_mfa = types.ModuleType("mfa")
	fake_mfa.get_hash_mfa_state = lambda email, env: []
	fake_mfa.validate_auth_mfa = lambda email, request, env: (True, [])

	fake_oauth_server = types.ModuleType("oauth_server")
	fake_oauth_server.validate_bearer = lambda env, raw_token, required_scope, deps: None

	monkeypatch.syspath_prepend(MGMT_DIR)
	for name, mod in [
		("expiringdict", fake_expiringdict),
		("mailconfig", fake_mailconfig),
		("mfa", fake_mfa),
		("oauth_server", fake_oauth_server),
	]:
		monkeypatch.setitem(sys.modules, name, mod)
	sys.modules.pop("auth", None)
	sys.modules.pop("utils", None)
	auth = importlib.import_module("auth")
	yield auth
	sys.modules.pop("auth", None)
	sys.modules.pop("utils", None)


@pytest.fixture
def service(auth_module):
	# Build an AuthService without running __init__ (which reads /var/lib/mailinabox/api.key).
	svc = auth_module.AuthService.__new__(auth_module.AuthService)
	svc.auth_realm = auth_module.DEFAULT_AUTH_REALM
	svc.key = "TESTSYSTEMAPIKEY"
	svc.sessions = {}
	svc.deprecation_log_dates = {}
	return svc


@pytest.fixture
def env(tmp_path):
	return {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "box.example.com"}


# --- make_unauthorized_response / www_authenticate_challenge (fixes the
# daemon.py:106 latent bug; www_authenticate_challenge is the single source of
# truth shared by make_unauthorized_response and daemon.py's
# authorized_personnel_only 401 path) ---

def test_unauthorized_response_advertises_bearer_and_basic_when_legacy_enabled(auth_module, service, env, monkeypatch):
	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {})
	resp = service.make_unauthorized_response(env)
	assert resp.status_code == 401
	assert resp.headers["WWW-Authenticate"] == 'Bearer realm="Mail-in-a-Box Management Server", Basic realm="Mail-in-a-Box Management Server"'


def test_unauthorized_response_bearer_only_when_legacy_disabled(auth_module, service, env, monkeypatch):
	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {"auth": {"legacy_basic": False}})
	www = service.make_unauthorized_response(env).headers["WWW-Authenticate"]
	assert www == 'Bearer realm="Mail-in-a-Box Management Server"'
	assert "Basic" not in www


def test_unauthorized_response_without_env_fails_open_to_both(service):
	www = service.make_unauthorized_response().headers["WWW-Authenticate"]
	assert "Bearer realm=" in www
	assert "Basic realm=" in www


def test_www_authenticate_challenge_gates_basic_on_legacy_basic_setting(auth_module, service, env, monkeypatch):
	# True, and the default when the key is missing, advertise Basic; False excludes
	# it. Bearer is always present. This is the helper both 401 code paths delegate to.
	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {"auth": {"legacy_basic": True}})
	assert 'Basic realm="Mail-in-a-Box Management Server"' in service.www_authenticate_challenge(env)

	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {})
	assert 'Basic realm="Mail-in-a-Box Management Server"' in service.www_authenticate_challenge(env)

	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {"auth": {"legacy_basic": False}})
	challenge = service.www_authenticate_challenge(env)
	assert 'Bearer realm="Mail-in-a-Box Management Server"' in challenge
	assert "Basic realm=" not in challenge


# --- Bearer branch of authenticate() ---

def test_bearer_client_credentials_token_grants_admin(auth_module, service, env):
	auth_module.oauth_server.validate_bearer = lambda e, raw, required_scope, deps: {"user_email": None, "scopes": {"admin"}, "client_id": "system"}
	req = FakeRequest({"Authorization": "Bearer sometoken"})
	assert service.authenticate(req, env) == (None, ["admin"])


def test_bearer_user_token_returns_privileges(auth_module, service, env):
	auth_module.oauth_server.validate_bearer = lambda e, raw, required_scope, deps: {"user_email": "me@example.com", "scopes": {"admin", "profile"}, "client_id": "panel"}
	req = FakeRequest({"Authorization": "Bearer sometoken"})
	assert service.authenticate(req, env) == ("me@example.com", ["admin"])


def test_bearer_invalid_token_raises(auth_module, service, env):
	auth_module.oauth_server.validate_bearer = lambda e, raw, required_scope, deps: None
	req = FakeRequest({"Authorization": "Bearer wrong"})
	with pytest.raises(ValueError, match="Invalid API token."):
		service.authenticate(req, env)


def test_bearer_not_accepted_for_login_only(auth_module, service, env):
	# /login manages legacy sessions only; a Bearer header there must not hit the OAuth path.
	auth_module.oauth_server.validate_bearer = lambda e, raw, required_scope, deps: {"user_email": None, "scopes": {"admin"}, "client_id": "system"}
	req = FakeRequest({"Authorization": "Bearer sometoken"})
	with pytest.raises(ValueError, match="Authorization header invalid."):
		service.authenticate(req, env, login_only=True)


# --- legacy_basic gate (read per-request; fail-open) ---

def test_legacy_basic_disabled_rejects_api_key(auth_module, service, env, monkeypatch):
	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {"auth": {"legacy_basic": False}})
	req = FakeRequest({"Authorization": basic_auth_header(service.key, "")})
	with pytest.raises(ValueError, match="Basic authentication is disabled on this box"):
		service.authenticate(req, env)


def test_legacy_basic_enabled_api_key_still_works(auth_module, service, env, monkeypatch):
	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {})
	req = FakeRequest({"Authorization": basic_auth_header(service.key, "")})
	assert service.authenticate(req, env) == (None, ["admin"])


def test_corrupt_settings_fails_open_with_loud_warning(auth_module, service, env, tmp_path, monkeypatch, capsys):
	# utils.load_settings returns {} on parse errors; the file exists with content.
	(tmp_path / "settings.yaml").write_text("{{{{ not yaml", encoding="utf-8")
	monkeypatch.setattr(auth_module.utils, "load_settings", lambda e: {})
	assert service.is_legacy_basic_enabled(env) is True
	err = capsys.readouterr().err
	assert "could not be parsed" in err
	assert "Failed login attempt" not in err
	# The warning is rate-limited: a second read the same day logs nothing new.
	assert service.is_legacy_basic_enabled(env) is True
	assert "could not be parsed" not in capsys.readouterr().err


# --- deprecation logging (rate-limited once per form per day) ---

def test_deprecation_warning_rate_limited_per_form_per_day(service, capsys):
	service.log_deprecated_basic("api_key")
	service.log_deprecated_basic("api_key")
	err = capsys.readouterr().err
	assert err.count("Mail-in-a-Box Management Daemon: Deprecated Basic authentication used (form=api_key)") == 1
	assert "Failed login attempt" not in err
	service.log_deprecated_basic("user_password")
	err = capsys.readouterr().err
	assert err.count("Mail-in-a-Box Management Daemon: Deprecated Basic authentication used (form=user_password)") == 1
