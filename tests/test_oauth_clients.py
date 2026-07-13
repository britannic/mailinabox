# Local unit tests for management/oauth_clients.py. These run WITHOUT a
# Mail-in-a-Box:
#
#   python3 -m pytest tests/test_oauth_clients.py -q
#
# ruff: noqa: S101, S105

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "management"))

import oauth_clients
from oauth_clients import get_client, registry


@pytest.fixture
def env(tmp_path):
	return {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "box.example.com"}


def test_registry_contents(env):
	r = registry(env)
	assert set(r.keys()) == {"panel", "roundcube", "system", "dovecot"}
	a = os.path.join(env["STORAGE_ROOT"], "auth")

	panel = r["panel"]
	assert panel.client_id == "panel"
	assert panel.is_public is True
	assert panel.grant_types == frozenset({"authorization_code", "refresh_token"})
	assert panel.allowed_scopes == frozenset({"admin", "profile"})
	assert panel.redirect_uris == ("https://box.example.com/admin",)
	assert panel.secret_path is None

	roundcube = r["roundcube"]
	assert roundcube.client_id == "roundcube"
	assert roundcube.is_public is False
	assert roundcube.grant_types == frozenset({"authorization_code", "refresh_token"})
	assert roundcube.allowed_scopes == frozenset({"mail", "profile"})
	assert roundcube.redirect_uris == ("https://box.example.com/mail/index.php/login/oauth",)
	assert roundcube.secret_path == os.path.join(a, "roundcube_client_secret.txt")

	system = r["system"]
	assert system.client_id == "system"
	assert system.is_public is False
	assert system.grant_types == frozenset({"client_credentials"})
	assert system.allowed_scopes == frozenset({"admin"})
	assert system.redirect_uris == ()
	assert system.secret_path == "/var/lib/mailinabox/api.key"

	dovecot = r["dovecot"]
	assert dovecot.client_id == "dovecot"
	assert dovecot.is_public is False
	assert dovecot.grant_types == frozenset()
	assert dovecot.allowed_scopes == frozenset()
	assert dovecot.redirect_uris == ()
	assert dovecot.secret_path == os.path.join(a, "dovecot_client_secret.txt")


def test_get_client(env):
	assert get_client(env, "panel").client_id == "panel"
	assert get_client(env, "no-such-client") is None


# --- verify_secret ---


@pytest.fixture
def dovecot_secret(tmp_path):
	path = tmp_path / "auth" / "dovecot_client_secret.txt"
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text("correct-horse-battery\n", encoding="utf-8")  # trailing newline must be stripped
	return "correct-horse-battery"


def test_verify_secret_correct(env, dovecot_secret):
	assert oauth_clients.verify_secret(get_client(env, "dovecot"), dovecot_secret) is True


def test_verify_secret_wrong(env, dovecot_secret):
	client = get_client(env, "dovecot")
	assert oauth_clients.verify_secret(client, dovecot_secret + "x") is False
	assert oauth_clients.verify_secret(client, "wrong-secret") is False
	assert oauth_clients.verify_secret(client, "") is False
	assert oauth_clients.verify_secret(client, None) is False


def test_verify_secret_missing_file(env):
	# roundcube's secret file was never created in this tmp STORAGE_ROOT.
	assert oauth_clients.verify_secret(get_client(env, "roundcube"), "anything") is False


def test_verify_secret_public_client(env):
	# Public clients have no secret; nothing may ever verify against them.
	assert oauth_clients.verify_secret(get_client(env, "panel"), "anything") is False
	assert oauth_clients.verify_secret(None, "anything") is False


def test_verify_secret_uses_compare_digest(env, dovecot_secret, monkeypatch):
	calls = []
	real_compare_digest = oauth_clients.hmac.compare_digest

	def spy(a, b):
		calls.append((a, b))
		return real_compare_digest(a, b)

	monkeypatch.setattr(oauth_clients.hmac, "compare_digest", spy)
	assert oauth_clients.verify_secret(get_client(env, "dovecot"), dovecot_secret) is True
	assert calls == [(dovecot_secret, dovecot_secret)]
