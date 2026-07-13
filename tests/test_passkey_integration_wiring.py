#!/usr/bin/env python3
# Local smoke (no live box) that the passkey integration hooks are wired into
# the on-box integration scripts. tests/test_auth_oauth.py and tests/fail2ban.py
# only run against a live Mail-in-a-Box; this pytest guards that their passkey
# additions stay present, and that the T4 software-authenticator helper exposes
# the interface the HTTPS round-trip relies on. These scripts have top-level
# argv/exit code, so we assert on their SOURCE rather than importing them.
#
# ruff: noqa: S101, PLC0415

import pathlib

TESTS = pathlib.Path(__file__).resolve().parent


def _src(name):
	return (TESTS / name).read_text()


def test_auth_oauth_defines_passkey_roundtrip():
	src = _src("test_auth_oauth.py")
	assert "def run_passkey_tests(" in src
	assert "run_passkey_tests()" in src
	assert "from webauthn_softauth import SoftwareAuthenticator" in src
	for path in (
		"/admin/auth/webauthn/register/begin",
		"/admin/auth/webauthn/register/finish",
		"/admin/auth/webauthn/authenticate/begin",
		"/admin/auth/webauthn/authenticate/finish",
	):
		assert path in src, path


def test_auth_oauth_has_feature_flag_toggle():
	src = _src("test_auth_oauth.py")
	assert 'setdefault("auth", {})["passkeys"]' in src
	assert "return 404" in src


def test_fail2ban_has_passkey_assertion_case():
	src = _src("fail2ban.py")
	assert "/admin/auth/webauthn/authenticate/finish" in src


def test_software_authenticator_interface():
	# The helper T4 commits must expose exactly the methods the round-trip calls.
	from webauthn_softauth import SoftwareAuthenticator
	soft = SoftwareAuthenticator(rp_id="box.example.com", origin="https://box.example.com")
	assert callable(soft.create)
	assert callable(soft.get)
