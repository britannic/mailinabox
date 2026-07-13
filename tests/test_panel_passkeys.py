#!/usr/bin/env python3
# Local render-smoke tests for the panel Passkeys enrollment/management UI (Task 10).
#
# Run: python3 -m pytest tests/test_panel_passkeys.py -q
#
# No live Mail-in-a-Box is required: these render the Jinja templates directly
# with a bare Flask app pointed at management/templates, exactly like the
# authorize-form render assertions in tests/test_oauth_server.py. The WebAuthn
# ceremony itself (navigator.credentials.create) can only be exercised with a
# real authenticator and is covered by the manual runbook, not here.
#
# ruff: noqa: S101

import os
import re
import sys

import pytest
from flask import Flask, render_template

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "management"))

TEMPLATES = os.path.join(os.path.dirname(__file__), "..", "management", "templates")


@pytest.fixture
def app():
	return Flask("panel-test", template_folder=TEMPLATES)


def render_index(app, passkeys_enabled):
	with app.test_request_context("/"):
		return render_template(
			"index.html",
			hostname="box.example.com",
			storage_root="/home/user-data",
			csp_nonce="testnonce",
			passkeys_enabled=passkeys_enabled,
			no_users_exist=False,
			no_admins_exist=False,
			backup_s3_hosts=[],
			csr_country_codes=[],
		)


def test_passkeys_panel_renders_when_enabled(app):
	html = render_index(app, True)
	# Nav entry + panel container are wired into index.html.
	assert 'id="panel_passkeys"' in html
	assert 'href="#passkeys"' in html
	# The enrollment/management controls exist.
	assert 'id="passkey-add-btn"' in html
	assert 'id="passkeys-list"' in html
	assert "function show_passkeys" in html
	assert "function do_add_passkey" in html
	# It drives the WebAuthn ceremony and the Bearer api() endpoints.
	assert "navigator.credentials.create" in html
	assert "/auth/webauthn/register/begin" in html
	assert "/auth/webauthn/register/finish" in html
	assert "/auth/webauthn/credentials" in html
	# CSP: events are wired with addEventListener under the request nonce.
	assert 'nonce="testnonce"' in html
	assert "addEventListener" in html


def test_passkeys_panel_hidden_when_disabled(app):
	html = render_index(app, False)
	assert 'href="#passkeys"' not in html
	assert 'id="passkey-add-btn"' not in html
	assert "function do_add_passkey" not in html
	assert "navigator.credentials.create" not in html


def test_passkeys_template_is_csp_safe():
	with open(os.path.join(TEMPLATES, "passkeys.html"), encoding="utf-8") as f:  # noqa: FURB101
		src = f.read()
	# Nonced inline script, no inline on*= handlers (strict CSP forbids them).
	assert 'nonce="{{ csp_nonce }}"' in src
	assert "addEventListener" in src
	assert re.search(r"""\son\w+\s*=\s*["']""", src) is None
