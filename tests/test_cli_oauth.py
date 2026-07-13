# Local unit tests for management/cli.py's OAuth client-credentials auth.
# These run WITHOUT a Mail-in-a-Box: a stdlib stub HTTP server stands in for
# the management daemon's /oauth/token endpoint.
#
#   python3 -m pytest tests/test_cli_oauth.py -q
#
# ruff: noqa: S101, S310, S404, S603

import http.server
import importlib.util
import io
import json
import os
import subprocess
import sys
import threading
import urllib.request
from unittest import mock

import pytest

CLI_PATH = os.path.join(os.path.dirname(__file__), "..", "management", "cli.py")

RESTART_HINT = "The management daemon refused access. The API key file may be out of sync. Try 'service mailinabox restart'."


class _Handler(http.server.BaseHTTPRequestHandler):
	def log_message(self, *a):
		pass

	def _send(self, status, obj):
		resp = json.dumps(obj).encode()
		self.send_response(status)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(resp)))
		self.end_headers()
		self.wfile.write(resp)

	def do_POST(self):
		length = int(self.headers.get("Content-Length", 0))
		body = self.rfile.read(length).decode()
		if self.path == "/oauth/token":
			# The client-credentials contract fields must be present.
			assert "grant_type=client_credentials" in body, body
			assert "client_id=system" in body, body
			assert "scope=admin" in body, body
			if "client_secret=GOODKEY" in body:
				self._send(200, {"access_token": "abc123token", "token_type": "Bearer", "expires_in": 3600, "scope": "admin"})
			else:
				self._send(401, {"error": "invalid_client"})
		elif self.path == "/test/endpoint":
			if self.headers.get("Authorization", "") == "Bearer abc123token":
				self._send(200, {"ok": True})
			else:
				self._send(401, {"ok": False})
		else:
			self.send_response(404)
			self.end_headers()


@pytest.fixture
def stub_daemon():
	server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
	thread = threading.Thread(target=server.serve_forever, daemon=True)
	thread.start()
	try:
		yield f"http://127.0.0.1:{server.server_address[1]}"
	finally:
		server.shutdown()


def _load_cli():
	# cli.py dispatches at import time when len(sys.argv) >= 2; keep it at 1 so
	# importing it just defines functions without making network calls.
	orig_open = open

	def fake_open(path, *a, **kw):
		if path == "/var/lib/mailinabox/api.key":
			return io.StringIO("GOODKEY")
		return orig_open(path, *a, **kw)

	sys.argv = ["cli.py"]
	spec = importlib.util.spec_from_file_location("cli_under_test", CLI_PATH)
	cli_mod = importlib.util.module_from_spec(spec)
	with mock.patch("builtins.open", side_effect=fake_open):
		spec.loader.exec_module(cli_mod)
	return cli_mod


def test_good_key_exchanges_for_bearer_and_authorizes(stub_daemon):
	# A valid api.key is exchanged at /oauth/token for a bearer token, and the
	# installed opener sends that token as Authorization: Bearer on API calls.
	orig_open = open

	def fake_open(path, *a, **kw):
		if path == "/var/lib/mailinabox/api.key":
			return io.StringIO("GOODKEY")
		return orig_open(path, *a, **kw)

	cli_mod = _load_cli()
	with mock.patch("builtins.open", side_effect=fake_open):
		cli_mod.setup_key_auth(stub_daemon)

	resp = urllib.request.urlopen(urllib.request.Request(stub_daemon + "/test/endpoint", data=b"x=1"))
	assert json.loads(resp.read().decode()) == {"ok": True}


def test_stale_key_triggers_restart_hint_and_exit(stub_daemon):
	# An api.key the daemon rejects (invalid_client at /oauth/token) must produce
	# the restart hint and a non-zero exit, not a raw traceback.
	script = (
		"import sys, io, importlib.util\n"
		"from unittest import mock\n"
		"sys.argv = ['cli.py']\n"
		"orig_open = open\n"
		"def fake_open(path, *a, **kw):\n"
		"    if path == '/var/lib/mailinabox/api.key':\n"
		"        return io.StringIO('BADKEY')\n"
		"    return orig_open(path, *a, **kw)\n"
		f"spec = importlib.util.spec_from_file_location('cli_under_test', {CLI_PATH!r})\n"
		"cli_mod = importlib.util.module_from_spec(spec)\n"
		"with mock.patch('builtins.open', side_effect=fake_open):\n"
		"    spec.loader.exec_module(cli_mod)\n"
		f"    cli_mod.setup_key_auth({stub_daemon!r})\n"
	)
	result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
	assert result.returncode != 0, result.stderr
	assert RESTART_HINT in result.stderr, repr(result.stderr)
