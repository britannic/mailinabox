import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
	with open(os.path.join(REPO, rel), encoding="utf-8") as f:
		return f.read()


def test_passkeys_doc_exists_and_has_sections():
	doc = _read("docs/passkeys.md")
	required = [
		"# Passkeys",
		"auth.passkeys",
		"## Enabling and disabling",
		"## Enrolling a passkey",
		"## Signing in with a passkey",
		"## Managing your passkeys",
		"## Security properties",
		"## Verifying on a live box",
		"Sign in with a passkey",
		"webauthn==1.8.0",
	]
	for needle in required:
		assert needle in doc, f"docs/passkeys.md is missing: {needle!r}"


def test_readme_indexes_passkeys():
	readme = _read("docs/README.md")
	assert "[passkeys.md](passkeys.md)" in readme, "docs/README.md index has no passkeys.md row"
	assert "Passkeys" in readme


def test_changelog_mentions_passkeys_under_authentication():
	changelog = _read("CHANGELOG.md")
	in_dev = changelog.split("Version 76", 1)[0]
	assert "Authentication:" in in_dev
	assert "passkey" in in_dev.lower(), "In Development changelog does not mention passkeys"
	assert "auth.passkeys" in in_dev, "changelog does not mention the auth.passkeys flag"
