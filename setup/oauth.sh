#!/bin/bash
#
# OAuth Authorization Server Data
# -------------------------------
#
# Provision the persistent data used by the embedded OAuth 2.0
# authorization server that runs inside the management daemon:
#
#  * STORAGE_ROOT/auth/                            (0700 root:root)
#  * STORAGE_ROOT/auth/auth.sqlite                 (0600; codes/tokens + persistent server secret)
#  * STORAGE_ROOT/auth/dovecot_client_secret.txt   (0600; introspection client credential)
#  * STORAGE_ROOT/auth/roundcube_client_secret.txt (0600; Roundcube SSO client credential)
#
# This script must be sourced BEFORE setup/mail-dovecot.sh:
# setup/mail-users.sh embeds the dovecot secret into
# /etc/dovecot/dovecot-oauth2.conf.ext and setup/webmail.sh embeds the
# roundcube secret into Roundcube's config.inc.php, and both of those
# run before setup/management.sh (which installs the daemon that reads
# the same files at runtime). See the setup ordering constraint in
# docs/superpowers/specs/2026-07-11-oauth-auth-modernization-design.md §13.
#
# Everything here is create-if-missing (idempotent), like the
# users.sqlite provisioning in setup/mail-users.sh. management/oauth_store.py
# is stdlib-only, so the system python3 can run it — the management
# virtualenv does not exist yet on first-time setup.

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

echo "Provisioning OAuth authorization server data..."

# Create the auth directory, root-only. OAuthStore.__init__ would create
# it too, but be explicit so ownership/permissions are corrected even if
# the directory already exists from an interrupted earlier run.
mkdir -p "$STORAGE_ROOT/auth"
chmod 700 "$STORAGE_ROOT/auth"
chown root:root "$STORAGE_ROOT/auth"

# Create the auth database (schema, 0600) and the persistent server
# secret if missing. OAuthStore.__init__ ensures the schema with
# CREATE TABLE IF NOT EXISTS and chmods the DB file to 0600;
# get_server_secret() generates the secret only when absent.
hide_output env STORAGE_ROOT="$STORAGE_ROOT" python3 -c '
import os, sys
sys.path.insert(0, "management")
import oauth_store
env = {"STORAGE_ROOT": os.environ["STORAGE_ROOT"]}
store = oauth_store.OAuthStore(oauth_store.db_path(env))
store.get_server_secret()
'

# Generate the client secret files once. umask 077 makes them 0600
# root:root — the same idiom as the backup secret key in
# setup/management.sh. Consumers strip the trailing newline.
for secret_file in dovecot_client_secret.txt roundcube_client_secret.txt; do
	# -s (not -f): regenerate when the file is missing OR empty, so a 0-byte
	# file left by an interrupted prior run self-heals on re-run. A valid,
	# non-empty secret is never clobbered (rotating it would break the
	# already-configured Dovecot/Roundcube client).
	if [ ! -s "$STORAGE_ROOT/auth/$secret_file" ]; then
		(umask 077; python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$STORAGE_ROOT/auth/$secret_file")
	fi
done
