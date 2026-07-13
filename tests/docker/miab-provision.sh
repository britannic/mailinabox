#!/bin/bash
# First-boot provisioner for the MiaB test container. Runs setup/start.sh once
# (with MIAB_TEST_MODE), then marks completion so later boots are fast no-ops.
set -uo pipefail

MARKER=/root/.miab-provisioned
if [ -f "$MARKER" ]; then
	echo "miab-provision: already provisioned; nothing to do."
	exit 0
fi

echo "miab-provision: starting first-boot Mail-in-a-Box setup (TEST/LAB MODE)..."
cd /root/mailinabox || { echo "miab-provision: /root/mailinabox missing"; exit 1; }

# MIAB_TEST_MODE and the lab defaults come from the image/compose environment.
# start.sh sources setup/test-mode.sh which fills in DISABLE_FIREWALL,
# SKIP_NETWORK_CHECKS, NONINTERACTIVE, PUBLIC_IP, PRIMARY_HOSTNAME.
if setup/start.sh; then
	# Trust the box's self-signed TLS certificate system-wide inside the
	# container. Server-side HTTPS calls the box makes to itself — e.g.
	# Roundcube's OAuth token exchange, which Guzzle/cURL verifies against
	# the system CA store — must pass verification here just as they do in
	# production, where the box holds a real Let's Encrypt certificate.
	source /etc/mailinabox.conf
	if install -m 0644 "$STORAGE_ROOT/ssl/ssl_certificate.pem" /usr/local/share/ca-certificates/miab-selfsigned.crt \
		&& update-ca-certificates; then
		echo "miab-provision: trusted the box's self-signed certificate."
	else
		echo "miab-provision: WARNING: could not trust the box's self-signed certificate; server-side OAuth TLS verification will fail." >&2
	fi
	touch "$MARKER"
	echo "miab-provision: setup completed; box is provisioned."
else
	rc=$?
	echo "miab-provision: setup FAILED (exit $rc). Marker NOT written; will retry on next boot." >&2
	exit "$rc"
fi
