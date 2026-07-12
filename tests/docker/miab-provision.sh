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
	touch "$MARKER"
	echo "miab-provision: setup completed; box is provisioned."
else
	rc=$?
	echo "miab-provision: setup FAILED (exit $rc). Marker NOT written; will retry on next boot." >&2
	exit "$rc"
fi
