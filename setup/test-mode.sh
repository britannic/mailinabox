# Mail-in-a-Box TEST/LAB MODE helper.
#
# Sourced from setup/start.sh (only when MIAB_TEST_MODE is non-empty), BEFORE
# preflight.sh, so its exports are in effect for the whole run. It ONLY exports
# environment and prints a banner — it never touches services, so it is safe to
# source under `set -euo pipefail`.
#
# It relaxes external-dependency validation that cannot pass in an isolated
# lab (firewall/netfilter, the outbound port-25 probe, Let's Encrypt, the RAM
# floor) and supplies lab-safe defaults for values that cannot be auto-detected
# without real infrastructure. It NEVER relaxes TLS, auth, SASL, fail2ban, the
# CSP, password hashing, or the health checks.

echo >&2
echo "************************************************************" >&2
echo "*  MAIL-IN-A-BOX TEST/LAB MODE - NOT FOR PRODUCTION USE     *" >&2
echo "*  External-dependency validation is being bypassed.       *" >&2
echo "*  Do not expose this instance to an untrusted network.    *" >&2
echo "************************************************************" >&2
echo >&2

# Imply the existing granular escape hatches (only if the operator didn't set them).
export DISABLE_FIREWALL="${DISABLE_FIREWALL:-1}"
export SKIP_NETWORK_CHECKS="${SKIP_NETWORK_CHECKS:-1}"
export NONINTERACTIVE="${NONINTERACTIVE:-1}"

# Supply lab defaults for values that cannot be auto-detected in isolation.
# NOTE: PUBLIC_IP=auto is unsafe here — get_publicip_from_web_service always
# exits 0 (functions.sh ends it with `|| /bin/true`), so `auto` silently
# resolves to an empty string with no egress. Use the container's routable
# private IP instead.
if [ -z "${PUBLIC_IP:-}" ] || [ "${PUBLIC_IP:-}" = "auto" ]; then
	export PUBLIC_IP="$(get_default_privateip 4)"
fi
if [ -z "${PUBLIC_IPV6:-}" ] || [ "${PUBLIC_IPV6:-}" = "auto" ]; then
	# May be empty; the installer treats empty IPv6 as "no IPv6", which is fine.
	export PUBLIC_IPV6="$(get_default_privateip 6)"
fi
if [ -z "${PRIMARY_HOSTNAME:-}" ]; then
	export PRIMARY_HOSTNAME="$(get_default_hostname)"
fi
