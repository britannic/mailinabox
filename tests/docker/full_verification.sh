#!/bin/bash
# Post-upgrade verification for the MiaB test container. ON-HOST: needs
# Docker; run after smoke.sh (provisioning) and sso_login_test.sh (SSO flow).
# Wraps the box-health assertions for the Roundcube 1.7 / PHP 8.2 upgrade so
# future upgrades and troubleshooting can re-run them with one command.
set -uo pipefail
cd "$(dirname "$0")"

C=miab-test
HOST=box.test.lan
PASS=0; FAIL=0

dx() { docker exec "$C" "$@"; }
check() { # <label> <expected> <actual>
	if [ "$2" = "$3" ]; then echo "ok: $1 ($3)"; PASS=$((PASS+1));
	else echo "FAIL: $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}

dx test -f /root/.miab-provisioned || { echo "FAIL: container not provisioned (run smoke.sh first)"; exit 1; }

echo "==> static assets are served as CSS, not HTML (the 1.6 layout bug)"
ct=$(dx curl -sk -o /dev/null -w '%{http_code} %{content_type}' "https://$HOST/mail/static.php/skins/elastic/styles/styles.min.css")
case "$ct" in
	"200 text/css"*) echo "ok: static.php serves CSS"; PASS=$((PASS+1)) ;;
	*) echo "FAIL: static.php asset routing broken ($ct)"; FAIL=$((FAIL+1)) ;;
esac

echo "==> only index.php/static.php are routed to PHP"
check "login page"         200 "$(dx curl -sk -o /dev/null -w '%{http_code}' "https://$HOST/mail/")"
check "installer blocked"  404 "$(dx curl -sk -o /dev/null -w '%{http_code}' "https://$HOST/mail/installer.php")"
check "config unreachable" 404 "$(dx curl -sk -o /dev/null -w '%{http_code}' "https://$HOST/mail/config/config.inc.php")"

echo "==> PHP 8.2 is live"
check "php8.2-fpm active" active "$(dx systemctl is-active php8.2-fpm)"
dx php -v | head -1

echo "==> co-tenants survived the PHP bump"
check "Z-Push answers (auth required)" 401 "$(dx curl -sk -o /dev/null -w '%{http_code}' "https://$HOST/Microsoft-Server-ActiveSync")"
check "Nextcloud login page"           200 "$(dx curl -sk -o /dev/null -w '%{http_code}' -L "https://$HOST/cloud/")"

echo "==> Roundcube error log has no plugin/PHP fatals"
errs=$(dx sh -c 'grep -iE "(persistent_login|html5_notifier|carddav)|PHP Fatal" /var/log/roundcubemail/errors.log 2>/dev/null | tail -10')
if [ -n "$errs" ]; then
	echo "$errs"
	echo "FAIL: plugin/PHP-fatal lines in roundcube errors.log"; FAIL=$((FAIL+1))
else
	echo "ok: no plugin fatals"; PASS=$((PASS+1))
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "VERIFICATION PASS" || exit 1
