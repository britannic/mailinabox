#!/bin/bash
# End-to-end Roundcube "Sign in with SSO" (OAuth 2.0 authorization code +
# PKCE) test against the MiaB test container. ON-HOST: needs Docker. Run
# after smoke.sh has left the container provisioned.
#
# Drives the whole flow the way a browser would:
#   Roundcube SSO redirect (must carry a PKCE code_challenge)
#   -> daemon authorize form -> credential POST -> callback code exchange
#   -> authenticated Roundcube session -> XOAUTH2/OAUTHBEARER in mail.log.
set -uo pipefail
cd "$(dirname "$0")"

C=miab-test
HOST=box.test.lan
USER_EMAIL=me@box.test.lan
USER_PASS=12345678
JAR=/tmp/sso-test-cookies.txt

dx() { docker exec "$C" "$@"; }
fail() { echo "FAIL: $1"; exit 1; }

dx test -f /root/.miab-provisioned || fail "container not provisioned (run smoke.sh first)"

# Fresh cookie jar, and a marker in mail.log so we only grep lines from this run.
dx rm -f "$JAR"
MARK="sso-test-marker-$$-$(date +%s)"
dx logger -p mail.info "$MARK"

echo "==> 1. Roundcube SSO redirect carries PKCE code_challenge"
AUTH_URL=$(dx curl -sk -c "$JAR" -o /dev/null -w '%{redirect_url}' "https://$HOST/mail/?_task=login&_action=oauth")
case "$AUTH_URL" in
	*code_challenge=*) echo "ok: code_challenge present" ;;
	*) fail "authorize URL missing PKCE code_challenge: $AUTH_URL" ;;
esac
case "$AUTH_URL" in
	*code_challenge_method=S256*) echo "ok: method S256" ;;
	*) fail "authorize URL missing code_challenge_method=S256: $AUTH_URL" ;;
esac

echo "==> 2. authorize endpoint renders the login form (not an error redirect)"
FORM=$(dx curl -sk -b "$JAR" -c "$JAR" "$AUTH_URL")
BINDING=$(printf '%s' "$FORM" | grep -o 'name="binding" value="[^"]*"' | sed 's/.*value="//;s/"$//')
BINDING_EXPIRES=$(printf '%s' "$FORM" | grep -o 'name="binding_expires" value="[^"]*"' | sed 's/.*value="//;s/"$//')
{ [ -n "$BINDING" ] && [ -n "$BINDING_EXPIRES" ]; } || fail "authorize form did not render (binding fields missing)"
echo "ok: authorize form rendered"

echo "==> 3. POST credentials -> 302 to Roundcube callback with a code"
CB_URL=$(dx curl -sk -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' \
	--data-urlencode "email=$USER_EMAIL" \
	--data-urlencode "password=$USER_PASS" \
	--data-urlencode "binding=$BINDING" \
	--data-urlencode "binding_expires=$BINDING_EXPIRES" \
	"$AUTH_URL")
case "$CB_URL" in
	*/mail/index.php/login/oauth\?*code=*) echo "ok: got authorization code" ;;
	*) fail "authorize POST did not redirect to the callback with a code: $CB_URL" ;;
esac

echo "==> 4. callback exchanges the code and lands an authenticated session"
FINAL=$(dx curl -sk -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code} %{url_effective}' -L "$CB_URL")
case "$FINAL" in
	200*_task=mail*) echo "ok: authenticated Roundcube session" ;;
	*) fail "callback did not produce a logged-in session: $FINAL" ;;
esac

echo "==> 5. Dovecot saw a token-based IMAP login"
if dx sh -c "sed -n '/$MARK/,\$p' /var/log/mail.log | grep -Eq 'imap-login.*Login.*method=(XOAUTH2|OAUTHBEARER)'"; then
	echo "ok: XOAUTH2/OAUTHBEARER login in mail.log"
else
	dx sh -c "sed -n '/$MARK/,\$p' /var/log/mail.log | tail -20"
	fail "no XOAUTH2/OAUTHBEARER login found in mail.log after marker"
fi

echo "SSO PASS"
