#!/bin/bash
# Build, boot, and smoke-test the MiaB test container. ON-HOST: needs Docker.
# Confirms the box provisions in TEST/LAB MODE and the panel + management
# daemon come up. Run from tests/docker/ .
set -uo pipefail
cd "$(dirname "$0")"

C=miab-test
echo "==> building + starting"
docker compose up -d --build

echo "==> waiting for provisioning (up to 30 min) ..."
deadline=$(( $(date +%s) + 1800 ))
until docker exec "$C" test -f /root/.miab-provisioned 2>/dev/null; do
	if [ "$(date +%s)" -ge "$deadline" ]; then echo "FAIL: provisioning timed out"; docker compose logs --tail=50; exit 1; fi
	sleep 10
done
echo "==> provisioned."

echo "==> assert the lab banner appeared"
if docker compose logs 2>&1 | grep -q "TEST/LAB MODE"; then echo "ok: banner"; else echo "FAIL: banner missing"; exit 1; fi

echo "==> assert the management daemon is listening on 10222"
docker exec "$C" bash -c 'until nc -z 127.0.0.1 10222; do sleep 2; done' || { echo "FAIL: daemon down"; exit 1; }
echo "ok: daemon up"

echo "==> assert the admin user exists"
if docker exec "$C" management/cli.py user 2>/dev/null | grep -q "me@box.test.lan"; then echo "ok: admin user"; else echo "FAIL: admin user missing"; exit 1; fi

echo "==> assert the panel answers HTTPS (self-signed)"
code=$(docker exec "$C" curl -sk -o /dev/null -w '%{http_code}' https://box.test.lan/admin/)
if [ "$code" = "200" ]; then echo "ok: panel 200"; else echo "FAIL: panel returned $code"; exit 1; fi

echo "ALL SMOKE CHECKS PASSED."
