#!/bin/bash
# Build, boot, and smoke-test the MiaB test container. ON-HOST: needs Docker.
# Confirms the box provisions in TEST/LAB MODE and the panel + management
# daemon come up. Run from tests/docker/ .
set -uo pipefail
cd "$(dirname "$0")"

C=miab-test
echo "==> building + starting"
# Fail fast on a build/start error instead of falling into the 30-min
# provisioning wait and misreporting it as a timeout.
docker compose up -d --build || { echo "FAIL: build/start failed"; exit 1; }

echo "==> waiting for provisioning (up to 30 min) ..."
deadline=$(( $(date +%s) + 1800 ))
until docker exec "$C" test -f /root/.miab-provisioned 2>/dev/null; do
	# Fail fast if the provisioning oneshot died, instead of waiting out the
	# full timeout for a marker that will never be written.
	if docker exec "$C" systemctl is-failed --quiet miab-provision.service 2>/dev/null; then
		echo "FAIL: provisioning service failed"
		docker exec "$C" journalctl -u miab-provision.service --no-pager 2>&1 | tail -40
		exit 1
	fi
	if [ "$(date +%s)" -ge "$deadline" ]; then echo "FAIL: provisioning timed out"; docker compose logs --tail=50; exit 1; fi
	sleep 10
done
echo "==> provisioned."

echo "==> assert the lab banner appeared"
if docker compose logs 2>&1 | grep -q "TEST/LAB MODE"; then echo "ok: banner"; else echo "FAIL: banner missing"; exit 1; fi

echo "==> assert the management daemon is listening on 10222"
# Bounded: if the daemon never binds (crash-loop, port conflict) this must FAIL
# loudly rather than hang the gate forever.
timeout 60 docker exec "$C" bash -c 'until nc -z 127.0.0.1 10222; do sleep 2; done' || { echo "FAIL: daemon not listening on 10222"; docker compose logs --tail=50; exit 1; }
echo "ok: daemon up"

echo "==> assert the admin user exists"
if docker exec "$C" management/cli.py user 2>/dev/null | grep -q "me@box.test.lan"; then echo "ok: admin user"; else echo "FAIL: admin user missing"; exit 1; fi

echo "==> assert the panel answers HTTPS (self-signed)"
code=$(docker exec "$C" curl -sk --max-time 15 -o /dev/null -w '%{http_code}' https://box.test.lan/admin/)
if [ "$code" = "200" ]; then echo "ok: panel 200"; else echo "FAIL: panel returned $code"; exit 1; fi

echo "ALL SMOKE CHECKS PASSED."
