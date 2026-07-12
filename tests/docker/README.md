# Mail-in-a-Box — Testing-Only Docker Container

**⚠️ TESTING ONLY. NOT FOR PRODUCTION. Do not expose this container to an
untrusted network.** It bypasses external-dependency validation (real FQDN,
public DNS, rDNS, Let's Encrypt, the outbound port-25 probe, the firewall) so
the full stack can run in an isolated lab. It does **not** weaken TLS, auth,
SASL, fail2ban, the CSP, or password storage — the security posture stays real
so QA is meaningful.

## Quick start

```bash
cd tests/docker
docker compose up -d --build      # first boot provisions the full stack (several minutes)
docker compose logs -f            # watch setup; you'll see the TEST/LAB MODE banner
```

Add the box hostname to your host's `/etc/hosts` (required — the OAuth
`redirect_uri` is an exact match on the hostname):

```
127.0.0.1 box.test.lan
```

Then:
- Control panel: <https://box.test.lan/admin> (self-signed cert → accept the warning)
- Webmail (Roundcube): <https://box.test.lan/mail>
- Admin login: `me@box.test.lan` / `12345678` (auto-created, non-TOTP)

## What `MIAB_TEST_MODE` does

The container sets `MIAB_TEST_MODE=1`, which activates `setup/test-mode.sh`.
It implies `DISABLE_FIREWALL=1`, `SKIP_NETWORK_CHECKS=1`, `NONINTERACTIVE=1`,
supplies lab defaults for `PUBLIC_IP`/`PRIMARY_HOSTNAME`, skips the Let's
Encrypt account registration, and relaxes the RAM floor. Nothing else changes.
On a real box with the flag unset, setup behaves exactly as upstream.

## Running the OAuth on-box runbook

The box is already provisioned, so start at the runbook's verification steps:

```bash
docker exec -it miab-test bash
tests/test_auth_oauth.py box.test.lan me@box.test.lan 12345678
tests/fail2ban.py box.test.lan
```

Browser gates (Roundcube SSO, panel login, CSP/Munin console sweep) are done
from your host browser against `https://box.test.lan/...`.

## Expected red health checks

The panel's Status Checks page will show failures for public DNS, rDNS/PTR,
blocklists, and mail deliverability — **expected** for an isolated box with no
real public IP or DNS delegation. They do not affect the OAuth/mail/auth
functionality you're testing.

## Systemd-in-Docker requirements

The compose file runs the container `privileged` with `cgroup: host` and a
tmpfs `/run` — the simplest configuration that works across Docker/Podman and
cgroup v1/v2 for a throwaway box. This is a testing tradeoff; do not use it for
anything but local/lab QA.

## Smoke test

```bash
cd tests/docker && ./smoke.sh   # build, boot, assert the box comes up
```

## Reset

```bash
docker compose down            # stop + remove (userdata volume persists only if you enabled it)
docker compose up -d --build   # fresh box
```
