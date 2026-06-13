# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

Mail-in-a-Box is a self-hosted mail server appliance targeting Ubuntu 22.04 LTS. It configures postfix (SMTP), Dovecot (IMAP), Nextcloud (CardDAV/CalDAV), Roundcube (webmail), NSD4 (DNS), Let's Encrypt (TLS), and other services via idempotent bash setup scripts. The project philosophy is "no user-configurable options" — it just works.

## Development Environment

Install and upgrade instructions are at https://mailinabox.email/. Both use the same command on a fresh Ubuntu 22.04 server:

```bash
curl -s https://mailinabox.email/setup.sh | sudo bash
```

To re-run a single setup component after making changes, SSH into the server and run the relevant script directly:

```bash
sudo setup/mail-postfix.sh      # re-run just the postfix setup
sudo setup/management.sh        # re-run just the management daemon setup
```

## Linting

The project uses `ruff` (configured in `pyproject.toml`). Line length is 320, indent style is tabs, quote style is preserved.

```bash
ruff check .                    # lint
ruff format .                   # format
```

`tools/mail.py` is excluded from ruff.

## Running the Management Daemon Locally

The management daemon (`management/daemon.py`) is a Flask app that listens on port 10222. To run it during development on the server:

```bash
sudo service mailinabox stop
sudo DEBUG=1 management/daemon.py
sudo service mailinabox start   # when done
```

The API is accessible via curl using the root API key:

```bash
curl --user $(</var/lib/mailinabox/api.key): http://localhost:10222/mail/users
```

## Tests

Integration tests require a running Mail-in-a-Box instance and are not unit tests. Install test dependencies first:

```bash
pip install -r tests/pip-requirements.txt   # installs dnspython3
```

Run individual test scripts against a live box:

```bash
tests/test_mail.py hostname emailaddress password     # SMTP/IMAP send-receive test
tests/test_dns.py                                     # DNS resolution checks
tests/test_smtp_server.py                             # SMTP server tests
tests/tls.py                                          # TLS checks
tests/fail2ban.py                                     # fail2ban checks
```

## Architecture

### Setup Layer (`setup/`)

Bash scripts that install and configure all system services. They are idempotent — designed to be run multiple times safely. `setup/start.sh` is the entry point; it sources `setup/functions.sh` (shared utilities) and runs all component scripts. `setup/migrate.py` handles data migrations between versions.

### Management Layer (`management/`)

A Python Flask API daemon (`daemon.py`) that exposes the control panel API on `http://127.0.0.1:10222`. All endpoints require HTTP Basic Auth (API key or username:password + optional TOTP OTP header).

Key modules:
- `daemon.py` — Flask routes, auth middleware, API entry point
- `mailconfig.py` — mail user/alias CRUD backed by SQLite (`mail/users.sqlite`)
- `dns_update.py` — generates and applies NSD4 zone files
- `ssl_certificates.py` — Let's Encrypt provisioning via Certbot
- `web_update.py` — generates nginx configs for hosted domains
- `backup.py` — duplicity-based encrypted backup management
- `status_checks.py` — comprehensive health checks run daily
- `auth.py` — API key and session token authentication
- `mfa.py` — TOTP multi-factor authentication
- `mail_log.py` — postfix log parsing for usage reports
- `utils.py` — shared utilities (environment loading, shell exec); **must not import non-standard modules** as it runs before the virtualenv is set up
- `cli.py` — command-line wrapper around the management HTTP API (requires root, reads `/var/lib/mailinabox/api.key`)

The management daemon runs under a Python virtualenv at `/usr/local/lib/mailinabox/env`. Scripts that run outside the virtualenv (e.g., `mailconfig.py` called from `setup/questions.sh`) can only import stdlib and packages in both contexts.

### Configuration

- `/etc/mailinabox.conf` — KEY=VALUE file with environment variables (`PRIMARY_HOSTNAME`, `STORAGE_ROOT`, `PUBLIC_IP`, etc.), loaded by `utils.load_environment()`
- `STORAGE_ROOT/settings.yaml` — YAML settings (backup config, etc.), loaded by `utils.load_settings()`
- `STORAGE_ROOT` (default `/home/user-data`) — all persistent data: mail, SSL certs, backups, DNS zones, Nextcloud data

### Templates and Config Files (`conf/`, `management/templates/`)

- `conf/` — static nginx, postfix, dovecot, and other service config templates applied by setup scripts
- `management/templates/` — Jinja2 HTML templates for the control panel web UI

### API Specification (`api/`)

OpenAPI 3.0 spec at `api/mailinabox.yml` documents all management API endpoints.

### Daily Automation

`management/daily_tasks.sh` runs at 3am via cron: weekly mail usage reports, backups via `backup.py`, TLS certificate renewal via `ssl_certificates.py -q`, and status change notifications via `status_checks.py --show-changes`. Errors/output are piped to `email_administrator.py` which emails the admin.
