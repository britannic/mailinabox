# Fork documentation

This directory holds documentation specific to the **britannic/mailinabox** fork —
features and changes that are not part of upstream
[Mail-in-a-Box](https://mailinabox.email). Upstream's own setup guide lives on the
project website, not in this repository, so anything this fork adds is documented
here instead.

## What this fork adds over upstream

| Feature | Docs |
|---|---|
| **OAuth 2.0 authentication** — a built-in authorization server for the management API, control panel, Roundcube SSO, and IMAP/SMTP; Bearer as the primary API scheme with HTTP Basic demoted to an opt-out legacy path | [oauth.md](oauth.md) |
| **Testing-only Docker container** — a systemd-in-Docker image plus a `MIAB_TEST_MODE` installer flag that relaxes FQDN/public-DNS/VPS-dependent validation, so the full stack can run in an isolated local/lab environment for development and QA (not for production) | [../tests/docker/README.md](../tests/docker/README.md) |

## Related references

- [`api/mailinabox.yml`](../api/mailinabox.yml) — the OpenAPI 3.0 specification for
  the management API, including the OAuth endpoints and security schemes.
- [`CHANGELOG.md`](../CHANGELOG.md) — the release notes; the OAuth work is under the
  **Authentication** heading.
