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

## Releases & tagging

Upstream release tags (`vNN`) don't describe this fork, so fork releases are
tagged **`v<upstream-base>-hrc.<n>`** — for example, `v76-hrc.1` is the first
fork release built on upstream **v76**:

- `v76` records exactly which upstream release the code is based on.
- `-hrc` namespaces the fork, so a fork tag can never collide with an upstream
  tag.
- `.<n>` is an incrementing counter for successive fork releases on the same
  upstream base. When the fork rebases onto a newer upstream, the counter
  restarts (e.g. `v77-hrc.1`).

Tags are **annotated** (`git tag -a`) — the control panel's version check runs
`git describe`, which only sees annotated tags. List them chronologically with
`git tag --sort=v:refname`.

**Install or update a server** with the fork's bootstrap script (its `TAG=`
default is this fork's latest release, not upstream's — using
`mailinabox.email/setup.sh` would install upstream instead):

```bash
curl -fsS https://raw.githubusercontent.com/britannic/mailinabox/master/setup/bootstrap.sh | sudo bash
```

To install a specific release rather than the latest, name the tag explicitly.
The variable must be set on the `bash` side of the pipe (an env var prefixed to
`curl` never reaches the script, and `sudo` strips the environment):

```bash
curl -fsS https://raw.githubusercontent.com/britannic/mailinabox/master/setup/bootstrap.sh | sudo TAG=v76-hrc.2 bash
```

**Cutting a release:**

1. Bump the Ubuntu 22.04 `TAG=` line in [`setup/bootstrap.sh`](../setup/bootstrap.sh)
   to the new tag (it must be the exact tag with nothing after it — the version
   check parses it with a greedy regex).
2. Merge to `master`.
3. Tag it: `git tag -a <new-tag> -m "…" && git push origin <new-tag>`.

The control panel's *"up to date / update available"* status compares the
installed `git describe` tag against the `TAG=` line in this fork's
`setup/bootstrap.sh` on `master`
([`get_latest_miab_version()`](../management/status_checks.py) is repointed at the
fork instead of `mailinabox.email`), so keeping that line current is what drives
the update indicator. If you later host your own `setup.sh`, point that function
at it instead.

## Related references

- [`api/mailinabox.yml`](../api/mailinabox.yml) — the OpenAPI 3.0 specification for
  the management API, including the OAuth endpoints and security schemes.
- [`CHANGELOG.md`](../CHANGELOG.md) — the release notes; the OAuth work is under the
  **Authentication** heading.
