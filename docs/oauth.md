# OAuth 2.0 authentication

This fork adds a built-in **OAuth 2.0 authorization server** to the Mail-in-a-Box
management daemon. It becomes the primary way to authenticate to the management
API, the control panel, and Roundcube webmail, and it lets mail users
authenticate to IMAP and SMTP submission with `OAUTHBEARER`/`XOAUTH2` access
tokens. HTTP Basic authentication still works everywhere but is now a deprecated,
opt-out legacy path.

> **Scope of this document.** This is the operator-facing guide. The request and
> response shapes of every endpoint are specified in the OpenAPI document
> [`api/mailinabox.yml`](../api/mailinabox.yml) (tag **OAuth**) — this guide links
> to it rather than repeating it.

- [What changed](#what-changed)
- [Endpoints and metadata](#endpoints-and-metadata)
- [Grants, scopes, and PKCE](#grants-scopes-and-pkce)
- [First-party OAuth clients](#first-party-oauth-clients)
- [Control panel login](#control-panel-login)
- [Roundcube single sign-on](#roundcube-single-sign-on)
- [IMAP and SMTP with OAUTHBEARER / XOAUTH2](#imap-and-smtp-with-oauthbearer--xoauth2)
- [Local tooling (the API key)](#local-tooling-the-api-key)
- [Legacy HTTP Basic authentication](#legacy-http-basic-authentication)
- [Token storage and lifetimes](#token-storage-and-lifetimes)
- [Security properties](#security-properties)
- [Verifying on a live box](#verifying-on-a-live-box)

Throughout, `<HOST>` means the box's `PRIMARY_HOSTNAME` (e.g. `box.example.com`)
and `STORAGE_ROOT` defaults to `/home/user-data`.

## What changed

- The management daemon runs a small OAuth 2.0 authorization server. The
  control panel logs in through the authorization endpoint (authorization
  code + PKCE) and calls the management API with `Authorization: Bearer`
  tokens. Panel sessions now survive daemon restarts.
- Mail users can authenticate to IMAP and SMTP submission with
  `OAUTHBEARER`/`XOAUTH2` access tokens. Passwords continue to work everywhere.
- Roundcube offers a **"Sign in with SSO"** button alongside the password login
  form.
- The management API's primary authentication scheme is now
  `Authorization: Bearer`. All HTTP Basic forms (root `api.key`,
  `email:password`, session keys) keep working but are deprecated and can be
  turned off with `auth.legacy_basic: false` in `settings.yaml`.
- Users with TOTP enrolled get multi-factor protection on every token they
  issue — including for mail — when they sign in through OAuth. Password-based
  mail logins remain single-factor.

## Endpoints and metadata

The daemon listens on `127.0.0.1:10222`. nginx proxies `https://<HOST>/admin/`
to it and strips the `/admin` prefix, so the daemon's `/oauth/*` routes are
reachable publicly under `/admin/oauth/*`. The RFC 8414 metadata document is the
one exception — it is served at the site root, without the `/admin` prefix.

| Public URL | Method | Purpose |
|---|---|---|
| `https://<HOST>/admin/oauth/authorize` | GET, POST | Authorization endpoint — renders the login form (GET) and, after validating credentials and a well-formed S256 code challenge, issues an authorization code (POST) |
| `https://<HOST>/admin/oauth/token` | POST | Token endpoint — code exchange, refresh rotation, and `client_credentials` |
| `https://<HOST>/admin/oauth/revoke` | POST | Token revocation (RFC 7009) |
| `https://<HOST>/admin/oauth/userinfo` | GET | The signed-in user's email and privileges (Bearer token, `profile` scope) |
| `https://<HOST>/.well-known/oauth-authorization-server` | GET | Authorization-server metadata (RFC 8414) |

The **introspection** endpoint (RFC 7662) is intentionally *not* public.
`https://<HOST>/admin/oauth/introspect` returns `404`, and the daemon rejects any
introspection request that arrives with an `X-Forwarded-For` header. Only a
direct loopback caller (Dovecot, at `http://127.0.0.1:10222/oauth/introspect`)
can reach it. It is deliberately omitted from the published metadata.

The metadata document advertises the endpoints above, `issuer:
https://<HOST>`, `scopes_supported: [mail, admin, profile]`,
`response_types_supported: [code]`,
`grant_types_supported: [authorization_code, refresh_token, client_credentials]`,
and `code_challenge_methods_supported: [S256]`.

## Grants, scopes, and PKCE

**Grant types:** `authorization_code`, `refresh_token`, and `client_credentials`.

**Scopes:**

| Scope | Grants access to | Held by |
|---|---|---|
| `admin` | the control panel and management API (and local tooling) | `panel`, `system` |
| `mail` | IMAP / SMTP submission (validated by Dovecot introspection) | `roundcube` |
| `profile` | the UserInfo endpoint (email + privileges) | `panel`, `roundcube` |

A user-bound token with the `admin` scope additionally requires the user to hold
the **admin privilege** at request time — losing admin invalidates access
immediately.

**PKCE is mandatory.** Every `authorization_code` client — public *and*
confidential — must use PKCE with `code_challenge_method=S256`. A missing
challenge, or any method other than `S256`, is rejected at the authorization
endpoint and again when the code is redeemed. Plain challenges are never
accepted.

## First-party OAuth clients

Clients are a **fixed, first-party registry defined in code**
([`management/oauth_clients.py`](../management/oauth_clients.py)) — never stored
in a database, and there is no runtime API or CLI to add, list, or remove them.
The `roundcube` and `dovecot` client secrets live in root-only `0600` files that
`setup/oauth.sh` provisions idempotently; the `system` client's secret is the
existing root-only `/var/lib/mailinabox/api.key`. Secrets are compared in
constant time.

| `client_id` | Type | Grants | Scopes | Redirect URI | Secret |
|---|---|---|---|---|---|
| `panel` | public (PKCE) | authorization_code, refresh_token | admin, profile | `https://<HOST>/admin` | none |
| `roundcube` | confidential | authorization_code, refresh_token | mail, profile | `https://<HOST>/mail/index.php/login/oauth` | `STORAGE_ROOT/auth/roundcube_client_secret.txt` |
| `system` | confidential | client_credentials | admin | — | `/var/lib/mailinabox/api.key` |
| `dovecot` | confidential | — (introspection caller only) | — | — | `STORAGE_ROOT/auth/dovecot_client_secret.txt` |

Because the registry is code, **adding a new client** (for example, to let a
third-party desktop or mobile mail client obtain `mail`-scoped tokens — see
[below](#imap-and-smtp-with-oauthbearer--xoauth2)) means editing
`management/oauth_clients.py` and re-running `setup/management.sh`. The redirect
URIs are matched exactly; if you change Roundcube's callback path, update the
`roundcube` entry and `tests/test_auth_oauth.py` in the same commit.

## Control panel login

The control panel is the `panel` client — a public single-page app that uses the
authorization-code + PKCE flow:

1. The panel sends the browser to `https://<HOST>/admin/oauth/authorize` with
   `response_type=code`, `client_id=panel`, `redirect_uri=https://<HOST>/admin`,
   `scope=admin profile`, a random `state`, and an S256 `code_challenge`.
2. The daemon renders a login form. The user submits email + password (plus a
   TOTP code if enrolled).
3. On success the browser is redirected back to `https://<HOST>/admin` with a
   short-lived `code` and the `state`.
4. The panel exchanges the code (with its PKCE `code_verifier`) at
   `/admin/oauth/token` for a Bearer access token and a refresh token, and calls
   the management API with `Authorization: Bearer`.

The panel silently refreshes its access token in the background, so sessions
persist across daemon restarts and last up to the 30-day refresh-chain cap
before a full re-login is required.

## Roundcube single sign-on

Roundcube is configured as a generic OAuth client (`config.inc.php`) pointing at
this box's authorization server:

```php
$config['oauth_provider']      = 'generic';
$config['oauth_provider_name'] = 'Mail-in-a-Box';
$config['oauth_client_id']     = 'roundcube';
$config['oauth_client_secret'] = '…';   // from STORAGE_ROOT/auth/roundcube_client_secret.txt
$config['oauth_auth_uri']      = 'https://<HOST>/admin/oauth/authorize';
$config['oauth_token_uri']     = 'https://<HOST>/admin/oauth/token';
$config['oauth_identity_uri']  = 'https://<HOST>/admin/oauth/userinfo';
$config['oauth_scope']         = 'mail profile';
$config['oauth_login_redirect'] = false;
```

Because `oauth_login_redirect` is `false`, SSO appears as a **"Sign in with
SSO"** button next to the normal password form rather than replacing it.

**TOTP users should prefer the SSO button.** OAuth is the only path that extends
multi-factor protection to mail: tokens are issued behind TOTP, whereas a
password-based mail login remains single-factor.

## IMAP and SMTP with OAUTHBEARER / XOAUTH2

Dovecot is configured with an `oauth2` passdb that validates access tokens by
introspecting them against the daemon on loopback. IMAP (`OAUTHBEARER`/`XOAUTH2`)
and — via the shared Dovecot SASL socket — Postfix submission both accept a
token that:

- is a live, non-expired, non-revoked access token, **and**
- carries the `mail` scope.

Endpoints for a mail client:

- **IMAP:** `<HOST>:993` (IMAPS), SASL mechanism `OAUTHBEARER` (RFC 7628) or
  `XOAUTH2`, over TLS.
- **SMTP submission:** `<HOST>:587` (STARTTLS) or `<HOST>:465` (implicit TLS),
  same mechanisms. SASL auth is enabled only on the submission ports, only over
  TLS, and the authenticated identity must own the `MAIL FROM` address.

Access tokens live one hour, so a mail client must implement OAuth refresh.

> **Third-party mail clients are not wired up out of the box.** The mechanisms
> are enabled and the box's own `roundcube` client is the only first-party
> holder of the `mail` scope. There is no pre-registered general-purpose IMAP
> client (with a client-side redirect URI) in the registry, so a desktop or
> mobile client cannot complete an OAuth flow to obtain a `mail`-scoped token
> today. Enabling that requires adding a public, `mail`-scoped client to
> `management/oauth_clients.py` (see
> [First-party OAuth clients](#first-party-oauth-clients)). Password
> authentication for IMAP/SMTP continues to work for all clients.

## Local tooling (the API key)

`management/cli.py`, `tools/dns_update`, and `tools/web_update` authenticate
themselves. There are **no OAuth subcommands** — instead, each tool reads
`/var/lib/mailinabox/api.key` (root-readable only) and exchanges it for a Bearer
token behind the scenes using the `client_credentials` grant as the `system`
client:

```
POST /admin/oauth/token
grant_type=client_credentials&client_id=system&client_secret=<api.key>&scope=admin
```

It then calls the API with the resulting Bearer token. Because the `api.key` file
*is* the `system` client's secret, and outstanding `system` tokens are revoked
whenever the daemon restarts, key rotation keeps its expected meaning. Run these
tools as root (they need to read `api.key`); a stale key surfaces as an
`invalid_client` error, fixed with `service mailinabox restart`.

You can obtain a token manually for scripting the API:

```bash
curl -s https://<HOST>/admin/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=system \
  -d scope=admin \
  --data-urlencode client_secret="$(sudo cat /var/lib/mailinabox/api.key)"
```

## Legacy HTTP Basic authentication

HTTP Basic is still accepted for backward compatibility but is **deprecated**.
Every successful Basic authentication is logged with a rate-limited deprecation
warning (once per day per credential form), and `Bearer` is always the first
scheme advertised in `WWW-Authenticate`.

Three Basic forms work while legacy Basic is enabled:

- the root `api.key` as the Basic username,
- a session token as the Basic password, and
- `email:password` (with an optional TOTP code in the `X-Auth-Token` header).

**Turning it off.** Set the key in `STORAGE_ROOT/settings.yaml`
(`/home/user-data/settings.yaml`):

```yaml
auth:
  legacy_basic: false
```

`auth.legacy_basic` defaults to `true` (enabled). The value is read live on every
request, so a change takes effect **without restarting** the daemon. The parser
fails open — if `settings.yaml` is missing or unparseable, Basic stays enabled.
A missing file is the normal case and is silent; a warning is logged only when
the file exists but cannot be parsed.

When legacy Basic is off, only OAuth Bearer authentication is accepted. That also
disables the classic control-panel `POST /login` username/password flow and the
`api.key`-as-Basic path, so make sure OAuth login works (see
[Verifying on a live box](#verifying-on-a-live-box)) before disabling it.

## Token storage and lifetimes

Tokens and authorization codes are opaque, high-entropy strings
(`secrets.token_urlsafe(32)`), stored **SHA-256-hashed** in the root-only SQLite
database `STORAGE_ROOT/auth/auth.sqlite` (file `0600`, directory `0700`). Raw
values are never persisted, so a leaked database identifies sessions but can
never be replayed. The database also holds a persistent server secret, so tokens
survive daemon restarts. Expired and revoked rows are purged nightly (kept 7 days
after they stop being live).

| Item | Lifetime |
|---|---|
| Authorization code | 60 seconds, single use |
| Access token | 1 hour |
| Refresh token | 30 days per rotation |
| Refresh chain (from interactive login) | 30 days absolute cap |

## Security properties

- **PKCE (S256) is mandatory** for every authorization-code client.
- **Refresh tokens rotate** on every use. Presenting an already-rotated refresh
  token (token reuse) revokes the **entire token family**; redeeming an already
  used authorization code does the same. This is the RFC 9700 replay defense.
- **Absolute chain cap:** a refresh chain cannot outlive 30 days from the
  original interactive login — after that, the user must sign in again.
- **Password / MFA changes invalidate tokens immediately.** Each user-bound
  token carries a keyed fingerprint of the user's password hash and MFA state;
  changing either (from the control panel, the API, or Roundcube) invalidates all
  of that user's tokens on the next use, across mail and the panel alike.
- **Tokens are stored hashed** (SHA-256); secrets are compared in constant time.
- **Introspection is loopback-only** and 404s if it sees a proxy header.
- **Local tooling uses a secure loopback exchange** — the `system` client's
  credential is the existing root-only `api.key`.

## Verifying on a live box

After an install or upgrade, confirm the OAuth wiring end to end:

1. **Control panel login.** Open `https://<HOST>/admin/`, click **Sign in**, and
   confirm the browser is redirected to `/admin/oauth/authorize` with
   `code_challenge_method=S256`, that you can log in, and that the panel loads.
   (There should be **no** `$ is not defined` errors in the browser console.)
2. **Roundcube SSO.** On `https://<HOST>/mail/`, use the **"Sign in with SSO"**
   button and confirm it returns you signed in. If it fails, the most common
   cause is a Roundcube callback path that no longer matches the `roundcube`
   client's registered `redirect_uri`
   (`https://<HOST>/mail/index.php/login/oauth`).
3. **Mail token path.** Confirm Dovecot can introspect: an OAuth mail login
   should produce exactly one localhost introspection POST (briefly cached by
   Dovecot's auth cache). A missing or mismatched
   `STORAGE_ROOT/auth/dovecot_client_secret.txt` breaks this.
4. **Metadata.** `curl -s https://<HOST>/.well-known/oauth-authorization-server`
   should return the metadata JSON described above.

Only after control-panel and API OAuth login are confirmed working should you
consider setting `auth.legacy_basic: false`.
