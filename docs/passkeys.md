# Passkeys (WebAuthn) sign-in

This fork adds **passkeys (WebAuthn/FIDO2)** as a first-class, phishing-resistant
browser sign-in method alongside passwords and [OAuth](oauth.md). A passkey is a
cryptographic credential bound to this box's hostname and stored on your device
(a phone, a laptop, or a security key); it cannot be phished or replayed, and a
user-verified passkey counts as multi-factor authentication on its own.

Passkey sign-in is wired into the OAuth **authorize endpoint**, so the control
panel and Roundcube webmail both gain a **"Sign in with a passkey"** button from
one implementation. Passwords remain fully supported everywhere — nothing is
removed, and because a password is always a valid factor, removing all of your
passkeys can never lock you out.

> **Scope of this document.** This is the operator-facing guide. Passkeys build
> directly on the OAuth authorization server documented in [oauth.md](oauth.md) —
> read that first.

- [What passkeys add](#what-passkeys-add)
- [Enabling and disabling](#enabling-and-disabling)
- [Enrolling a passkey](#enrolling-a-passkey)
- [Signing in with a passkey](#signing-in-with-a-passkey)
- [Managing your passkeys](#managing-your-passkeys)
- [Endpoints](#endpoints)
- [Security properties](#security-properties)
- [Verifying on a live box](#verifying-on-a-live-box)

Throughout, `<HOST>` means the box's `PRIMARY_HOSTNAME` (e.g. `box.example.com`)
and `STORAGE_ROOT` defaults to `/home/user-data`.

## What passkeys add

- A signed-in control-panel user can **enroll** one or more passkeys from account
  security settings.
- On supported browsers, a user who has enrolled a passkey can **sign in with it —
  no password** — at the authorize endpoint, for both the control panel and
  Roundcube SSO. Sign-in is *usernameless*: it uses discoverable credentials, so
  you are never asked for an email address first.
- A user-verified passkey **satisfies MFA**, so TOTP is skipped for passkey
  sign-ins. (Password sign-in still requires TOTP exactly as before.)
- Users can **list, rename, and revoke** their own passkeys.
- Enrollment, sign-in, and revocation are audit-logged; failed assertions feed the
  existing fail2ban jail.

**One relying party for the whole box.** The WebAuthn *RP ID* is the box's
`PRIMARY_HOSTNAME`, which covers both `/admin` and `/mail` (the same host). A
passkey enrolled in the control panel therefore works for Roundcube SSO and
vice-versa.

**Who can enroll (phase-1 boundary).** Enrollment happens from the control panel,
which requires the **admin** privilege, so in this phase only admin mailbox users
can enroll a passkey (and then use it at either surface). Ordinary non-admin
webmail users cannot yet self-enroll. This is an accepted boundary, not a security
gap — extending enrollment to non-admin users is future work.

**Not affected.** IMAP, SMTP submission, CalDAV, CardDAV, and ActiveSync are
non-browser protocols and cannot use WebAuthn; they keep password/OAuth
authentication unchanged.

## Enabling and disabling

Passkeys are controlled by the `auth.passkeys` key in
`STORAGE_ROOT/settings.yaml` (`/home/user-data/settings.yaml`), mirroring the
`auth.legacy_basic` flag from the OAuth phase:

```yaml
auth:
  passkeys: false
```

`auth.passkeys` defaults to `true` (enabled). The value is read **live on every
request**, so a change takes effect **without restarting** the daemon. The parser
**fails open** — if `settings.yaml` is missing or unparseable, passkeys stay
enabled; a warning is logged only when the file exists but cannot be parsed (a
missing file is the normal case and is silent).

When `auth.passkeys` is `false`, every passkey endpoint returns `404` and the
control-panel and authorize-page passkey affordances are hidden. Because passwords
remain a valid factor, disabling passkeys is an instantly reversible rollback
lever that can never lock anyone out.

## Enrolling a passkey

1. Sign in to the control panel at `https://<HOST>/admin/` and open the
   **Security / Passkeys** section of account settings.
2. Click **Add a passkey**. Your browser prompts you to create a credential on a
   device (a platform authenticator such as Touch ID / Windows Hello, or a roaming
   security key) and to verify yourself (biometric or PIN — *user verification is
   required*).
3. When the browser finishes, you are prompted for a friendly **name** for the
   passkey (e.g. "MacBook Touch ID"). Names need not be unique.

You can enroll several passkeys (for example one per device). Re-registering an
authenticator you have already enrolled is blocked, so each authenticator maps to
exactly one credential.

## Signing in with a passkey

1. Go to the control-panel login (`https://<HOST>/admin/`) or Roundcube
   (`https://<HOST>/mail/`) and start a login. Both land on the authorize page,
   which shows the normal password form plus a **"Sign in with a passkey"**
   button. The button appears only when passkeys are enabled and your browser
   supports WebAuthn.
2. Click it and choose your passkey when the browser prompts, then verify yourself
   (biometric/PIN). You are **not** asked for an email address — the passkey
   identifies you.
3. On success you are signed in and redirected exactly as a password login would
   be. If you have TOTP enrolled you are **not** asked for a code — the passkey
   already provided the second factor.

If you cancel the prompt or have no passkey on the device, nothing is submitted
and the password form remains usable.

**Roundcube SSO.** The passkey button is presented by the same authorize page that
backs Roundcube's **"Sign in with SSO"** button, so a passkey enrolled in the
panel signs you in to webmail too, with the resulting OAuth code/token
round-tripping through Roundcube unchanged.

## Managing your passkeys

From the **Security / Passkeys** panel section you can:

- **List** your passkeys — each shows its name, when it was created, and when it
  was last used.
- **Rename** a passkey.
- **Revoke** a passkey — it can no longer be used to sign in. Revoking one passkey
  never affects your password or your other passkeys.

You can only see and manage **your own** passkeys; the endpoints are scoped to the
signed-in user and return `404` for any credential that is not yours.

## Endpoints

The daemon listens on `127.0.0.1:10222`. nginx proxies `https://<HOST>/admin/` to
it and strips the `/admin` prefix, so the daemon's `/auth/webauthn/*` routes are
reachable publicly under `/admin/auth/webauthn/*`. The two `begin` endpoints are
`POST` (they store a short-lived challenge row) and are rate-limited.

| Public URL | Method | Auth | Purpose |
|---|---|---|---|
| `.../admin/auth/webauthn/register/begin` | POST | Bearer (`admin`) | Issue registration options; store a `registration` challenge bound to the caller |
| `.../admin/auth/webauthn/register/finish` | POST | Bearer (`admin`) | Verify attestation, store the new credential |
| `.../admin/auth/webauthn/authenticate/begin` | POST | none | Issue authentication options; store an `authentication` challenge (usernameless) |
| `.../admin/auth/webauthn/authenticate/finish` | POST | none | Verify the assertion, resolve the owner from the credential, and issue an OAuth authorization code |
| `.../admin/auth/webauthn/credentials` | GET | Bearer (`admin`) | List the caller's passkeys |
| `.../admin/auth/webauthn/credentials/<id>` | PATCH | Bearer (`admin`) | Rename one of the caller's passkeys |
| `.../admin/auth/webauthn/credentials/<id>` | DELETE | Bearer (`admin`) | Revoke one of the caller's passkeys |

Bearer-authenticated endpoints resolve identity from the access token (scope
`admin`), the same Bearer model the control panel already uses for the management
API (see [oauth.md](oauth.md)). Sign-in (`authenticate/*`) is unauthenticated by
design and reads the OAuth request parameters (`client_id`, `redirect_uri`,
`scope`, `state`, `code_challenge`) only from the **query string**, exactly like
the password path — never from the request body.

## Security properties

- **Origin and RP ID verified on every ceremony** — the client-data origin must be
  `https://<HOST>` and the RP ID must be `<HOST>`. This is what makes passkeys
  phishing-resistant.
- **User verification required** (the flag is checked, not merely requested) on
  both enrollment and sign-in — this is the basis for treating a passkey as MFA and
  skipping TOTP.
- **Challenges are single-use and short-lived** — a cryptographically random
  challenge is stored for 120 seconds, consumed atomically on use, and typed so a
  `registration` challenge can never satisfy an `authentication` (and vice-versa).
  Expired challenges are purged nightly.
- **Identity comes from the credential, never the client** — sign-in resolves your
  email from the stored credential row; the browser never asserts who it is.
- **Mandatory PKCE (S256) + exact `redirect_uri` match** bind a passkey sign-in to
  a valid OAuth request just as strictly as the password path, so an intercepted
  code is useless without the client's `code_verifier`.
- **No user enumeration** — an unknown credential, a wrong user, and a verification
  failure all return the same generic error, and management endpoints `404` on
  cross-user access.
- **Signature-counter clone detection** — a non-increasing counter from an
  authenticator that reports one is rejected and audited.
- **fail2ban** — every failed assertion goes through the existing `log_failed_login`
  path, so the `miab-management-daemon` jail covers passkey abuse with no filter
  changes.
- **Root-only storage** — credentials and challenges live in
  `STORAGE_ROOT/auth/auth.sqlite` (file `0600`, directory `0700`), never in the
  www-data-writable `users.sqlite`. Credential public keys are verification
  material, not secrets.
- **Strict CSP** — the authorize page's passkey script runs under the per-request
  nonce with no inline event handlers.
- **No cryptography change** — passkey support uses the `webauthn==1.8.0` library,
  the newest release compatible with the box-wide `cryptography==37.0.2` pin, so no
  other crypto consumer on the box is affected.
- **Lockout safety** — passwords remain a valid factor, so removing all passkeys
  cannot lock a user out; there is no "last credential" guard.

## Verifying on a live box

After an install or upgrade with `auth.passkeys` enabled:

1. **Enroll.** In the control panel's **Security / Passkeys** section, add a passkey
   with a platform authenticator and (ideally) a roaming security key. Confirm both
   appear in the list.
2. **Panel sign-in.** Sign out, then use **"Sign in with a passkey"** on
   `https://<HOST>/admin/` and confirm the panel loads with no password prompt.
3. **Roundcube SSO.** On `https://<HOST>/mail/`, sign in with the passkey via the
   SSO button and confirm you land in webmail.
4. **TOTP not double-prompted.** With a TOTP-enrolled user, confirm a passkey
   sign-in does **not** ask for a TOTP code (the passkey is the second factor).
5. **Revoke.** Revoke the passkey in the panel and confirm it can no longer sign
   in, while your password still works.

To disable the feature entirely, set `auth.passkeys: false` in
`STORAGE_ROOT/settings.yaml` (no restart needed) and confirm the passkey button
disappears from the login pages.
