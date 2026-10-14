# Passkeys Demo — authentication hardening

This repository demonstrates passkey (WebAuthn) registration and login using Express, `@simplewebauthn/server`, Angular, and `@ownid/webauthn`.

## Security changes

- Username enrollment is create-only: the existing account's credential cannot be replaced through the registration endpoint.
- WebAuthn challenges come from a CSPRNG, expire after five minutes, are scoped to login/registration, and are consumed once before verification.
- Registration and authentication both require user verification and validate expected RP ID, challenge, and origin.
- Credential public keys and signature counters are stored on disk with restrictive permissions, and corrupt state fails closed.
- Login creates an opaque, random server-side session with an eight-hour TTL in a HttpOnly, SameSite=Strict cookie; `POST /logout` revokes it. `GET /session` reports the current identity.
- Browser POST requests require same-origin Fetch Metadata when available, and origin matching; production requires an Origin header.
- Rate limits and request-body limits add basic protection. Secrets and local user data are excluded from Git.

## Development

```sh
npm ci
npm test
npm run build:frontend
npm start
```

Defaults: `APP_ORIGIN=http://localhost:3000`, `RP_ID=localhost`, `PORT=3000`; see `.env.example`. The backend serves the built Angular frontend from port 3000. For production, configure `NODE_ENV=production`, an HTTPS `APP_ORIGIN`, and matching `RP_ID`.

Registration routes are `POST /register/start` and `POST /register/finish`; login routes are `POST /login/start` and `POST /login/finish`. The finish routes expect `{ "username": "...", "data": <WebAuthn response> }`. `GET /session` checks the browser session and `POST /logout` ends it.

## Limits — do not deploy this demo unchanged as a multi-tenant service

The user registry is a local JSON file. Session, challenge, and rate-limit stores are in memory and **do not support multi-instance or serverless deployment**. Active sessions are lost on restart; no cross-node revocation is implemented. For production, replace them with transactional and durable shared stores, add first-party provisioning controls, enforce registration eligibility, per-identity abuse controls, observability, backup procedures, credential recovery/rotation, and test real-device authenticator compatibility. Public username enrollment remains open by design; it is unsuitable for organization-controlled identities.

Node unit tests cover low-level storage and challenge/session behavior. Real browser WebAuthn registration/login, full HTTP integration testing, npm dependency installation, and production deployment are not asserted to have passed until corresponding CI and integration checks complete.

**Important:** The fix protects existing usernames from overwrite; it does not establish trusted identity ownership for a new username, nor implement enterprise SSO/OIDC/GCP federation or Dune-Sub control-plane identity.


## Physical-device passkey acceptance

A browser-native WebAuthn acceptance runner is included under [acceptance/README.md](acceptance/README.md). It uses real `navigator.credentials.create/get` calls and exports sanitized, integrity-hashed, **operator-attested** JSON evidence; it never substitutes a virtual authenticator for hardware.

On an isolated HTTPS staging deployment, set `APP_ENABLE_ACCEPTANCE=1` and open `/acceptance` on the real phone, laptop or security-key host. The runner is disabled by default. Execute all required scenarios in order (registration, duplicate enrollment, login, replay rejection, cookie session after browser reload, logout, user-cancelled authenticator request, server restart persistence, and observed biometric/PIN user verification).

Validate exports locally with `node acceptance/verify-evidence.js evidence.json`. Run the release diversity gate with `node acceptance/verify-evidence.js --release mobile.json desktop.json`. CI tests conversion/evidence logic but **cannot claim physical-device PASS**. Do not mark a release ready based on CI alone.
