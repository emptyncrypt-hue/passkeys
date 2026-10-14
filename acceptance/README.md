# Real-device WebAuthn acceptance (manual-in-the-loop, browser-executed)

**Purpose:** Produce reproducible, privacy-minimized acceptance evidence for actual platform authenticators (Face ID, Touch ID, device PIN / Windows Hello), hardware security keys, and, where supported, synced passkeys. This is **not** a substitute for FIDO Metadata Service device attestation, MDM posture, hardware enrollment verification, or physical custody verification. Evidence is self-attested by the operator; a SHA-256 checksum detects edits but is not a digital signature or independent proof.

## Set up a disposable isolated staging instance

1. Deploy the security-hardening PR on **one** Node process with persistent `AUTH_STORE_PATH`, a working browser build and working HTTPS ingress. Use disposable identities; never production accounts or data. Do not publicly expose an acceptance runner unless deliberately restricted to trusted testers.
2. Set `APP_ENABLE_ACCEPTANCE=1`, `APP_ORIGIN=https://<your-test-host>`, `RP_ID=<your-test-host or parent domain>`, and `NODE_ENV=production` (with TLS termination at ingress). Launch `npm start`. For a local laptop test only, `APP_ORIGIN=http://localhost:3000` is allowed with `NODE_ENV` unset; **do not use localhost as a remote phone URL**.
3. From the physical device/browser, open `https://<your-test-host>/acceptance`, confirm the expected TLS origin, and follow the ordered test cases. The runner is served only when `APP_ENABLE_ACCEPTANCE=1`; disable that setting after the exercise.
4. Use a fresh generated `qa-*` username for each attempt/device. Never reset the runner and reuse the same server account. To start a new test, use a new private browsing context or clear that tab's session storage; do not delete a passkey from an unrelated account.
5. The **REPLAY** test must run in the same loaded page as **LOGIN** (its ephemeral assertion is intentionally kept only in memory). Then **refresh the page** before **SESSION**. Next **LOGOUT** and **CANCEL**. Restart only the Node backend (preserve credential JSON file), check the operator gate, and complete **RESTART** with the same passkey. Confirm successful local user verification in **UV**.
6. Fill physical device model, OS version, browser/version, authenticator type, tester alias, and real-device attestation. Export the JSON and save it to the controlled acceptance evidence location. No raw assertions, private keys, browser cookies, authenticator response, or token material is exported.

Run a fresh credential for each physical device. Use supported authenticators with device lock/PIN/biometrics active. Cancel the native prompt for CANCEL; deliberately cancelling the WebAuthn UI is not the same as programmatically aborting it.

## Scenario matrix (all required on each tested device)

| ID | Acceptance criterion | Evidence source |
| --- | --- | --- |
| ENV | Native WebAuthn API and secure browsing context are available | Browser API check |
| REGISTER | Platform or roaming physical authenticator registers disposable credential | Browser WebAuthn create + server HTTP 200 |
| DUPLICATE | Attempt to enroll the same username is rejected | Server HTTP 409 |
| LOGIN | Device signs fresh challenge and server validates credential, UV and session | Browser WebAuthn get + HTTP 200, GET session |
| REPLAY | The exact prior signed assertion cannot be reused | Server HTTP 401; prior session still valid |
| SESSION | HttpOnly session persists after actual browser reload | Operator confirms reload + GET session 200; JS cannot read session cookie |
| LOGOUT | Logout revokes authenticated access | POST logout, GET session 401 |
| CANCEL | Real authenticator prompt cancelled by operator, no session | Native NotAllowedError/AbortError + GET session 401 + operator gate |
| RESTART | Existing passkey still works after actual backend restart, with the user registry retained | Operator confirms restart + browser WebAuthn get + GET session 200 |
| UV | Device prompted for and operator completed local biometric or PIN verification | Explicit operator attestation; not independently provable from this browser |

Failures must be recorded as FAIL; reruns should use new test identities. Unexpected 5xx, missing prompts, credential mismatch, cancel-as-success, wrong cookie policy, or origin mismatch are rejection criteria.

## Physical-device matrix and release gate

Test combinations relevant to your support policy. Suggested matrix:

- iPhone/iPad Safari with Face ID / Touch ID / device PIN (current supported OS).
- Android Chrome with Android passkey provider and screen-lock verification.
- macOS Safari (Touch ID) or Windows Edge/Chrome (Windows Hello).
- Optional: hardware security key via USB/NFC and synced passkey where supported. Synced-key workflows require the device/provider to support that credential; do not label unsupported workflows as PASS.

For conservative release acceptance, require **at least two distinct physical devices** on different OS families, including one mobile plus one desktop or external security key, using the **same RP origin**. The validator enforces these conditions with `--release`; adjust the matrix only through an approved risk decision, not by editing test evidence.

## Validate locally and archive evidence

```sh
npm test
node acceptance/verify-evidence.js path/to/ios-evidence.json
node acceptance/verify-evidence.js path/to/android-or-desktop-evidence.json
node acceptance/verify-evidence.js --release path/to/mobile-evidence.json path/to/desktop-evidence.json
```

Exit code `0` means evidence passed structural/integrity checks and (with `--release`) completed the device diversity matrix. Exit `1` means `NO_GO`. Exit `2` means missing CLI input. Keep the exported file in a secured review archive and record the device models, run date, implementation commit SHA, acceptance operator, reviewer, build identity, and whether the original file was modified after export. Do not mistake self-attested evidence for digitally signed proof.

**Limits:** There is no automated physical-device lab, unattended real-device UI controller, hardware attestation verifier, or stable cross-browser remote WebAuthn control in this repository. No physical authenticator can be exercised from GitHub Actions. CI runs only unit checks for this harness. Reviewer must inspect test evidence and browser/device logs independently before signing off.
