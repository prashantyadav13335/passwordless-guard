# Passwordless Guard — Step 1: Registration Flow

WebAuthn/FIDO2 passwordless authentication. This step covers **registration only**
(login/authentication flow is the next step).

## How it works

1. User enters a username and clicks "Register with device."
2. Browser asks server for registration options (`POST /api/register/options`) —
   server generates a random challenge and stashes it in the session.
3. Browser calls the native WebAuthn API (`navigator.credentials.create`), which
   prompts fingerprint / Face ID / Windows Hello / security key. The device
   creates a public/private key pair — **private key never leaves the device.**
4. Browser sends the signed response back (`POST /api/register/verify`).
5. Server verifies the signature against the challenge and stores the
   **public key only**.

No password is ever created, transmitted, or stored.

## Run it

```bash
npm install
npm start
```

Then open **http://localhost:3000** in a browser that supports WebAuthn
(Chrome, Edge, Firefox, Safari — all modern versions do) on a device with a
fingerprint reader, Face ID, Windows Hello, or a USB security key.

Check what got stored (dev-only debug route):
```
http://localhost:3000/api/debug/users
```

## Important notes

- **Storage is in-memory** (a `Map`) — restarting the server wipes all
  registered users. Swap this for SQLite/Postgres before treating this as
  anything beyond a demo — that'll be a later step.
- **`rpID` is hardcoded to `localhost`.** WebAuthn ties credentials to a
  specific domain — if you deploy this, `rpID` and `origin` in `server.js`
  must match your real domain, or the browser will reject every ceremony.
- **Session secret is a placeholder** (`dev-secret-change-this`) — replace
  before deploying.
- This step deliberately has no login route yet — that's next, and it reuses
  the same credential store.

## Threat model (partial — expand as you add login)

**Defeats:**
- Phishing — there's no shared secret to phish; a fake site can't get the
  private key or replay a signature for the real origin.
- Credential stuffing / reused-password attacks — there's no password.
- Server-side credential DB leaks — leaked public keys are useless to an
  attacker without the matching private key.

**Does not defeat:**
- A compromised/malware-infected client device (attacker can trigger the
  authenticator directly).
- Physical theft of an unlocked device that already has the platform
  authenticator unlocked.
- Session hijacking after a legitimate login (this flow only secures
  authentication, not the session that follows).
