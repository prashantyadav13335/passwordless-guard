import { startRegistration } from '/vendor/simplewebauthn-browser.js';

const statusEl = document.getElementById('status');
const usernameEl = document.getElementById('username');

document.getElementById('registerBtn').addEventListener('click', async () => {
  const username = usernameEl.value.trim();
  if (!username) {
    statusEl.textContent = 'Enter a username first.';
    return;
  }

  try {
    // 1. Ask server for registration options (includes a random challenge)
    const optionsRes = await fetch('/api/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // needed so the session cookie carries the challenge
      body: JSON.stringify({ username }),
    });
    const options = await optionsRes.json();
    if (!optionsRes.ok) throw new Error(options.error || 'failed to get options');

    // 2. Trigger the browser's native WebAuthn prompt (fingerprint / Face ID / security key)
    statusEl.textContent = 'Follow your device prompt...';
    const attestationResponse = await startRegistration({ optionsJSON: options });

    // 3. Send what the device produced back to the server to verify + store
    const verifyRes = await fetch('/api/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, response: attestationResponse }),
    });
    const verifyJson = await verifyRes.json();

    if (verifyJson.verified) {
      statusEl.textContent = `Registered "${username}" successfully — no password stored anywhere.`;
    } else {
      statusEl.textContent = `Verification failed: ${verifyJson.error || 'unknown reason'}`;
    }
  } catch (err) {
    console.error(err);
    statusEl.textContent = `Error: ${err.message}`;
  }
});
