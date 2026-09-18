const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// --- Config: change these when you deploy ---
const rpName = 'Passwordless Guard';
const rpID = 'localhost';           // must match the domain the browser is on
const origin = 'http://localhost:3000';

// --- Session, to hold the challenge between "options" and "verify" calls ---
app.use(session({
  secret: 'dev-secret-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }, // set true once served over https
}));

// --- In-memory "database" ---
// Replace with real persistence (SQLite/Postgres) once this flow works.
// Structure: username -> { id: Buffer, credentials: [ { id, publicKey, counter, transports } ] }
const users = new Map();

// STEP 1: Client asks the server for registration options
app.post('/api/register/options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });

  let user = users.get(username);
  if (!user) {
    user = { id: crypto.randomUUID(), credentials: [] };
    users.set(username, user);
  }

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: username,
    userDisplayName: username,
    attestationType: 'none', // don't need the device's manufacturer cert for this use case
    excludeCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  // Stash the challenge so we can check it in the verify step
  req.session.currentChallenge = options.challenge;
  req.session.registeringUser = username;

  res.json(options);
});

// STEP 2: Client sends back what the authenticator (fingerprint/security key) produced
app.post('/api/register/verify', async (req, res) => {
  const { username, response } = req.body;
  const expectedChallenge = req.session.currentChallenge;
  const user = users.get(username);

  if (!user || !expectedChallenge || req.session.registeringUser !== username) {
    return res.status(400).json({ verified: false, error: 'no active registration for this user' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ verified: false, error: err.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credential } = registrationInfo;
    user.credentials.push({
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: response.response.transports || [],
    });
  }

  // Clean up the one-time challenge
  delete req.session.currentChallenge;
  delete req.session.registeringUser;

  res.json({ verified });
});

// Debug helper so you can see what got stored — remove before anything real
app.get('/api/debug/users', (req, res) => {
  const summary = {};
  for (const [name, u] of users.entries()) {
    summary[name] = { id: u.id, credentialCount: u.credentials.length };
  }
  res.json(summary);
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Passwordless Guard running on http://localhost:${PORT}`));
