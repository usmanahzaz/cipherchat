import { createHash, randomInt, randomUUID } from 'node:crypto';
import { Router } from 'express';
import { hashPassword, issueToken, requireAuth, verifyPassword } from './auth.js';
import { db, messageRow, publicProfile, selfProfile } from './db.js';
import { emailConfigured, sendCode } from './email.js';
import { sendContentFreePush } from './push.js';
import { isOnline, sendTo } from './realtime.js';

export const router = Router();

const now = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// Email verification codes (6-digit, hashed, 15-minute expiry)
// ---------------------------------------------------------------------------
const CODE_TTL_MS = 15 * 60 * 1000;
const hashCode = (code) => createHash('sha256').update(code).digest('hex');

/** Issues a fresh code for a purpose, replacing any prior one, and emails it.
 *  Returns the plaintext code ONLY when SMTP is unconfigured (dev mode). */
async function issueEmailCode(user, kind) {
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  db.prepare('DELETE FROM email_tokens WHERE user_id = ? AND kind = ?').run(user.id, kind);
  db.prepare(
    'INSERT INTO email_tokens (id, user_id, kind, code_hash, expires_at) VALUES (?, ?, ?, ?, ?)',
  ).run(randomUUID(), user.id, kind, hashCode(code), new Date(Date.now() + CODE_TTL_MS).toISOString());
  await sendCode(user.email, kind, code);
  return emailConfigured ? undefined : code;
}

/** Consumes a valid, unexpired code; returns true on success. */
function consumeEmailCode(userId, kind, code) {
  const row = db
    .prepare('SELECT * FROM email_tokens WHERE user_id = ? AND kind = ?')
    .get(userId, kind);
  if (!row || row.code_hash !== hashCode(String(code ?? '')) || row.expires_at < now()) return false;
  db.prepare('DELETE FROM email_tokens WHERE id = ?').run(row.id);
  return true;
}

// ---------------------------------------------------------------------------
// Auth — email + password, with email verification before first use.
// ---------------------------------------------------------------------------
router.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required.' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  const id = randomUUID();
  try {
    db.prepare('INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, ?, 0)').run(
      id,
      email.trim(),
      hashPassword(password),
    );
  } catch (e) {
    if (String(e).includes('UNIQUE')) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    throw e;
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const devCode = await issueEmailCode(user, 'verify');
  // No session token until the email is verified.
  res.json({ needsVerification: true, email: user.email, dev_code: devCode });
});

router.post('/auth/verify', (req, res) => {
  const { email, code } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email ?? '').trim());
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  if (!consumeEmailCode(user.id, 'verify', code)) {
    return res.status(400).json({ error: 'Invalid or expired code.' });
  }
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
  const fresh = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  res.json({ token: issueToken(user.id), profile: selfProfile(fresh) });
});

router.post('/auth/resend', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(req.body?.email ?? '').trim());
  // Do not reveal whether the account exists / is already verified.
  let devCode;
  if (user && !user.email_verified) devCode = await issueEmailCode(user, 'verify');
  res.json({ ok: true, dev_code: devCode });
});

router.post('/auth/login', async (req, res) => {
  const { email, password } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email ?? '').trim());
  if (!user || !verifyPassword(String(password ?? ''), user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }
  if (!user.email_verified) {
    const devCode = await issueEmailCode(user, 'verify');
    return res.status(403).json({ needsVerification: true, email: user.email, dev_code: devCode });
  }
  res.json({ token: issueToken(user.id), profile: selfProfile(user) });
});

// Forgot / reset password (keys are unaffected — they live only on-device).
router.post('/auth/forgot', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(req.body?.email ?? '').trim());
  let devCode;
  if (user) devCode = await issueEmailCode(user, 'reset'); // silent if no such account
  res.json({ ok: true, dev_code: devCode });
});

router.post('/auth/reset', (req, res) => {
  const { email, code, new_password } = req.body ?? {};
  if (typeof new_password !== 'string' || new_password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email ?? '').trim());
  if (!user || !consumeEmailCode(user.id, 'reset', code)) {
    return res.status(400).json({ error: 'Invalid or expired code.' });
  }
  // A successful reset also proves control of the inbox → mark verified.
  db.prepare('UPDATE users SET password_hash = ?, email_verified = 1 WHERE id = ?').run(
    hashPassword(new_password),
    user.id,
  );
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Profile / keys
// ---------------------------------------------------------------------------
router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  res.json({ profile: selfProfile(user) });
});

// Publishes the PUBLIC key bundle (X25519 identity, Ed25519 signing key,
// signed prekey + signature) and the derived Secure ID. Private keys never
// appear in any request.
router.post('/me/keys', requireAuth, (req, res) => {
  const { public_key, secure_id, sign_public_key, signed_prekey, prekey_signature } =
    req.body ?? {};
  const fields = { public_key, secure_id, sign_public_key, signed_prekey, prekey_signature };
  for (const [name, value] of Object.entries(fields)) {
    if (typeof value !== 'string' || !value) {
      return res.status(400).json({ error: `${name} required.` });
    }
  }
  try {
    db.prepare(
      `UPDATE users SET public_key = ?, secure_id = ?, sign_public_key = ?,
                        signed_prekey = ?, prekey_signature = ?
       WHERE id = ?`,
    ).run(public_key, secure_id, sign_public_key, signed_prekey, prekey_signature, req.userId);
  } catch (e) {
    if (String(e).includes('UNIQUE')) {
      return res.status(409).json({ error: 'That Secure ID is already registered.' });
    }
    throw e;
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  res.json({ profile: selfProfile(user) });
});

router.post('/me/push-token', requireAuth, (req, res) => {
  const token = typeof req.body?.token === 'string' ? req.body.token : null;
  db.prepare('UPDATE users SET push_token = ? WHERE id = ?').run(token, req.userId);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Contact discovery: by Secure ID or public key only — exact match, no
// browsing. Email is intentionally NOT searchable, so an email can never be
// linked to an identity by other users.
// ---------------------------------------------------------------------------
router.post('/lookup', requireAuth, (req, res) => {
  const identifier = String(req.body?.identifier ?? '').trim();
  if (!identifier) return res.status(400).json({ error: 'identifier required.' });
  const user = db
    .prepare(`SELECT * FROM users WHERE secure_id = ? OR public_key = ? LIMIT 1`)
    .get(identifier.toUpperCase(), identifier);
  if (!user || !user.public_key) {
    return res.status(404).json({ error: 'No user found for that Secure ID or public key.' });
  }
  res.json({ profile: publicProfile(user) });
});

// ---------------------------------------------------------------------------
// Contacts — request/accept handshake. Nobody can message you until you
// explicitly accept their request.
// ---------------------------------------------------------------------------
const CONTACT_SELECT = `
  SELECT c.id, c.owner_id, c.contact_id, c.alias, c.status,
         u.id AS p_id, u.email AS p_email, u.secure_id AS p_secure_id,
         u.public_key AS p_public_key, u.sign_public_key AS p_sign_public_key,
         u.signed_prekey AS p_signed_prekey, u.prekey_signature AS p_prekey_signature`;

function contactShape(r) {
  return {
    id: r.id,
    owner_id: r.owner_id,
    contact_id: r.contact_id,
    alias: r.alias,
    status: r.status,
    profile: {
      id: r.p_id,
      email: r.p_email,
      secure_id: r.p_secure_id,
      public_key: r.p_public_key,
      sign_public_key: r.p_sign_public_key,
      signed_prekey: r.p_signed_prekey,
      prekey_signature: r.p_prekey_signature,
    },
  };
}

function isAccepted(recipientId, senderId) {
  return !!db
    .prepare(`SELECT 1 FROM contacts WHERE owner_id = ? AND contact_id = ? AND status = 'accepted'`)
    .get(recipientId, senderId);
}

router.get('/contacts', requireAuth, (req, res) => {
  const accepted = db
    .prepare(`${CONTACT_SELECT} FROM contacts c JOIN users u ON u.id = c.contact_id
              WHERE c.owner_id = ? AND c.status = 'accepted' ORDER BY c.created_at ASC`)
    .all(req.userId)
    .map(contactShape);
  const outgoing = db
    .prepare(`${CONTACT_SELECT} FROM contacts c JOIN users u ON u.id = c.contact_id
              WHERE c.owner_id = ? AND c.status = 'pending' ORDER BY c.created_at ASC`)
    .all(req.userId)
    .map(contactShape);
  res.json({ contacts: accepted, outgoing });
});

/** Incoming requests awaiting my decision. */
router.get('/contact-requests', requireAuth, (req, res) => {
  const requests = db
    .prepare(`${CONTACT_SELECT} FROM contacts c JOIN users u ON u.id = c.owner_id
              WHERE c.contact_id = ? AND c.status = 'pending' ORDER BY c.created_at ASC`)
    .all(req.userId)
    .map(contactShape);
  res.json({ requests });
});

router.post('/contacts', requireAuth, (req, res) => {
  const { contact_id, alias } = req.body ?? {};
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(String(contact_id ?? ''));
  if (!target || !target.public_key) return res.status(404).json({ error: 'User not found.' });
  if (target.id === req.userId) return res.status(400).json({ error: 'That is your own ID.' });

  const aliasVal = typeof alias === 'string' && alias ? alias : null;

  // If they already asked US, adding them back completes the handshake.
  const incoming = db
    .prepare(`SELECT * FROM contacts WHERE owner_id = ? AND contact_id = ? AND status = 'pending'`)
    .get(target.id, req.userId);
  if (incoming) {
    acceptRequest(incoming, req.userId, aliasVal);
    return res.json({ ok: true, status: 'accepted' });
  }

  db.prepare(
    `INSERT INTO contacts (id, owner_id, contact_id, alias, status) VALUES (?, ?, ?, ?, 'pending')
     ON CONFLICT (owner_id, contact_id) DO UPDATE SET alias = excluded.alias`,
  ).run(randomUUID(), req.userId, target.id, aliasVal);

  // Notify the target live: someone wants to exchange encrypted messages.
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  sendTo(target.id, { type: 'contact:request', profile: publicProfile(me) });
  res.json({ ok: true, status: 'pending' });
});

/** Marks their request accepted and creates my reciprocal accepted row. */
function acceptRequest(requestRow, myId, myAlias) {
  db.prepare(`UPDATE contacts SET status = 'accepted' WHERE id = ?`).run(requestRow.id);
  db.prepare(
    `INSERT INTO contacts (id, owner_id, contact_id, alias, status) VALUES (?, ?, ?, ?, 'accepted')
     ON CONFLICT (owner_id, contact_id) DO UPDATE SET status = 'accepted'`,
  ).run(randomUUID(), myId, requestRow.owner_id, myAlias);
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(myId);
  sendTo(requestRow.owner_id, { type: 'contact:accepted', profile: publicProfile(me) });
}

router.post('/contact-requests/:id/accept', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM contacts WHERE id = ?').get(req.params.id);
  if (!row || row.contact_id !== req.userId || row.status !== 'pending') {
    return res.status(404).json({ error: 'Request not found.' });
  }
  acceptRequest(row, req.userId, typeof req.body?.alias === 'string' && req.body.alias ? req.body.alias : null);
  res.json({ ok: true });
});

router.post('/contact-requests/:id/decline', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM contacts WHERE id = ?').get(req.params.id);
  if (!row || row.contact_id !== req.userId || row.status !== 'pending') {
    return res.status(404).json({ error: 'Request not found.' });
  }
  db.prepare('DELETE FROM contacts WHERE id = ?').run(row.id);
  sendTo(row.owner_id, { type: 'contact:declined', peer_id: req.userId });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Messages — opaque blobs in, opaque blobs out.
// ---------------------------------------------------------------------------
router.get('/messages/:peerId', requireAuth, (req, res) => {
  const rows = db
    .prepare(
      `SELECT * FROM messages
       WHERE (sender_id = @me AND recipient_id = @peer)
          OR (sender_id = @peer AND recipient_id = @me)
       ORDER BY created_at ASC`,
    )
    .all({ me: req.userId, peer: req.params.peerId });
  res.json({ messages: rows.map(messageRow) });
});

router.post('/messages', requireAuth, (req, res) => {
  const { recipient_id, ciphertext, nonce, one_time } = req.body ?? {};
  if (typeof ciphertext !== 'string' || !ciphertext || typeof nonce !== 'string' || !nonce) {
    return res.status(400).json({ error: 'ciphertext and nonce required.' });
  }
  const recipient = db.prepare('SELECT * FROM users WHERE id = ?').get(String(recipient_id ?? ''));
  if (!recipient) return res.status(404).json({ error: 'Recipient not found.' });
  if (!isAccepted(recipient.id, req.userId)) {
    return res.status(403).json({ error: 'This contact has not accepted your request yet.' });
  }

  const id = randomUUID();
  db.prepare(
    `INSERT INTO messages (id, sender_id, recipient_id, ciphertext, nonce, one_time, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, req.userId, recipient.id, ciphertext, nonce, one_time ? 1 : 0, now());
  const message = messageRow(db.prepare('SELECT * FROM messages WHERE id = ?').get(id));

  const deliveredLive = sendTo(recipient.id, { type: 'message:new', message });
  if (!deliveredLive) sendContentFreePush(recipient.push_token);

  res.json({ message });
});

// Recipient marks a peer's messages delivered; the sender is told live (✓✓).
router.post('/messages/delivered', requireAuth, (req, res) => {
  const peerId = String(req.body?.peer_id ?? '');
  const at = now();
  const result = db
    .prepare(
      `UPDATE messages SET delivered_at = ?
       WHERE sender_id = ? AND recipient_id = ? AND delivered_at IS NULL`,
    )
    .run(at, peerId, req.userId);
  if (result.changes > 0) {
    sendTo(peerId, { type: 'messages:delivered', peer_id: req.userId, delivered_at: at });
  }
  res.json({ ok: true });
});

// Either endpoint may delete (one-time burn / cleanup).
router.delete('/messages/:id', requireAuth, (req, res) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.json({ ok: true });
  if (msg.sender_id !== req.userId && msg.recipient_id !== req.userId) {
    return res.status(403).json({ error: 'Not your message.' });
  }
  db.prepare('DELETE FROM messages WHERE id = ?').run(msg.id);
  const other = msg.sender_id === req.userId ? msg.recipient_id : msg.sender_id;
  sendTo(other, { type: 'message:deleted', id: msg.id, peer_id: req.userId });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Panic: server-side cleanup for a device wipe. (The real guarantee is the
// destroyed private key on-device; this just removes the blobs too.)
// ---------------------------------------------------------------------------
router.post('/panic', requireAuth, (req, res) => {
  db.prepare('DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?').run(
    req.userId,
    req.userId,
  );
  db.prepare('UPDATE users SET push_token = NULL WHERE id = ?').run(req.userId);
  res.json({ ok: true });
});
