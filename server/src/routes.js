import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { hashPassword, issueToken, requireAuth, verifyPassword } from './auth.js';
import { db, messageRow, publicProfile } from './db.js';
import { sendContentFreePush } from './push.js';
import { isOnline, sendTo } from './realtime.js';

export const router = Router();

const now = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// Auth — signup returns a session immediately: no email confirmation loop.
// ---------------------------------------------------------------------------
router.post('/auth/signup', (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required.' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  const id = randomUUID();
  try {
    db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)').run(
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
  res.json({ token: issueToken(id), profile: publicProfile(user) });
});

router.post('/auth/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email ?? '').trim());
  if (!user || !verifyPassword(String(password ?? ''), user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }
  res.json({ token: issueToken(user.id), profile: publicProfile(user) });
});

// ---------------------------------------------------------------------------
// Profile / keys
// ---------------------------------------------------------------------------
router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  res.json({ profile: publicProfile(user) });
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
  res.json({ profile: publicProfile(user) });
});

router.post('/me/push-token', requireAuth, (req, res) => {
  const token = typeof req.body?.token === 'string' ? req.body.token : null;
  db.prepare('UPDATE users SET push_token = ? WHERE id = ?').run(token, req.userId);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Contact discovery: exact match only — no browsing or enumeration.
// ---------------------------------------------------------------------------
router.post('/lookup', requireAuth, (req, res) => {
  const identifier = String(req.body?.identifier ?? '').trim();
  if (!identifier) return res.status(400).json({ error: 'identifier required.' });
  const user = db
    .prepare(
      `SELECT * FROM users
       WHERE secure_id = ? OR email = ? COLLATE NOCASE OR public_key = ?
       LIMIT 1`,
    )
    .get(identifier.toUpperCase(), identifier, identifier);
  if (!user || !user.public_key) {
    return res.status(404).json({ error: 'No user found for that Secure ID, email, or public key.' });
  }
  res.json({ profile: publicProfile(user) });
});

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------
router.get('/contacts', requireAuth, (req, res) => {
  const rows = db
    .prepare(
      `SELECT c.id, c.owner_id, c.contact_id, c.alias,
              u.id AS p_id, u.email AS p_email, u.secure_id AS p_secure_id,
              u.public_key AS p_public_key, u.sign_public_key AS p_sign_public_key,
              u.signed_prekey AS p_signed_prekey, u.prekey_signature AS p_prekey_signature
       FROM contacts c JOIN users u ON u.id = c.contact_id
       WHERE c.owner_id = ?
       ORDER BY c.created_at ASC`,
    )
    .all(req.userId);
  res.json({
    contacts: rows.map((r) => ({
      id: r.id,
      owner_id: r.owner_id,
      contact_id: r.contact_id,
      alias: r.alias,
      profile: {
        id: r.p_id,
        email: r.p_email,
        secure_id: r.p_secure_id,
        public_key: r.p_public_key,
        sign_public_key: r.p_sign_public_key,
        signed_prekey: r.p_signed_prekey,
        prekey_signature: r.p_prekey_signature,
      },
    })),
  });
});

router.post('/contacts', requireAuth, (req, res) => {
  const { contact_id, alias } = req.body ?? {};
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(String(contact_id ?? ''));
  if (!target || !target.public_key) return res.status(404).json({ error: 'User not found.' });
  if (target.id === req.userId) return res.status(400).json({ error: 'That is your own ID.' });
  db.prepare(
    `INSERT INTO contacts (id, owner_id, contact_id, alias) VALUES (?, ?, ?, ?)
     ON CONFLICT (owner_id, contact_id) DO UPDATE SET alias = excluded.alias`,
  ).run(randomUUID(), req.userId, target.id, typeof alias === 'string' && alias ? alias : null);
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
