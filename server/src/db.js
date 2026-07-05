/**
 * Embedded SQLite database — created automatically at data/cipherchat.db on
 * first start. No external database, no accounts, no configuration.
 *
 * Zero-knowledge by construction: the `messages` table holds only ciphertext
 * and nonces produced on-device (X25519 + XSalsa20-Poly1305). No column
 * anywhere stores plaintext and the server holds no decryption keys.
 */
import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Override with CIPHERCHAT_DATA_DIR to point at a mounted volume (e.g. /data
// on Railway/Fly) so the database survives redeploys.
export const DATA_DIR =
  process.env.CIPHERCHAT_DATA_DIR ?? join(dirname(fileURLToPath(import.meta.url)), '..', 'data');
mkdirSync(DATA_DIR, { recursive: true });

export const db = new Database(join(DATA_DIR, 'cipherchat.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- private: never shown to other users
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    secure_id     TEXT UNIQUE,            -- CC-XXXX-…, derived on-device from public_key
    public_key    TEXT,                   -- base64 X25519 identity key (safe to share)
    sign_public_key   TEXT,               -- base64 Ed25519 signing key
    signed_prekey     TEXT,               -- base64 X25519 signed prekey (X3DH)
    prekey_signature  TEXT,               -- Ed25519 signature over signed_prekey
    push_token    TEXT,                   -- Expo push token; notifications carry no content
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );

  -- Short-lived, hashed one-time codes for email verification / password reset.
  CREATE TABLE IF NOT EXISTS email_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,             -- 'verify' | 'reset'
    code_hash  TEXT NOT NULL,             -- sha256 of the 6-digit code
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE INDEX IF NOT EXISTS email_tokens_user_idx ON email_tokens (user_id, kind);

  CREATE TABLE IF NOT EXISTS contacts (
    id          TEXT PRIMARY KEY,
    owner_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alias       TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',  -- request → accept handshake
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (owner_id, contact_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id            TEXT PRIMARY KEY,
    sender_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext    TEXT NOT NULL,          -- base64 nacl.box output (opaque)
    nonce         TEXT NOT NULL,          -- base64 24-byte nonce
    one_time      INTEGER NOT NULL DEFAULT 0,
    delivered_at  TEXT,
    read_at       TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );

  CREATE INDEX IF NOT EXISTS messages_thread_idx
    ON messages (sender_id, recipient_id, created_at);
  CREATE INDEX IF NOT EXISTS messages_inbox_idx
    ON messages (recipient_id, created_at);
`);

// Dev-friendly migration for databases created before the prekey columns.
for (const col of ['sign_public_key', 'signed_prekey', 'prekey_signature']) {
  const exists = db
    .prepare(`SELECT 1 FROM pragma_table_info('users') WHERE name = ?`)
    .get(col);
  if (!exists) db.exec(`ALTER TABLE users ADD COLUMN ${col} TEXT`);
}
// Pre-request-flow databases: existing contacts stay usable as accepted.
if (!db.prepare(`SELECT 1 FROM pragma_table_info('contacts') WHERE name = 'status'`).get()) {
  db.exec(`ALTER TABLE contacts ADD COLUMN status TEXT NOT NULL DEFAULT 'accepted'`);
}
// Pre-verification databases: grandfather existing accounts as verified so
// current testers aren't locked out.
if (!db.prepare(`SELECT 1 FROM pragma_table_info('users') WHERE name = 'email_verified'`).get()) {
  db.exec(`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`);
  db.exec(`UPDATE users SET email_verified = 1`);
}

/**
 * Profile shown to OTHER users — deliberately excludes email. Other people
 * only ever see your Secure ID code and public keys, never your email.
 */
export function publicProfile(row) {
  if (!row) return null;
  return {
    id: row.id,
    secure_id: row.secure_id,
    public_key: row.public_key,
    sign_public_key: row.sign_public_key,
    signed_prekey: row.signed_prekey,
    prekey_signature: row.prekey_signature,
  };
}

/** Profile of the signed-in user themselves — includes their own email. */
export function selfProfile(row) {
  if (!row) return null;
  return {
    ...publicProfile(row),
    email: row.email,
    email_verified: !!row.email_verified,
  };
}

export function messageRow(row) {
  if (!row) return null;
  return { ...row, one_time: !!row.one_time };
}
