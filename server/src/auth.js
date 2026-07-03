/**
 * Password hashing (scrypt, node:crypto) and JWT session tokens.
 * The JWT secret is generated once on first start and persisted in
 * data/jwt-secret — nothing to configure.
 */
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import jwt from 'jsonwebtoken';
import { DATA_DIR } from './db.js';

const SECRET_FILE = join(DATA_DIR, 'jwt-secret');

function loadSecret() {
  if (!existsSync(SECRET_FILE)) {
    writeFileSync(SECRET_FILE, randomBytes(48).toString('base64'), { mode: 0o600 });
  }
  return readFileSync(SECRET_FILE, 'utf8').trim();
}

const JWT_SECRET = process.env.CIPHERCHAT_JWT_SECRET ?? loadSecret();

const SCRYPT_N = 16384;
const KEY_LEN = 64;

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEY_LEN, { N: SCRYPT_N });
  return `${salt.toString('base64')}:${hash.toString('base64')}`;
}

export function verifyPassword(password, stored) {
  const [saltB64, hashB64] = stored.split(':');
  if (!saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = scryptSync(password, Buffer.from(saltB64, 'base64'), KEY_LEN, { N: SCRYPT_N });
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function issueToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '30d' });
}

/** Returns the user id or null. */
export function verifyToken(token) {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return typeof payload.sub === 'string' ? payload.sub : null;
  } catch {
    return null;
  }
}

/** Express middleware: sets req.userId or responds 401. */
export function requireAuth(req, res, next) {
  const header = req.headers.authorization ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const userId = token && verifyToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  req.userId = userId;
  next();
}
