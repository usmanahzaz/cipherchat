/**
 * Double Ratchet + X3DH for the CipherChat web client.
 *
 * Wire-compatible with the mobile app's ratchet (mobile/src/lib/ratchet.ts):
 * same primitives, same KDF info strings, same envelope format — a browser
 * user and an app user can converse.
 *
 * Primitives (audited implementations only):
 *   - X25519 / Ed25519 / XSalsa20-Poly1305: TweetNaCl.js (vendored, Cure53-audited)
 *   - HKDF / HMAC-SHA-512: the browser's built-in WebCrypto (crypto.subtle)
 *
 * Expects `nacl` (with nacl.util) as a global — vendor scripts load first.
 * In Node tests, set globalThis.nacl before importing.
 */

const INFO_X3DH = 'CipherChat-v2-X3DH';
const INFO_RK = 'CipherChat-v2-RootChain';
const MAX_SKIP = 256;

const te = new TextEncoder();
const b64 = (u) => nacl.util.encodeBase64(u);
const unb64 = (s) => nacl.util.decodeBase64(s);

// ---------------------------------------------------------------------------
// KDFs via WebCrypto (byte-identical to @noble/hashes on mobile)
// ---------------------------------------------------------------------------

async function hmac512(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
}

async function hkdf512(ikm, salt, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-512', salt, info: te.encode(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

function dh(privB64, pubB64) {
  return nacl.scalarMult(unb64(privB64), unb64(pubB64));
}

async function kdfRootChain(rk, dhOut) {
  const out = await hkdf512(dhOut, rk, INFO_RK, 64);
  return [out.slice(0, 32), out.slice(32, 64)];
}

async function kdfChainKey(ck) {
  const mk = (await hmac512(ck, Uint8Array.of(0x01))).slice(0, 32);
  const next = (await hmac512(ck, Uint8Array.of(0x02))).slice(0, 32);
  return { mk, next };
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function sessionIdFromEphemeral(ekPub) {
  return b64(nacl.hash(unb64(ekPub)).slice(0, 12));
}

async function messageKeyFor(mk, headerJson) {
  return (await hmac512(mk, te.encode(headerJson))).slice(0, 32);
}

// ---------------------------------------------------------------------------
// Identity & bundles
// ---------------------------------------------------------------------------

export function generateIdentity() {
  const identity = nacl.box.keyPair();
  const signing = nacl.sign.keyPair();
  const prekey = nacl.box.keyPair();
  return {
    identitySecret: b64(identity.secretKey),
    identityPublic: b64(identity.publicKey),
    signingSecret: b64(signing.secretKey),
    signingPublic: b64(signing.publicKey),
    prekeySecret: b64(prekey.secretKey),
    prekeyPublic: b64(prekey.publicKey),
  };
}

export function bundleFromIdentity(id) {
  return {
    identity_key: id.identityPublic,
    signing_key: id.signingPublic,
    signed_prekey: id.prekeyPublic,
    prekey_signature: b64(nacl.sign.detached(unb64(id.prekeyPublic), unb64(id.signingSecret))),
  };
}

export function verifyBundle(bundle) {
  try {
    return nacl.sign.detached.verify(
      unb64(bundle.signed_prekey),
      unb64(bundle.prekey_signature),
      unb64(bundle.signing_key),
    );
  } catch {
    return false;
  }
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function secureIdFromPublicKey(publicKeyB64) {
  const digest = nacl.hash(unb64(publicKeyB64));
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < 15; i++) {
    value = (value << 8) | digest[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  const body = out.slice(0, 16);
  return `CC-${body.slice(0, 4)}-${body.slice(4, 8)}-${body.slice(8, 12)}-${body.slice(12, 16)}`;
}

// ---------------------------------------------------------------------------
// X3DH session establishment
// ---------------------------------------------------------------------------

export async function createOutboundSession(me, bundle) {
  if (!verifyBundle(bundle)) throw new Error('Invalid prekey signature — refusing to start session.');
  const ek = nacl.box.keyPair();

  const sk = await hkdf512(
    concatBytes(
      dh(me.identitySecret, bundle.signed_prekey),
      dh(b64(ek.secretKey), bundle.identity_key),
      dh(b64(ek.secretKey), bundle.signed_prekey),
    ),
    new Uint8Array(32),
    INFO_X3DH,
    32,
  );

  const dhs = nacl.box.keyPair();
  const [rk, cks] = await kdfRootChain(sk, dh(b64(dhs.secretKey), bundle.signed_prekey));

  return {
    sid: sessionIdFromEphemeral(b64(ek.publicKey)),
    peerIdentityKey: bundle.identity_key,
    rk: b64(rk),
    dhsPub: b64(dhs.publicKey),
    dhsPriv: b64(dhs.secretKey),
    dhr: bundle.signed_prekey,
    cks: b64(cks),
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
    init: { ik: me.identityPublic, ek: b64(ek.publicKey) },
  };
}

export async function createInboundSession(me, init) {
  const sk = await hkdf512(
    concatBytes(
      dh(me.prekeySecret, init.ik),
      dh(me.identitySecret, init.ek),
      dh(me.prekeySecret, init.ek),
    ),
    new Uint8Array(32),
    INFO_X3DH,
    32,
  );

  return {
    sid: sessionIdFromEphemeral(init.ek),
    peerIdentityKey: init.ik,
    rk: b64(sk),
    dhsPub: me.prekeyPublic,
    dhsPriv: me.prekeySecret,
    dhr: null,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
    init: null,
  };
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt
// ---------------------------------------------------------------------------

export async function encrypt(session, plaintext) {
  if (!session.cks) throw new Error('Session not ready to send — wait for the first incoming message.');
  const { mk, next } = await kdfChainKey(unb64(session.cks));
  const header = {
    sid: session.sid,
    dh: session.dhsPub,
    n: session.ns,
    pn: session.pn,
    ...(session.init ? { init: session.init } : {}),
  };
  const headerJson = JSON.stringify(header);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const ct = nacl.secretbox(te.encode(plaintext), nonce, await messageKeyFor(mk, headerJson));

  session.cks = b64(next);
  session.ns += 1;

  return JSON.stringify({ v: 2, h: headerJson, n: b64(nonce), c: b64(ct) });
}

export function parseEnvelope(raw) {
  try {
    const envelope = JSON.parse(raw);
    if (envelope.v !== 2 || typeof envelope.h !== 'string') return null;
    const header = JSON.parse(envelope.h);
    if (typeof header.dh !== 'string' || typeof header.n !== 'number') return null;
    return { envelope, header };
  } catch {
    return null;
  }
}

export async function decrypt(session, raw) {
  const parsed = parseEnvelope(raw);
  if (!parsed) return null;
  const { envelope, header } = parsed;

  const s = JSON.parse(JSON.stringify(session));
  const nonce = unb64(envelope.n);
  const ct = unb64(envelope.c);

  const skippedKey = `${header.dh}:${header.n}`;
  const skippedMk = s.skipped[skippedKey];
  if (skippedMk) {
    const opened = nacl.secretbox.open(ct, nonce, await messageKeyFor(unb64(skippedMk), envelope.h));
    if (!opened) return null;
    delete s.skipped[skippedKey];
    if (s.init) s.init = null;
    return { plaintext: new TextDecoder().decode(opened), session: s };
  }

  if (header.dh !== s.dhr) {
    if (!(await skipToMessage(s, header.pn))) return null;
    s.pn = s.ns;
    s.ns = 0;
    s.nr = 0;
    s.dhr = header.dh;
    const [rk1, ckr] = await kdfRootChain(unb64(s.rk), dh(s.dhsPriv, s.dhr));
    const dhs = nacl.box.keyPair();
    const [rk2, cks] = await kdfRootChain(rk1, dh(b64(dhs.secretKey), s.dhr));
    s.rk = b64(rk2);
    s.ckr = b64(ckr);
    s.cks = b64(cks);
    s.dhsPub = b64(dhs.publicKey);
    s.dhsPriv = b64(dhs.secretKey);
  }

  if (!(await skipToMessage(s, header.n))) return null;
  if (!s.ckr) return null;
  const { mk, next } = await kdfChainKey(unb64(s.ckr));
  const opened = nacl.secretbox.open(ct, nonce, await messageKeyFor(mk, envelope.h));
  if (!opened) return null;

  s.ckr = b64(next);
  s.nr += 1;
  if (s.init) s.init = null;
  return { plaintext: new TextDecoder().decode(opened), session: s };
}

async function skipToMessage(s, until) {
  if (s.nr + MAX_SKIP < until) return false;
  if (s.nr < until && !s.ckr) return false;
  while (s.nr < until) {
    const { mk, next } = await kdfChainKey(unb64(s.ckr));
    s.skipped[`${s.dhr}:${s.nr}`] = b64(mk);
    s.ckr = b64(next);
    s.nr += 1;
  }
  return true;
}
