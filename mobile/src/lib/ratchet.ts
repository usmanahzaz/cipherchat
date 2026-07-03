/**
 * Double Ratchet with X3DH-style session setup — Signal's algorithm
 * (https://signal.org/docs/specifications/doubleratchet/), implemented on
 * audited primitives only:
 *
 *   - X25519 DH             tweetnacl  nacl.scalarMult / nacl.box.keyPair
 *   - Ed25519 signatures    tweetnacl  nacl.sign (prekey authenticity)
 *   - AEAD                  tweetnacl  nacl.secretbox (XSalsa20-Poly1305)
 *   - HKDF / HMAC-SHA-512   @noble/hashes (Cure53-audited)
 *
 * What this buys over a static key pair:
 *   FORWARD SECRECY — every message is encrypted under a one-time key derived
 *   from an advancing HMAC chain and destroyed after use. Stealing all keys
 *   on a device today cannot decrypt yesterday's ciphertext.
 *   POST-COMPROMISE SECURITY — fresh X25519 randomness is mixed in with every
 *   send/receive round-trip, so a copied session state is locked out again as
 *   soon as the two parties exchange one more message pair.
 *
 * This is a faithful implementation of a published protocol, not invented
 * cryptography — but it is OUR implementation and has not been independently
 * audited. See SECURITY.md.
 */
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import nacl from 'tweetnacl';
import { decodeBase64, decodeUTF8, encodeBase64, encodeUTF8 } from 'tweetnacl-util';

const INFO_X3DH = 'CipherChat-v2-X3DH';
const INFO_RK = 'CipherChat-v2-RootChain';
/** Max out-of-order messages we will derive-and-store keys for, per chain. */
const MAX_SKIP = 256;

const b64 = encodeBase64;
const unb64 = decodeBase64;

// ---------------------------------------------------------------------------
// Key bundles
// ---------------------------------------------------------------------------

/** Public half of a user's identity, published to the server. */
export interface PrekeyBundle {
  identity_key: string; // X25519, long-term
  signing_key: string; // Ed25519, long-term
  signed_prekey: string; // X25519, medium-term ("SPK")
  prekey_signature: string; // Ed25519 sig over signed_prekey by signing_key
}

/** Private identity material, generated on-device at provisioning. */
export interface IdentityKeys {
  identitySecret: string;
  identityPublic: string;
  signingSecret: string; // Ed25519 64-byte secret
  signingPublic: string;
  prekeySecret: string;
  prekeyPublic: string;
}

export function generateIdentity(): IdentityKeys {
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

export function bundleFromIdentity(id: IdentityKeys): PrekeyBundle {
  return {
    identity_key: id.identityPublic,
    signing_key: id.signingPublic,
    signed_prekey: id.prekeyPublic,
    prekey_signature: b64(nacl.sign.detached(unb64(id.prekeyPublic), unb64(id.signingSecret))),
  };
}

/** Reject bundles whose prekey was not signed by the owner's signing key. */
export function verifyBundle(bundle: PrekeyBundle): boolean {
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

// ---------------------------------------------------------------------------
// Session state (JSON-serializable; all key material base64)
// ---------------------------------------------------------------------------

export interface Session {
  sid: string; // hash of the X3DH ephemeral — same on both sides
  peerIdentityKey: string;
  rk: string; // root key
  dhsPub: string; // my current ratchet key pair
  dhsPriv: string;
  dhr: string | null; // their latest ratchet public key
  cks: string | null; // sending chain key
  ckr: string | null; // receiving chain key
  ns: number; // messages sent in current chain
  nr: number; // messages received in current chain
  pn: number; // length of previous sending chain
  skipped: Record<string, string>; // `${dhr}:${n}` -> message key
  /** X3DH material attached to headers until the peer demonstrably has the
   *  session (initiator side only). */
  init: { ik: string; ek: string } | null;
}

interface Header {
  sid: string;
  dh: string;
  n: number;
  pn: number;
  init?: { ik: string; ek: string };
}

// ---------------------------------------------------------------------------
// KDFs (Signal spec §5.2, HKDF/HMAC-SHA-512)
// ---------------------------------------------------------------------------

function dh(privB64: string, pubB64: string): Uint8Array {
  return nacl.scalarMult(unb64(privB64), unb64(pubB64));
}

function kdfRootChain(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const out = hkdf(sha512, dhOut, rk, INFO_RK, 64);
  return [out.slice(0, 32), out.slice(32, 64)];
}

function kdfChainKey(ck: Uint8Array): { mk: Uint8Array; next: Uint8Array } {
  return {
    mk: hmac(sha512, ck, Uint8Array.of(0x01)).slice(0, 32),
    next: hmac(sha512, ck, Uint8Array.of(0x02)).slice(0, 32),
  };
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function sessionIdFromEphemeral(ekPub: string): string {
  return b64(sha512(unb64(ekPub)).slice(0, 12));
}

// ---------------------------------------------------------------------------
// X3DH session establishment (no one-time prekeys in this MVP; see SECURITY.md)
// ---------------------------------------------------------------------------

/** Alice starts a session toward Bob using his published bundle. */
export function createOutboundSession(me: IdentityKeys, bundle: PrekeyBundle): Session {
  if (!verifyBundle(bundle)) throw new Error('Invalid prekey signature — refusing to start session.');
  const ek = nacl.box.keyPair();

  const sk = hkdf(
    sha512,
    concat(
      dh(me.identitySecret, bundle.signed_prekey), // DH1: IK_a × SPK_b
      dh(b64(ek.secretKey), bundle.identity_key), //  DH2: EK_a × IK_b
      dh(b64(ek.secretKey), bundle.signed_prekey), // DH3: EK_a × SPK_b
    ),
    new Uint8Array(32),
    INFO_X3DH,
    32,
  );

  // Double Ratchet init (Alice): Bob's SPK is his first ratchet key.
  const dhs = nacl.box.keyPair();
  const [rk, cks] = kdfRootChain(sk, dh(b64(dhs.secretKey), bundle.signed_prekey));

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

/** Bob accepts a session from the init block of Alice's first message. */
export function createInboundSession(
  me: IdentityKeys,
  init: { ik: string; ek: string },
): Session {
  const sk = hkdf(
    sha512,
    concat(
      dh(me.prekeySecret, init.ik), //   DH1 mirror: SPK_b × IK_a
      dh(me.identitySecret, init.ek), // DH2 mirror: IK_b × EK_a
      dh(me.prekeySecret, init.ek), //   DH3 mirror: SPK_b × EK_a
    ),
    new Uint8Array(32),
    INFO_X3DH,
    32,
  );

  // Double Ratchet init (Bob): his SPK pair is his first ratchet key pair;
  // chains start on the first received header's DH ratchet step.
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
// Encrypt / decrypt (Signal spec §3; header authenticated as associated data)
// ---------------------------------------------------------------------------

export interface RatchetEnvelope {
  v: 2;
  h: string; // header JSON, verbatim — authenticated via the message key
  n: string; // base64 24-byte nonce
  c: string; // base64 XSalsa20-Poly1305 ciphertext
}

/** Binds the header to the ciphertext: km = HMAC(mk, header bytes). */
function messageKeyFor(mk: Uint8Array, headerJson: string): Uint8Array {
  return hmac(sha512, mk, decodeUTF8(headerJson)).slice(0, 32);
}

/** Encrypts, advancing (and mutating) the session's sending chain. */
export function encrypt(session: Session, plaintext: string): string {
  if (!session.cks) {
    throw new Error('Session not ready to send — wait for the first incoming message.');
  }
  const { mk, next } = kdfChainKey(unb64(session.cks));
  const header: Header = {
    sid: session.sid,
    dh: session.dhsPub,
    n: session.ns,
    pn: session.pn,
    ...(session.init ? { init: session.init } : {}),
  };
  const headerJson = JSON.stringify(header);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const ct = nacl.secretbox(decodeUTF8(plaintext), nonce, messageKeyFor(mk, headerJson));

  session.cks = b64(next); // one-time message key is never stored
  session.ns += 1;

  const envelope: RatchetEnvelope = { v: 2, h: headerJson, n: b64(nonce), c: b64(ct) };
  return JSON.stringify(envelope);
}

export function parseEnvelope(raw: string): { envelope: RatchetEnvelope; header: Header } | null {
  try {
    const envelope = JSON.parse(raw) as RatchetEnvelope;
    if (envelope.v !== 2 || typeof envelope.h !== 'string') return null;
    const header = JSON.parse(envelope.h) as Header;
    if (typeof header.dh !== 'string' || typeof header.n !== 'number') return null;
    return { envelope, header };
  } catch {
    return null;
  }
}

/**
 * Decrypts an envelope. Works on a clone and returns the advanced session
 * only on success, so a forged message can never corrupt real state.
 * Handles out-of-order delivery via skipped-key storage (bounded by MAX_SKIP).
 */
export function decrypt(
  session: Session,
  raw: string,
): { plaintext: string; session: Session } | null {
  const parsed = parseEnvelope(raw);
  if (!parsed) return null;
  const { envelope, header } = parsed;

  const s: Session = JSON.parse(JSON.stringify(session));
  const nonce = unb64(envelope.n);
  const ct = unb64(envelope.c);

  // 1. A key we already skipped past?
  const skippedKey = `${header.dh}:${header.n}`;
  const skippedMk = s.skipped[skippedKey];
  if (skippedMk) {
    const opened = nacl.secretbox.open(ct, nonce, messageKeyFor(unb64(skippedMk), envelope.h));
    if (!opened) return null;
    delete s.skipped[skippedKey];
    if (s.init) s.init = null; // peer provably has the session
    return { plaintext: encodeUTF8(opened), session: s };
  }

  // 2. New ratchet key from the peer → DH ratchet step.
  if (header.dh !== s.dhr) {
    if (!skipToMessage(s, header.pn)) return null; // close out old chain
    s.pn = s.ns;
    s.ns = 0;
    s.nr = 0;
    s.dhr = header.dh;
    const [rk1, ckr] = kdfRootChain(unb64(s.rk), dh(s.dhsPriv, s.dhr));
    const dhs = nacl.box.keyPair();
    const [rk2, cks] = kdfRootChain(rk1, dh(b64(dhs.secretKey), s.dhr));
    s.rk = b64(rk2);
    s.ckr = b64(ckr);
    s.cks = b64(cks);
    s.dhsPub = b64(dhs.publicKey);
    s.dhsPriv = b64(dhs.secretKey);
  }

  // 3. Advance the receiving chain to this message.
  if (!skipToMessage(s, header.n)) return null;
  if (!s.ckr) return null;
  const { mk, next } = kdfChainKey(unb64(s.ckr));
  const opened = nacl.secretbox.open(ct, nonce, messageKeyFor(mk, envelope.h));
  if (!opened) return null;

  s.ckr = b64(next);
  s.nr += 1;
  if (s.init) s.init = null;
  return { plaintext: encodeUTF8(opened), session: s };
}

/** Derive and stash keys for messages we haven't seen yet (out-of-order). */
function skipToMessage(s: Session, until: number): boolean {
  if (s.nr + MAX_SKIP < until) return false;
  if (s.nr < until && !s.ckr) return false;
  while (s.nr < until) {
    const { mk, next } = kdfChainKey(unb64(s.ckr as string));
    s.skipped[`${s.dhr}:${s.nr}`] = b64(mk);
    s.ckr = b64(next);
    s.nr += 1;
  }
  return true;
}
