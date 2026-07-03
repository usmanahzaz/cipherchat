/**
 * Small crypto utilities (Secure ID derivation, PIN hashing).
 * Message encryption lives in ratchet.ts (Double Ratchet / X3DH).
 * All primitives come from TweetNaCl (audited by Cure53) — no custom crypto.
 */
import 'react-native-get-random-values';
import nacl from 'tweetnacl';
import { decodeBase64, decodeUTF8, encodeBase64 } from 'tweetnacl-util';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Deterministic, human-shareable Secure ID derived from the identity public
 * key: base32 of the first 15 bytes of SHA-512(publicKey), grouped for
 * readability. Collision-resistant enough for a directory lookup; the public
 * key itself remains the cryptographic identity.
 */
export function secureIdFromPublicKey(publicKeyB64: string): string {
  const digest = nacl.hash(decodeBase64(publicKeyB64));
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

/** Salted SHA-512 digest used only as a local PIN gate (see SECURITY.md). */
export function hashPin(pin: string, saltB64: string): string {
  const salt = decodeBase64(saltB64);
  const pinBytes = decodeUTF8(pin);
  const input = new Uint8Array(salt.length + pinBytes.length);
  input.set(salt);
  input.set(pinBytes, salt.length);
  return encodeBase64(nacl.hash(input));
}

export function newSalt(): string {
  return encodeBase64(nacl.randomBytes(16));
}
