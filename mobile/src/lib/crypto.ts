/**
 * End-to-end encryption primitives for CipherChat.
 *
 * Built entirely on TweetNaCl (audited by Cure53), no custom cryptography:
 *  - Key agreement: X25519 (nacl.box.keyPair)
 *  - Authenticated encryption: XSalsa20-Poly1305 (nacl.box)
 *
 * nacl.box derives a shared key from (mySecretKey, theirPublicKey), so the
 * sender can also re-open their own sent messages using the recipient's
 * public key. Plaintext only ever exists transiently in memory on-device.
 */
import 'react-native-get-random-values';
import nacl from 'tweetnacl';
import {
  decodeBase64,
  decodeUTF8,
  encodeBase64,
  encodeUTF8,
} from 'tweetnacl-util';

export interface KeyPairB64 {
  publicKey: string;
  secretKey: string;
}

export interface EncryptedPayload {
  ciphertext: string; // base64
  nonce: string; // base64
}

export function generateKeyPair(): KeyPairB64 {
  const kp = nacl.box.keyPair();
  return {
    publicKey: encodeBase64(kp.publicKey),
    secretKey: encodeBase64(kp.secretKey),
  };
}

export function encryptMessage(
  plaintext: string,
  theirPublicKeyB64: string,
  mySecretKeyB64: string,
): EncryptedPayload {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const box = nacl.box(
    decodeUTF8(plaintext),
    nonce,
    decodeBase64(theirPublicKeyB64),
    decodeBase64(mySecretKeyB64),
  );
  return { ciphertext: encodeBase64(box), nonce: encodeBase64(nonce) };
}

/** Returns null when authentication fails (tampered or wrong keys). */
export function decryptMessage(
  payload: EncryptedPayload,
  theirPublicKeyB64: string,
  mySecretKeyB64: string,
): string | null {
  try {
    const opened = nacl.box.open(
      decodeBase64(payload.ciphertext),
      decodeBase64(payload.nonce),
      decodeBase64(theirPublicKeyB64),
      decodeBase64(mySecretKeyB64),
    );
    return opened ? encodeUTF8(opened) : null;
  } catch {
    return null;
  }
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Deterministic, human-shareable Secure ID derived from the public key:
 * base32 of the first 15 bytes of SHA-512(publicKey), grouped for readability.
 * Collision-resistant enough for a directory lookup; the public key itself
 * remains the cryptographic identity.
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
