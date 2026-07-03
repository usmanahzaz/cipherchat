/**
 * Secure on-device storage backed by iOS Keychain / Android Keystore via
 * expo-secure-store. All private key material lives here and never leaves
 * the device or this module's callers.
 */
import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import type { IdentityKeys } from './ratchet';

const K = {
  identitySecret: 'cc.secretKey',
  identityPublic: 'cc.publicKey',
  signingSecret: 'cc.signSecretKey',
  signingPublic: 'cc.signPublicKey',
  prekeySecret: 'cc.spkSecretKey',
  prekeyPublic: 'cc.spkPublicKey',
  storageKey: 'cc.storageKey',
  pinHash: 'cc.pinHash',
  pinSalt: 'cc.pinSalt',
  panicHash: 'cc.panicHash',
  session: 'cc.session',
} as const;

const OPTS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

const get = (k: string) => SecureStore.getItemAsync(k, OPTS);
const put = (k: string, v: string) => SecureStore.setItemAsync(k, v, OPTS);
const del = (k: string) => SecureStore.deleteItemAsync(k, OPTS);

// ---------------------------------------------------------------------------
// Identity (X25519 identity, Ed25519 signing, X25519 signed prekey)
// ---------------------------------------------------------------------------

export async function saveIdentityKeys(id: IdentityKeys): Promise<void> {
  await Promise.all([
    put(K.identitySecret, id.identitySecret),
    put(K.identityPublic, id.identityPublic),
    put(K.signingSecret, id.signingSecret),
    put(K.signingPublic, id.signingPublic),
    put(K.prekeySecret, id.prekeySecret),
    put(K.prekeyPublic, id.prekeyPublic),
  ]);
}

export async function getIdentityKeys(): Promise<IdentityKeys | null> {
  const [identitySecret, identityPublic, signingSecret, signingPublic, prekeySecret, prekeyPublic] =
    await Promise.all([
      get(K.identitySecret),
      get(K.identityPublic),
      get(K.signingSecret),
      get(K.signingPublic),
      get(K.prekeySecret),
      get(K.prekeyPublic),
    ]);
  if (!identitySecret || !identityPublic || !signingSecret || !signingPublic || !prekeySecret || !prekeyPublic) {
    return null;
  }
  return { identitySecret, identityPublic, signingSecret, signingPublic, prekeySecret, prekeyPublic };
}

/** Device-local key encrypting the vault (sessions + decoded-message cache). */
export async function getStorageKey(): Promise<string> {
  const existing = await get(K.storageKey);
  if (existing) return existing;
  const fresh = encodeBase64(nacl.randomBytes(nacl.secretbox.keyLength));
  await put(K.storageKey, fresh);
  return fresh;
}

// ---------------------------------------------------------------------------
// Session token (API auth)
// ---------------------------------------------------------------------------

export async function saveSessionToken(token: string): Promise<void> {
  await put(K.session, token);
}

export async function getSessionToken(): Promise<string | null> {
  return get(K.session);
}

export async function clearSessionToken(): Promise<void> {
  await del(K.session);
}

// ---------------------------------------------------------------------------
// App-lock PIN + panic PIN
// ---------------------------------------------------------------------------

export async function savePin(hash: string, salt: string): Promise<void> {
  await put(K.pinHash, hash);
  await put(K.pinSalt, salt);
}

export async function getPin(): Promise<{ hash: string; salt: string } | null> {
  const [hash, salt] = await Promise.all([get(K.pinHash), get(K.pinSalt)]);
  return hash && salt ? { hash, salt } : null;
}

export async function clearPin(): Promise<void> {
  await del(K.pinHash);
  await del(K.pinSalt);
}

export async function savePanicHash(hash: string): Promise<void> {
  await put(K.panicHash, hash);
}

export async function getPanicHash(): Promise<string | null> {
  return get(K.panicHash);
}

export async function clearPanicHash(): Promise<void> {
  await del(K.panicHash);
}

/**
 * Panic wipe: destroys all private keys and the vault key (rendering every
 * stored ciphertext AND the local vault permanently unreadable), then clears
 * all cached app state.
 */
export async function wipeAll(): Promise<void> {
  await Promise.all(Object.values(K).map((k) => del(k)));
  await AsyncStorage.clear();
}
