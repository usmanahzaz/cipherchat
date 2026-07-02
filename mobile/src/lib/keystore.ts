/**
 * Secure on-device storage backed by iOS Keychain / Android Keystore via
 * expo-secure-store. The private key is written here at generation time and
 * never leaves the device or this module's callers.
 */
import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';
import type { KeyPairB64 } from './crypto';

const K = {
  secretKey: 'cc.secretKey',
  publicKey: 'cc.publicKey',
  pinHash: 'cc.pinHash',
  pinSalt: 'cc.pinSalt',
  panicHash: 'cc.panicHash',
} as const;

const OPTS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export async function saveKeyPair(kp: KeyPairB64): Promise<void> {
  await SecureStore.setItemAsync(K.secretKey, kp.secretKey, OPTS);
  await SecureStore.setItemAsync(K.publicKey, kp.publicKey, OPTS);
}

export async function getKeyPair(): Promise<KeyPairB64 | null> {
  const [secretKey, publicKey] = await Promise.all([
    SecureStore.getItemAsync(K.secretKey, OPTS),
    SecureStore.getItemAsync(K.publicKey, OPTS),
  ]);
  return secretKey && publicKey ? { secretKey, publicKey } : null;
}

export async function savePin(hash: string, salt: string): Promise<void> {
  await SecureStore.setItemAsync(K.pinHash, hash, OPTS);
  await SecureStore.setItemAsync(K.pinSalt, salt, OPTS);
}

export async function getPin(): Promise<{ hash: string; salt: string } | null> {
  const [hash, salt] = await Promise.all([
    SecureStore.getItemAsync(K.pinHash, OPTS),
    SecureStore.getItemAsync(K.pinSalt, OPTS),
  ]);
  return hash && salt ? { hash, salt } : null;
}

export async function clearPin(): Promise<void> {
  await SecureStore.deleteItemAsync(K.pinHash, OPTS);
  await SecureStore.deleteItemAsync(K.pinSalt, OPTS);
}

export async function savePanicHash(hash: string): Promise<void> {
  await SecureStore.setItemAsync(K.panicHash, hash, OPTS);
}

export async function getPanicHash(): Promise<string | null> {
  return SecureStore.getItemAsync(K.panicHash, OPTS);
}

export async function clearPanicHash(): Promise<void> {
  await SecureStore.deleteItemAsync(K.panicHash, OPTS);
}

/**
 * Panic wipe: destroys the private key (rendering every stored ciphertext
 * permanently unreadable), all secure material, and all cached app state.
 */
export async function wipeAll(): Promise<void> {
  await Promise.all(Object.values(K).map((k) => SecureStore.deleteItemAsync(k, OPTS)));
  await AsyncStorage.clear();
}
