/**
 * Encrypted-at-rest local storage.
 *
 * Forward secrecy means transport keys are destroyed after one use — so, like
 * Signal, the device keeps its own copy of conversation data in a local vault
 * encrypted with a device-only key (XSalsa20-Poly1305, key in Keychain/
 * Keystore). Used for (a) ratchet session state and (b) plaintexts the user
 * has already decoded, so Decode keeps working after the transport keys are
 * gone. One-time messages are deliberately never vaulted: after their single
 * reveal, no key exists anywhere that can show them again.
 *
 * The panic wipe destroys the vault key, rendering the vault unreadable, and
 * clears the blobs.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import nacl from 'tweetnacl';
import { decodeBase64, decodeUTF8, encodeBase64, encodeUTF8 } from 'tweetnacl-util';
import { getStorageKey } from './keystore';

const MSG_PREFIX = 'cc.vault.msg.';
const KV_PREFIX = 'cc.vault.kv.';

async function key(): Promise<Uint8Array> {
  return decodeBase64(await getStorageKey());
}

function seal(plaintext: string, k: Uint8Array): string {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const box = nacl.secretbox(decodeUTF8(plaintext), nonce, k);
  const out = new Uint8Array(nonce.length + box.length);
  out.set(nonce);
  out.set(box, nonce.length);
  return encodeBase64(out);
}

function open(sealed: string, k: Uint8Array): string | null {
  try {
    const raw = decodeBase64(sealed);
    const nonce = raw.slice(0, nacl.secretbox.nonceLength);
    const box = raw.slice(nacl.secretbox.nonceLength);
    const opened = nacl.secretbox.open(box, nonce, k);
    return opened ? encodeUTF8(opened) : null;
  } catch {
    return null;
  }
}

export const vault = {
  async putMessage(messageId: string, plaintext: string): Promise<void> {
    await AsyncStorage.setItem(MSG_PREFIX + messageId, seal(plaintext, await key()));
  },

  async getMessage(messageId: string): Promise<string | null> {
    const sealed = await AsyncStorage.getItem(MSG_PREFIX + messageId);
    return sealed ? open(sealed, await key()) : null;
  },

  async deleteMessage(messageId: string): Promise<void> {
    await AsyncStorage.removeItem(MSG_PREFIX + messageId);
  },

  /** Encrypted generic JSON storage (used for ratchet session state). */
  async setJson(name: string, value: unknown): Promise<void> {
    await AsyncStorage.setItem(KV_PREFIX + name, seal(JSON.stringify(value), await key()));
  },

  async getJson<T>(name: string): Promise<T | null> {
    const sealed = await AsyncStorage.getItem(KV_PREFIX + name);
    if (!sealed) return null;
    const text = open(sealed, await key());
    if (text === null) return null;
    try {
      return JSON.parse(text) as T;
    } catch {
      return null;
    }
  },
};
