import { create } from 'zustand';
import { api, errorMessage, loadSession, setSession } from '../lib/api';
import { generateKeyPair, secureIdFromPublicKey } from '../lib/crypto';
import { getKeyPair, saveKeyPair, wipeAll } from '../lib/keystore';
import type { KeyPairB64 } from '../lib/crypto';
import type { Profile } from '../lib/types';

interface AuthState {
  initialized: boolean;
  userId: string | null;
  profile: Profile | null;
  keyPair: KeyPairB64 | null;
  /** True when signed in but this device has no published key pair yet. */
  needsKeySetup: boolean;

  init: () => Promise<void>;
  signUp: (email: string, password: string) => Promise<string | null>;
  signIn: (email: string, password: string) => Promise<string | null>;
  /** Generates X25519 keys on-device, stores the secret in Keychain/Keystore,
   *  publishes only the public key + derived Secure ID. */
  provisionKeys: () => Promise<string | null>;
  signOut: () => Promise<void>;
  panicWipe: () => Promise<void>;
}

export const useAuth = create<AuthState>((set, get) => ({
  initialized: false,
  userId: null,
  profile: null,
  keyPair: null,
  needsKeySetup: false,

  init: async () => {
    const token = await loadSession();
    if (!token) {
      set({ initialized: true, userId: null, profile: null, keyPair: null });
      return;
    }
    try {
      const [{ profile }, keyPair] = await Promise.all([api.me(), getKeyPair()]);
      set({
        initialized: true,
        userId: profile.id,
        profile,
        keyPair,
        needsKeySetup: !keyPair || !profile.public_key,
      });
    } catch {
      // Stale/invalid session (or server unreachable) → back to onboarding.
      await setSession(null);
      set({ initialized: true, userId: null, profile: null, keyPair: null });
    }
  },

  signUp: async (email, password) => {
    try {
      const { token, profile } = await api.signup(email.trim(), password);
      await setSession(token);
      set({ userId: profile.id, profile, needsKeySetup: true });
      return null;
    } catch (e) {
      return errorMessage(e);
    }
  },

  signIn: async (email, password) => {
    try {
      const { token, profile } = await api.login(email.trim(), password);
      await setSession(token);
      const keyPair = await getKeyPair();
      set({
        userId: profile.id,
        profile,
        keyPair,
        needsKeySetup: !keyPair || !profile.public_key,
      });
      return null;
    } catch (e) {
      return errorMessage(e);
    }
  },

  provisionKeys: async () => {
    if (!get().userId) return 'Not signed in.';
    try {
      // Reuse existing local keys if present (e.g. retried setup).
      const keyPair = (await getKeyPair()) ?? generateKeyPair();
      await saveKeyPair(keyPair);
      const { profile } = await api.publishKeys(
        keyPair.publicKey,
        secureIdFromPublicKey(keyPair.publicKey),
      );
      set({ keyPair, profile, needsKeySetup: false });
      return null;
    } catch (e) {
      return errorMessage(e);
    }
  },

  signOut: async () => {
    try {
      await api.setPushToken(null);
    } catch {
      // best-effort
    }
    await setSession(null);
    set({ userId: null, profile: null, keyPair: null, needsKeySetup: false });
  },

  panicWipe: async () => {
    // Best-effort server cleanup, then destroy everything local. Destroying
    // the private key makes all remaining ciphertext permanently unreadable.
    try {
      await api.panic();
    } catch {
      // Offline panic still wipes locally.
    }
    await setSession(null);
    await wipeAll();
    set({ userId: null, profile: null, keyPair: null, needsKeySetup: false });
  },
}));
