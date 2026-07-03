import { create } from 'zustand';
import { api, errorMessage, loadSession, setSession } from '../lib/api';
import { secureIdFromPublicKey } from '../lib/crypto';
import { getIdentityKeys, saveIdentityKeys, wipeAll } from '../lib/keystore';
import { bundleFromIdentity, generateIdentity } from '../lib/ratchet';
import type { Profile } from '../lib/types';

interface AuthState {
  initialized: boolean;
  userId: string | null;
  profile: Profile | null;
  hasKeys: boolean;
  /** True when signed in but this device has no published key material yet. */
  needsKeySetup: boolean;

  init: () => Promise<void>;
  signUp: (email: string, password: string) => Promise<string | null>;
  signIn: (email: string, password: string) => Promise<string | null>;
  /** Generates the full identity (X25519 identity + Ed25519 signing +
   *  signed prekey) on-device, stores secrets in Keychain/Keystore, and
   *  publishes only the public bundle + derived Secure ID. */
  provisionKeys: () => Promise<string | null>;
  signOut: () => Promise<void>;
  panicWipe: () => Promise<void>;
}

export const useAuth = create<AuthState>((set, get) => ({
  initialized: false,
  userId: null,
  profile: null,
  hasKeys: false,
  needsKeySetup: false,

  init: async () => {
    const token = await loadSession();
    if (!token) {
      set({ initialized: true, userId: null, profile: null, hasKeys: false });
      return;
    }
    try {
      const [{ profile }, identity] = await Promise.all([api.me(), getIdentityKeys()]);
      set({
        initialized: true,
        userId: profile.id,
        profile,
        hasKeys: !!identity,
        needsKeySetup: !identity || !profile.public_key,
      });
    } catch {
      // Stale/invalid session (or server unreachable) → back to onboarding.
      await setSession(null);
      set({ initialized: true, userId: null, profile: null, hasKeys: false });
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
      const identity = await getIdentityKeys();
      set({
        userId: profile.id,
        profile,
        hasKeys: !!identity,
        needsKeySetup: !identity || !profile.public_key,
      });
      return null;
    } catch (e) {
      return errorMessage(e);
    }
  },

  provisionKeys: async () => {
    if (!get().userId) return 'Not signed in.';
    try {
      // Reuse existing local identity if present (e.g. retried setup).
      const identity = (await getIdentityKeys()) ?? generateIdentity();
      await saveIdentityKeys(identity);
      const bundle = bundleFromIdentity(identity);
      const { profile } = await api.publishKeys({
        public_key: bundle.identity_key,
        secure_id: secureIdFromPublicKey(bundle.identity_key),
        sign_public_key: bundle.signing_key,
        signed_prekey: bundle.signed_prekey,
        prekey_signature: bundle.prekey_signature,
      });
      set({ profile, hasKeys: true, needsKeySetup: false });
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
    set({ userId: null, profile: null, hasKeys: false, needsKeySetup: false });
  },

  panicWipe: async () => {
    // Best-effort server cleanup, then destroy everything local. Destroying
    // the identity keys and vault key makes every stored ciphertext AND the
    // local vault permanently unreadable.
    try {
      await api.panic();
    } catch {
      // Offline panic still wipes locally.
    }
    await setSession(null);
    await wipeAll();
    set({ userId: null, profile: null, hasKeys: false, needsKeySetup: false });
  },
}));
