import { create } from 'zustand';
import { generateKeyPair, secureIdFromPublicKey } from '../lib/crypto';
import { getKeyPair, saveKeyPair, wipeAll } from '../lib/keystore';
import { supabase, type Profile } from '../lib/supabase';
import type { KeyPairB64 } from '../lib/crypto';

interface AuthState {
  initialized: boolean;
  userId: string | null;
  profile: Profile | null;
  keyPair: KeyPairB64 | null;
  /** True when signed in but this device has no private key yet. */
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
    const { data } = await supabase.auth.getSession();
    const userId = data.session?.user.id ?? null;
    if (!userId) {
      set({ initialized: true, userId: null, profile: null, keyPair: null });
      return;
    }
    const keyPair = await getKeyPair();
    const { data: profile } = await supabase
      .from('profiles')
      .select('id, email, secure_id, public_key')
      .eq('id', userId)
      .maybeSingle();
    set({
      initialized: true,
      userId,
      profile: (profile as Profile) ?? null,
      keyPair,
      needsKeySetup: !keyPair || !profile,
    });
  },

  signUp: async (email, password) => {
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) return error.message;
    if (!data.session) return 'Check your inbox to confirm your email, then log in.';
    set({ userId: data.session.user.id, needsKeySetup: true });
    return null;
  },

  signIn: async (email, password) => {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return error.message;
    set({ userId: data.session.user.id });
    await get().init();
    return null;
  },

  provisionKeys: async () => {
    const { userId } = get();
    if (!userId) return 'Not signed in.';
    const { data: userRes } = await supabase.auth.getUser();
    const email = userRes.user?.email ?? '';

    // Reuse existing local keys if present (e.g. retried setup).
    const keyPair = (await getKeyPair()) ?? generateKeyPair();
    await saveKeyPair(keyPair);
    const secureId = secureIdFromPublicKey(keyPair.publicKey);

    const { data: profile, error } = await supabase
      .from('profiles')
      .upsert(
        { id: userId, email, secure_id: secureId, public_key: keyPair.publicKey },
        { onConflict: 'id' },
      )
      .select('id, email, secure_id, public_key')
      .single();
    if (error) return error.message;

    set({ keyPair, profile: profile as Profile, needsKeySetup: false });
    return null;
  },

  signOut: async () => {
    await supabase.auth.signOut();
    set({ userId: null, profile: null, keyPair: null, needsKeySetup: false });
  },

  panicWipe: async () => {
    // Best-effort server cleanup, then destroy everything local. Destroying
    // the private key makes all remaining ciphertext permanently unreadable.
    const { userId } = get();
    try {
      if (userId) {
        await supabase.from('messages').delete().eq('recipient_id', userId);
        await supabase.from('messages').delete().eq('sender_id', userId);
        await supabase.from('profiles').update({ push_token: null }).eq('id', userId);
      }
      await supabase.auth.signOut();
    } catch {
      // Offline panic still wipes locally.
    }
    await wipeAll();
    set({ userId: null, profile: null, keyPair: null, needsKeySetup: false });
  },
}));
