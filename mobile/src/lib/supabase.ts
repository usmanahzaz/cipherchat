import 'react-native-url-polyfill/auto';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { createClient } from '@supabase/supabase-js';

// Set these in mobile/.env (see README) — Expo inlines EXPO_PUBLIC_* vars.
const SUPABASE_URL = process.env.EXPO_PUBLIC_SUPABASE_URL ?? '';
const SUPABASE_ANON_KEY = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY ?? '';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    storage: AsyncStorage,
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: false,
  },
});

export interface Profile {
  id: string;
  email: string;
  secure_id: string;
  public_key: string;
}

export interface Contact {
  id: string;
  owner_id: string;
  contact_id: string;
  alias: string | null;
  profile: Profile;
}

export interface Message {
  id: string;
  sender_id: string;
  recipient_id: string;
  ciphertext: string;
  nonce: string;
  one_time: boolean;
  delivered_at: string | null;
  read_at: string | null;
  created_at: string;
}
