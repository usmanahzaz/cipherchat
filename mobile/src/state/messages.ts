import { create } from 'zustand';
import type { RealtimeChannel } from '@supabase/supabase-js';
import { encryptMessage } from '../lib/crypto';
import { supabase, type Contact, type Message, type Profile } from '../lib/supabase';
import { useAuth } from './auth';

/**
 * Messages are held ONLY as ciphertext, both on the server and in this store.
 * Decryption happens inside MessageBubble at render/decode time and the
 * resulting plaintext lives in transient component state for max 10 seconds.
 */
interface MessagesState {
  contacts: Contact[];
  /** contactId (peer user id) -> encrypted messages, oldest first */
  threads: Record<string, Message[]>;
  channel: RealtimeChannel | null;

  loadContacts: () => Promise<void>;
  addContact: (identifier: string, alias?: string) => Promise<string | null>;
  loadThread: (peerId: string) => Promise<void>;
  sendMessage: (peer: Profile, text: string, oneTime: boolean) => Promise<string | null>;
  burnMessage: (message: Message) => Promise<void>;
  markDelivered: (peerId: string) => Promise<void>;
  subscribe: () => void;
  unsubscribe: () => void;
  reset: () => void;
}

function upsertMessage(list: Message[], msg: Message): Message[] {
  const without = list.filter((m) => m.id !== msg.id);
  return [...without, msg].sort((a, b) => a.created_at.localeCompare(b.created_at));
}

export const useMessages = create<MessagesState>((set, get) => ({
  contacts: [],
  threads: {},
  channel: null,

  loadContacts: async () => {
    const { data } = await supabase
      .from('contacts')
      .select('id, owner_id, contact_id, alias, profile:profiles!contacts_contact_id_fkey(id, email, secure_id, public_key)')
      .order('created_at', { ascending: true });
    if (data) set({ contacts: data as unknown as Contact[] });
  },

  addContact: async (identifier, alias) => {
    const me = useAuth.getState();
    if (!me.userId) return 'Not signed in.';
    // lookup_profile is a SECURITY DEFINER RPC that only returns a row on an
    // exact Secure ID / email / public key match — no browsing or fuzzy search.
    const { data, error } = await supabase.rpc('lookup_profile', {
      identifier: identifier.trim(),
    });
    if (error) return error.message;
    const found = (data as Profile[] | null)?.[0];
    if (!found) return 'No user found for that Secure ID, email, or public key.';
    if (found.id === me.userId) return 'That is your own ID.';

    const { error: insErr } = await supabase.from('contacts').upsert(
      { owner_id: me.userId, contact_id: found.id, alias: alias || null },
      { onConflict: 'owner_id,contact_id' },
    );
    if (insErr) return insErr.message;
    await get().loadContacts();
    return null;
  },

  loadThread: async (peerId) => {
    const me = useAuth.getState().userId;
    if (!me) return;
    const { data } = await supabase
      .from('messages')
      .select('*')
      .or(
        `and(sender_id.eq.${me},recipient_id.eq.${peerId}),and(sender_id.eq.${peerId},recipient_id.eq.${me})`,
      )
      .order('created_at', { ascending: true });
    if (data) set((s) => ({ threads: { ...s.threads, [peerId]: data as Message[] } }));
  },

  sendMessage: async (peer, text, oneTime) => {
    const { userId, keyPair } = useAuth.getState();
    if (!userId || !keyPair) return 'Missing keys.';
    // Encrypt on-device before anything touches the network.
    const payload = encryptMessage(text, peer.public_key, keyPair.secretKey);
    const { data, error } = await supabase
      .from('messages')
      .insert({
        sender_id: userId,
        recipient_id: peer.id,
        ciphertext: payload.ciphertext,
        nonce: payload.nonce,
        one_time: oneTime,
      })
      .select('*')
      .single();
    if (error) return error.message;
    set((s) => ({
      threads: { ...s.threads, [peer.id]: upsertMessage(s.threads[peer.id] ?? [], data as Message) },
    }));
    return null;
  },

  burnMessage: async (message) => {
    const me = useAuth.getState().userId;
    const peerId = message.sender_id === me ? message.recipient_id : message.sender_id;
    await supabase.from('messages').delete().eq('id', message.id);
    set((s) => ({
      threads: {
        ...s.threads,
        [peerId]: (s.threads[peerId] ?? []).filter((m) => m.id !== message.id),
      },
    }));
  },

  markDelivered: async (peerId) => {
    const me = useAuth.getState().userId;
    if (!me) return;
    await supabase
      .from('messages')
      .update({ delivered_at: new Date().toISOString() })
      .eq('sender_id', peerId)
      .eq('recipient_id', me)
      .is('delivered_at', null);
  },

  subscribe: () => {
    const me = useAuth.getState().userId;
    if (!me || get().channel) return;
    const channel = supabase
      .channel('messages-inbox')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'messages', filter: `recipient_id=eq.${me}` },
        (payload) => {
          const msg = payload.new as Message;
          set((s) => ({
            threads: {
              ...s.threads,
              [msg.sender_id]: upsertMessage(s.threads[msg.sender_id] ?? [], msg),
            },
          }));
        },
      )
      .on(
        'postgres_changes',
        { event: 'DELETE', schema: 'public', table: 'messages' },
        (payload) => {
          const gone = payload.old as Partial<Message>;
          if (!gone.id) return;
          set((s) => {
            const threads = Object.fromEntries(
              Object.entries(s.threads).map(([k, v]) => [k, v.filter((m) => m.id !== gone.id)]),
            );
            return { threads };
          });
        },
      )
      .subscribe();
    set({ channel });
  },

  unsubscribe: () => {
    const { channel } = get();
    if (channel) supabase.removeChannel(channel);
    set({ channel: null });
  },

  reset: () => {
    get().unsubscribe();
    set({ contacts: [], threads: {} });
  },
}));
