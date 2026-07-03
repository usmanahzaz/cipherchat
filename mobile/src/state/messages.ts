import { create } from 'zustand';
import { api, errorMessage, wsUrl, type RealtimeEvent } from '../lib/api';
import { encryptMessage } from '../lib/crypto';
import type { Contact, Message, PeerProfile } from '../lib/types';
import { useAuth } from './auth';

/**
 * Messages are held ONLY as ciphertext, both on the server and in this store.
 * Decryption happens inside MessageBubble at render/decode time and the
 * resulting plaintext lives in transient component state for max 10 seconds.
 */
interface MessagesState {
  contacts: Contact[];
  /** peer user id -> encrypted messages, oldest first */
  threads: Record<string, Message[]>;
  socket: WebSocket | null;

  loadContacts: () => Promise<void>;
  addContact: (identifier: string, alias?: string) => Promise<string | null>;
  loadThread: (peerId: string) => Promise<void>;
  sendMessage: (peer: PeerProfile, text: string, oneTime: boolean) => Promise<string | null>;
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

let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let wantSocket = false;

export const useMessages = create<MessagesState>((set, get) => ({
  contacts: [],
  threads: {},
  socket: null,

  loadContacts: async () => {
    try {
      const { contacts } = await api.contacts();
      set({ contacts });
    } catch {
      // keep whatever we had; screens surface errors on user actions
    }
  },

  addContact: async (identifier, alias) => {
    const me = useAuth.getState();
    if (!me.userId) return 'Not signed in.';
    try {
      // Exact-match lookup only (Secure ID / email / public key) — no browsing.
      const { profile } = await api.lookup(identifier.trim());
      if (profile.id === me.userId) return 'That is your own ID.';
      await api.addContact(profile.id, alias);
      await get().loadContacts();
      return null;
    } catch (e) {
      return errorMessage(e);
    }
  },

  loadThread: async (peerId) => {
    try {
      const { messages } = await api.thread(peerId);
      set((s) => ({ threads: { ...s.threads, [peerId]: messages } }));
    } catch {
      // transient; realtime + next focus will refresh
    }
  },

  sendMessage: async (peer, text, oneTime) => {
    const { keyPair } = useAuth.getState();
    if (!keyPair) return 'Missing keys.';
    try {
      // Encrypt on-device before anything touches the network.
      const payload = encryptMessage(text, peer.public_key, keyPair.secretKey);
      const { message } = await api.send(peer.id, payload.ciphertext, payload.nonce, oneTime);
      set((s) => ({
        threads: { ...s.threads, [peer.id]: upsertMessage(s.threads[peer.id] ?? [], message) },
      }));
      return null;
    } catch (e) {
      return errorMessage(e);
    }
  },

  burnMessage: async (message) => {
    const me = useAuth.getState().userId;
    const peerId = message.sender_id === me ? message.recipient_id : message.sender_id;
    try {
      await api.deleteMessage(message.id);
    } catch {
      // still remove locally; server delete retried implicitly on next burn
    }
    set((s) => ({
      threads: {
        ...s.threads,
        [peerId]: (s.threads[peerId] ?? []).filter((m) => m.id !== message.id),
      },
    }));
  },

  markDelivered: async (peerId) => {
    try {
      await api.markDelivered(peerId);
    } catch {
      // best-effort
    }
  },

  subscribe: () => {
    wantSocket = true;
    connect(set, get);
  },

  unsubscribe: () => {
    wantSocket = false;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = null;
    get().socket?.close();
    set({ socket: null });
  },

  reset: () => {
    get().unsubscribe();
    set({ contacts: [], threads: {} });
  },
}));

function connect(
  set: (fn: (s: MessagesState) => Partial<MessagesState>) => void,
  get: () => MessagesState,
) {
  if (!wantSocket || get().socket) return;
  const url = wsUrl();
  if (!url) return;

  const socket = new WebSocket(url);

  socket.onmessage = (evt) => {
    let event: RealtimeEvent;
    try {
      event = JSON.parse(String(evt.data));
    } catch {
      return;
    }
    if (event.type === 'message:new') {
      const msg = event.message;
      set((s) => ({
        threads: {
          ...s.threads,
          [msg.sender_id]: upsertMessage(s.threads[msg.sender_id] ?? [], msg),
        },
      }));
    } else if (event.type === 'message:deleted') {
      const deletedId = event.id;
      set((s) => ({
        threads: Object.fromEntries(
          Object.entries(s.threads).map(([k, v]) => [k, v.filter((m) => m.id !== deletedId)]),
        ),
      }));
    } else if (event.type === 'messages:delivered') {
      const { peer_id: peerId, delivered_at: deliveredAt } = event;
      set((s) => ({
        threads: {
          ...s.threads,
          [peerId]: (s.threads[peerId] ?? []).map((m) =>
            m.recipient_id === peerId && !m.delivered_at ? { ...m, delivered_at: deliveredAt } : m,
          ),
        },
      }));
    }
  };

  socket.onclose = () => {
    set(() => ({ socket: null }));
    if (wantSocket && !reconnectTimer) {
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connect(set, get);
      }, 2000);
    }
  };
  socket.onerror = () => socket.close();

  set(() => ({ socket }));
}
