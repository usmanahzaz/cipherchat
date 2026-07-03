/**
 * REST client for the CipherChat server (cipherchat/server).
 *
 * Zero configuration: when the app runs through the Expo dev server, the
 * backend is assumed to be on the same machine, so its address is derived
 * from Expo's own host — no .env needed. Set EXPO_PUBLIC_API_URL to override
 * (e.g. a deployed server).
 *
 * Everything crossing this boundary is either public identity material or
 * an opaque {ciphertext, nonce} blob. Plaintext never enters this module.
 */
import Constants from 'expo-constants';
import { getSessionToken, saveSessionToken, clearSessionToken } from './keystore';
import type { Contact, Message, Profile } from './types';

function resolveBaseUrl(): string {
  const explicit = process.env.EXPO_PUBLIC_API_URL;
  if (explicit) return explicit.replace(/\/$/, '');
  // hostUri is e.g. "192.168.1.23:8081" when served by `expo start`.
  const host = Constants.expoConfig?.hostUri?.split(':')[0];
  return host ? `http://${host}:4000` : 'http://localhost:4000';
}

export const API_URL = resolveBaseUrl();

let sessionToken: string | null = null;

export async function loadSession(): Promise<string | null> {
  sessionToken = await getSessionToken();
  return sessionToken;
}

export async function setSession(token: string | null): Promise<void> {
  sessionToken = token;
  if (token) await saveSessionToken(token);
  else await clearSessionToken();
}

export function wsUrl(): string | null {
  if (!sessionToken) return null;
  return `${API_URL.replace(/^http/, 'ws')}/ws?token=${encodeURIComponent(sessionToken)}`;
}

class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function request<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      method: options.method ?? 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch {
    throw new ApiError(`Cannot reach the CipherChat server at ${API_URL}. Is it running? (cd cipherchat/server && npm start)`, 0);
  }
  const json = (await res.json().catch(() => ({}))) as { error?: string } & T;
  if (!res.ok) throw new ApiError(json.error ?? `Request failed (${res.status})`, res.status);
  return json;
}

export const api = {
  signup: (email: string, password: string) =>
    request<{ token: string; profile: Profile }>('/auth/signup', {
      method: 'POST',
      body: { email, password },
    }),

  login: (email: string, password: string) =>
    request<{ token: string; profile: Profile }>('/auth/login', {
      method: 'POST',
      body: { email, password },
    }),

  me: () => request<{ profile: Profile }>('/me'),

  publishKeys: (bundle: {
    public_key: string;
    secure_id: string;
    sign_public_key: string;
    signed_prekey: string;
    prekey_signature: string;
  }) => request<{ profile: Profile }>('/me/keys', { method: 'POST', body: bundle }),

  setPushToken: (token: string | null) =>
    request<{ ok: true }>('/me/push-token', { method: 'POST', body: { token } }),

  lookup: (identifier: string) =>
    request<{ profile: Profile }>('/lookup', { method: 'POST', body: { identifier } }),

  contacts: () => request<{ contacts: Contact[] }>('/contacts'),

  addContact: (contact_id: string, alias?: string) =>
    request<{ ok: true }>('/contacts', { method: 'POST', body: { contact_id, alias } }),

  thread: (peerId: string) => request<{ messages: Message[] }>(`/messages/${peerId}`),

  send: (recipient_id: string, ciphertext: string, nonce: string, one_time: boolean) =>
    request<{ message: Message }>('/messages', {
      method: 'POST',
      body: { recipient_id, ciphertext, nonce, one_time },
    }),

  markDelivered: (peer_id: string) =>
    request<{ ok: true }>('/messages/delivered', { method: 'POST', body: { peer_id } }),

  deleteMessage: (id: string) => request<{ ok: true }>(`/messages/${id}`, { method: 'DELETE' }),

  panic: () => request<{ ok: true }>('/panic', { method: 'POST' }),
};

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : 'Something went wrong.';
}

/** Realtime events pushed by the server over the WebSocket. */
export type RealtimeEvent =
  | { type: 'message:new'; message: Message }
  | { type: 'message:deleted'; id: string; peer_id: string }
  | { type: 'messages:delivered'; peer_id: string; delivered_at: string };
