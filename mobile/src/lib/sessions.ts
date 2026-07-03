/**
 * Per-peer Double Ratchet session management.
 *
 * A peer can have multiple live sessions (e.g. both sides initiated
 * simultaneously); each is addressed by the sid carried in every message
 * header. For sending, both devices deterministically converge on the same
 * session (lowest sid) once they know the same set. Session state is
 * persisted through the encrypted vault after every operation, so consumed
 * chain keys are truly gone from the device.
 */
import type { PeerProfile } from './types';
import type { IdentityKeys, Session } from './ratchet';
import {
  createInboundSession,
  createOutboundSession,
  decrypt,
  encrypt,
  parseEnvelope,
  verifyBundle,
} from './ratchet';
import { getIdentityKeys } from './keystore';
import { vault } from './vault';

interface PeerSessions {
  sessions: Record<string, Session>;
}

const storeName = (peerId: string) => `sessions.${peerId}`;

async function load(peerId: string): Promise<PeerSessions> {
  return (await vault.getJson<PeerSessions>(storeName(peerId))) ?? { sessions: {} };
}

async function save(peerId: string, data: PeerSessions): Promise<void> {
  await vault.setJson(storeName(peerId), data);
}

/** Sending session: prefer one that's ready to send, lowest sid for determinism. */
function pickSendSession(data: PeerSessions): Session | null {
  const ready = Object.values(data.sessions)
    .filter((s) => s.cks !== null)
    .sort((a, b) => a.sid.localeCompare(b.sid));
  return ready[0] ?? null;
}

export async function encryptFor(peer: PeerProfile, plaintext: string): Promise<string> {
  const me: IdentityKeys | null = await getIdentityKeys();
  if (!me) throw new Error('Missing identity keys.');
  const data = await load(peer.id);

  let session = pickSendSession(data);
  if (!session) {
    const bundle = {
      identity_key: peer.public_key,
      signing_key: peer.sign_public_key,
      signed_prekey: peer.signed_prekey,
      prekey_signature: peer.prekey_signature,
    };
    if (!verifyBundle(bundle)) {
      throw new Error("This contact's security keys failed verification. Re-add the contact.");
    }
    session = createOutboundSession(me, bundle);
    data.sessions[session.sid] = session;
  }

  const envelope = encrypt(session, plaintext); // mutates the chain forward
  data.sessions[session.sid] = session;
  await save(peer.id, data);
  return envelope;
}

/**
 * Decrypts an incoming envelope from a peer, creating an inbound session on
 * the fly when the header carries X3DH init material. Returns null when the
 * message is unreadable (consumed keys, tampering, or unknown session).
 */
export async function decryptFrom(peerId: string, peerIdentityKey: string, raw: string): Promise<string | null> {
  const me = await getIdentityKeys();
  if (!me) return null;
  const parsed = parseEnvelope(raw);
  if (!parsed) return null;
  const { header } = parsed;
  const data = await load(peerId);

  let session = data.sessions[header.sid] ?? null;
  if (!session && header.init) {
    // Bind the session to the contact we THINK we're talking to: the init
    // block's identity key must match the peer's published identity key.
    if (header.init.ik !== peerIdentityKey) return null;
    session = createInboundSession(me, header.init);
  }
  if (!session) return null;

  const result = decrypt(session, raw);
  if (!result) return null;

  data.sessions[header.sid] = result.session; // advanced state; old keys gone
  await save(peerId, data);
  return result.plaintext;
}
