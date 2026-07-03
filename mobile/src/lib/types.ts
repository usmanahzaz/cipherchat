export interface Profile {
  id: string;
  email: string;
  /** Identity fields are null until the device has generated and published keys. */
  secure_id: string | null;
  public_key: string | null; // X25519 identity key
  sign_public_key: string | null; // Ed25519 signing key
  signed_prekey: string | null; // X25519 signed prekey (session setup)
  prekey_signature: string | null; // Ed25519 signature over signed_prekey
}

/** A profile that has completed key setup and can receive messages. */
export interface PeerProfile extends Profile {
  secure_id: string;
  public_key: string;
  sign_public_key: string;
  signed_prekey: string;
  prekey_signature: string;
}

export interface Contact {
  id: string;
  owner_id: string;
  contact_id: string;
  alias: string | null;
  profile: PeerProfile;
}

export interface Message {
  id: string;
  sender_id: string;
  recipient_id: string;
  /** v2 ratchet envelope (JSON: version, header, nonce, ciphertext) — opaque to the server. */
  ciphertext: string;
  nonce: string;
  one_time: boolean;
  delivered_at: string | null;
  read_at: string | null;
  created_at: string;
}
