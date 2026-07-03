export interface Profile {
  id: string;
  email: string;
  /** Null until the device has generated and published its keys. */
  secure_id: string | null;
  public_key: string | null;
}

/** A profile that has completed key setup and can receive messages. */
export interface PeerProfile extends Profile {
  secure_id: string;
  public_key: string;
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
  ciphertext: string;
  nonce: string;
  one_time: boolean;
  delivered_at: string | null;
  read_at: string | null;
  created_at: string;
}
