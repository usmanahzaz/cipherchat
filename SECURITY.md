# CipherChat — Security Notes

This document states precisely what CipherChat protects, how, and — just as important — what it
does **not** protect. No custom cryptographic primitives are used anywhere.

> **A note on marketing claims:** nothing is "100% uncrackable," and no honest security product
> claims to be. What CipherChat can truthfully claim: *messages are end-to-end encrypted with
> per-message keys that are destroyed after use, so even a complete copy of a device's keys
> cannot unlock past conversations — and the conversation automatically re-secures itself
> afterward.* That is the same class of guarantee Signal and WhatsApp advertise.

## Protocol

CipherChat implements Signal's published **X3DH + Double Ratchet** algorithms
([spec](https://signal.org/docs/)) in `mobile/src/lib/ratchet.ts`:

- **Session setup (X3DH):** each user publishes a signed prekey bundle (X25519 identity key,
  Ed25519 signing key, signed prekey). A sender verifies the prekey signature and derives a
  shared root key from three Diffie-Hellman exchanges, binding the session to both identities.
- **Symmetric-key ratchet:** every message is encrypted under a one-time key derived from an
  advancing HMAC-SHA-512 chain. The key is deleted the moment it is used.
- **DH ratchet:** every send/receive round-trip mixes fresh X25519 randomness into the root
  chain and rotates the chain keys.
- **Header authentication:** the ratchet header is bound to the ciphertext through the message
  key (`km = HMAC(mk, header)`), so tampering with either fails authentication.
- **Out-of-order delivery:** skipped message keys are stored (bounded at 256/chain) and deleted
  on use.

### What this buys

| Attack | Outcome |
|---|---|
| Server/network archive of all ciphertext | Unreadable, ever — keys never existed server-side |
| **Private keys stolen from a device** | **Past messages stay unreadable (forward secrecy)** |
| **Full session state copied from a device** | **Locked out after one message round-trip (post-compromise security / self-healing)** |
| Modified ciphertext or header | Rejected by Poly1305/HMAC without corrupting session state |
| Server substitutes a fake prekey | Rejected unless also signed — requires substituting the whole identity (see TOFU limitation) |

## Primitives (all from audited libraries)

| Purpose | Primitive | Implementation |
|---|---|---|
| Diffie-Hellman | X25519 | TweetNaCl.js (`nacl.scalarMult`) — [Cure53 audit](https://cure53.de/tweetnacl.pdf) |
| Signatures (prekeys) | Ed25519 | TweetNaCl.js (`nacl.sign`) |
| AEAD | XSalsa20-Poly1305 | TweetNaCl.js (`nacl.secretbox`) |
| KDF chains | HKDF / HMAC-SHA-512 | [@noble/hashes](https://github.com/paulmillr/noble-hashes) (Cure53-audited) |
| Randomness | OS CSPRNG | `react-native-get-random-values` → `crypto.getRandomValues` |

## What the server can and cannot see

**Cannot see, ever:** message content. The server stores ratchet envelopes (header + nonce +
ciphertext) produced on-device in an embedded SQLite database. There is no key escrow, no backup
of private keys, and every API endpoint checks ownership. Passwords are stored as scrypt hashes;
sessions are JWTs signed with a secret generated on first start.

**Can see (metadata):** who talks to whom, when, how often, message sizes, delivery timestamps,
emails, public key bundles, and push tokens. **E2EE hides content, not traffic patterns.**
Hiding metadata requires onion routing / sealed-sender designs out of scope for an MVP.

## Device-side protections

- **Private keys** (identity, signing, prekey) in iOS Keychain / Android Keystore
  (`expo-secure-store`, `WHEN_UNLOCKED_THIS_DEVICE_ONLY`) — excluded from cloud backups.
- **Encrypted local vault**: forward secrecy destroys transport keys after one use, so (like
  Signal's local database) already-decoded messages are kept on-device encrypted with
  XSalsa20-Poly1305 under a vault key in the Keychain/Keystore. Ratchet session state is stored
  the same way. One-time messages are **never** vaulted.
- **Plaintext display lifetime**: decoded text lives in component state for 10 seconds, then is
  destroyed. Never written to logs or the clipboard.
- **App lock**: PIN (salted hash in secure storage) + optional biometrics, re-locks on
  backgrounding.
- **Panic PIN**: silently destroys all private keys AND the vault key — every server blob and
  every vaulted message becomes permanently unreadable — then best-effort deletes server-side
  blobs. No recovery, by design.
- **One-time messages**: single reveal enforced cryptographically — the transport key is
  consumed on decode and no vault copy is made; the blob is also deleted from the server.
- **Screenshots**: blocked on chat screens (Android `FLAG_SECURE` hard block; iOS can only
  blank recordings — platform restriction).
- **Copy protection**: decoded text is non-selectable.
- **Notifications**: fixed body `"Encrypted message received"`, `VISIBILITY_SECRET` on Android.

## Known limitations (read before trusting this with lives or livelihoods)

1. **The ratchet implementation is unaudited.** It faithfully follows Signal's published
   specification, uses only audited primitive implementations, and passes adversarial tests
   (forward secrecy, self-healing, tampering, out-of-order) — but it is *our* code. Before
   marketing this as a secure messenger, commission an independent audit or replace the module
   with libsignal via a native bridge. This is the single most important line in this document.
2. **Trust-on-first-use identity distribution.** Prekey signatures stop the server swapping a
   prekey under an identity, but the server still introduces identities: a malicious server
   could hand you a wholly fake bundle for a contact (full-identity MITM) when you first add
   them. Mitigation available today: add contacts by scanning their QR code in person. Fix:
   safety-number verification UI + key-change alerts.
3. **No one-time prekeys.** X3DH here uses the signed prekey only, and prekey rotation is not
   implemented; first-message forward secrecy is weaker than Signal's until the first
   round-trip completes (the ratchet then takes over fully).
4. **The local vault trades FS for usability.** A device thief who defeats the OS lock, app
   lock, and Keychain/Keystore can read *vaulted* (already-decoded, non-one-time) messages —
   exactly like Signal's local database. The transport layer's forward secrecy protects
   everything the vault doesn't hold; the panic PIN destroys the vault key instantly.
5. **No key backup or multi-device.** Lose the device (or panic-wipe) and history is gone
   forever. Deliberate trade-off.
6. **PIN hashing is salted SHA-512, not a memory-hard KDF** — it gates the UI only and never
   derives encryption keys; Argon2id would still be better.
7. **A compromised OS wins.** Root/jailbreak malware can read the screen, keylog, or dump
   memory during the 10-second reveal. No messenger survives a hostile OS.
8. **Metadata is visible to the server operator** (see above).
9. **No rate limiting / abuse controls** on lookup or messaging endpoints yet.
10. **Panic wipe's server-side cleanup is best-effort** — offline it still destroys local keys,
    which is what makes the data unreadable.
11. **Local testing runs over plain HTTP on your LAN.** Message bodies are already E2E-encrypted,
    but session tokens and metadata are not — fine on a home network. **Any deployment beyond
    your own machine must use HTTPS** (Railway's generated domain provides this), and
    `server/data/jwt-secret` must stay private.

## Responsible use

Before real-world deployment to at-risk users: commission an independent security audit (see
limitation #1), add key verification (safety numbers), add rate limiting, and implement prekey
rotation. Do not advertise "unbreakable" or "military-grade" encryption — describe the actual
properties: end-to-end encryption with forward secrecy and post-compromise security.
