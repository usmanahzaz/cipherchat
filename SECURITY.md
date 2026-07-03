# CipherChat — Security Notes

This document states precisely what CipherChat protects, how, and — just as important — what it
does **not** protect in this MVP. No custom cryptography is used anywhere.

## Cryptography

| Purpose | Primitive | Implementation |
|---|---|---|
| Key agreement | X25519 (Curve25519 ECDH) | `nacl.box.keyPair()` — TweetNaCl.js |
| Message encryption | XSalsa20-Poly1305 AEAD | `nacl.box` — TweetNaCl.js |
| Secure ID derivation | SHA-512 | `nacl.hash` |
| Randomness | OS CSPRNG | `react-native-get-random-values` → `crypto.getRandomValues` |

TweetNaCl.js is a port of Daniel J. Bernstein's NaCl, [audited by Cure53](https://cure53.de/tweetnacl.pdf).
`nacl.box` computes a shared key from *(my private key, their public key)*; the same shared key
is derived on both ends, which also lets a sender re-open their own sent messages. Every message
uses a fresh random 24-byte nonce. Poly1305 authentication means tampered ciphertext fails to
decrypt rather than yielding garbage.

## What the server can and cannot see

**Cannot see, ever:** message content. The server stores `{ciphertext, nonce}` produced
on-device in an embedded SQLite database. There is no key escrow, no backup of private keys,
and every API endpoint checks ownership so authenticated users can only ever fetch or delete
messages they are an endpoint of. Passwords are stored as scrypt hashes; sessions are JWTs
signed with a secret generated on first start.

**Can see (metadata):** who talks to whom, when, how often, message sizes, delivery/read
timestamps, emails, public keys, and push tokens. **E2EE hides content, not traffic patterns.**
Hiding metadata requires onion routing / sealed sender designs that are out of scope for an MVP.

## Device-side protections

- **Private key** in iOS Keychain / Android Keystore (`expo-secure-store`,
  `WHEN_UNLOCKED_THIS_DEVICE_ONLY`) — excluded from cloud backups, never leaves the device.
- **Plaintext lifetime**: decrypted text exists only in React component state and is destroyed
  after 10 seconds. It is never written to disk, logs, or the clipboard.
- **App lock**: PIN (salted-hash in secure storage) + optional biometrics
  (`expo-local-authentication`), re-locks on backgrounding.
- **Panic PIN**: entered at the lock screen, it silently wipes the private key, all secure
  material and local state, and best-effort deletes the user's messages server-side. Destroying
  the private key makes all remaining ciphertext **permanently** unreadable — there is no
  recovery by design.
- **One-time messages**: deleted from the server and the recipient's device after their single
  10-second reveal.
- **Screenshots**: blocked on the chat screen via `expo-screen-capture` — on Android this sets
  `FLAG_SECURE` (hard block); on iOS screenshots *cannot* be prevented by any app, but screen
  *recording* is blanked and screenshot events can be detected.
- **Copy protection**: decoded text is rendered non-selectable, so the standard copy UI is
  unavailable.
- **Notifications**: fixed body `"Encrypted message received"` — no sender, no preview — and
  `VISIBILITY_SECRET` on the Android lock screen.

## Known limitations (read before trusting this MVP)

1. **No forward secrecy / post-compromise security.** A single static X25519 key pair per user
   means a stolen private key decrypts *all* past and future messages for that user. Fix:
   Signal-style double ratchet (libsignal) behind the existing `crypto.ts` interface.
2. **Trust-on-first-use key distribution.** Public keys come from the server; a malicious server
   could substitute its own key (MITM) when you add a contact. Mitigation available today:
   verify contacts by scanning their QR code in person. Fix: safety-number verification UI and
   key-change alerts.
3. **No key backup or multi-device.** Lose the device (or trigger panic mode) and history is
   permanently gone. This is a deliberate trade-off; a future encrypted-backup scheme must be
   user-passphrase based (e.g. Argon2id-derived key) so the server still can't read it.
4. **PIN hashing is salted SHA-512, not a memory-hard KDF.** The hash never leaves the secure
   enclave-backed store and only gates the UI (it does not derive the encryption key), so
   offline brute-force requires a compromised device — but Argon2id would still be better.
5. **A compromised OS wins.** Root/jailbreak malware can read screen contents, keylog, or dump
   memory during the 10-second reveal window. No messenger survives a hostile OS.
6. **Screenshots on iOS** cannot be blocked (platform restriction) — and nothing stops someone
   photographing the screen with another device.
7. **The 10-second concealment is a UX/shoulder-surfing defense**, not a cryptographic one: the
   recipient's device necessarily holds the ciphertext and the key to read it again (except for
   one-time messages, which are destroyed).
8. **Metadata is visible to the operator** (see above).
9. **No rate limiting / abuse controls** on the lookup endpoint beyond exact-match semantics; a
   production deployment should add rate limits and enumeration monitoring.
10. **Panic wipe's server-side cleanup is best-effort** — offline it still destroys local keys
    (which is what makes data unreadable), but blobs may remain on the server until connectivity
    allows deletion.
11. **Local testing runs over plain HTTP on your LAN.** The message bodies crossing it are
    already end-to-end encrypted, but session tokens and metadata are not — fine on a trusted
    home network, not fine on the internet. **Any deployment beyond your own machine must sit
    behind HTTPS** (and the JWT secret file `server/data/jwt-secret` must be kept private).

## Responsible use

This is an MVP for educational/product-development purposes. Before real-world deployment with
at-risk users: commission an independent security audit, add forward secrecy, add key
verification, and pin TLS certificates.
