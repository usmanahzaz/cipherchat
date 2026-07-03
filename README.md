# CipherChat

A privacy-first, end-to-end encrypted messenger for iOS and Android. Every message renders as
ciphertext until the recipient taps **Decode** — and ten seconds later it conceals itself again.

**Zero-setup testing** — no cloud accounts, no database to create. The bundled Node.js server
creates its own embedded SQLite database automatically on first start, and the app finds the
server by itself:

```sh
# terminal 1 — backend (auto-creates its database)
cd cipherchat/server && npm install && npm start

# terminal 2 — app
cd cipherchat/mobile && npm install && npx expo start
```

```
┌─────────────────────────────────────────────────────────────────┐
│  sender device           server (Node + SQLite)  recipient device│
│  ─────────────           ──────────────────────  ────────────────│
│  plaintext                                                       │
│     │ nacl.box                                                   │
│     ▼ (X25519 + XSalsa20-Poly1305)                               │
│  ciphertext ──────────▶  encrypted blob  ───────▶ ciphertext     │
│                          (never readable)           │ Decode     │
│                                                     ▼            │
│                                             plaintext (≤ 10 s,   │
│                                             memory only)         │
└─────────────────────────────────────────────────────────────────┘
```

Because the encryption is end-to-end, the server is deliberately a *dumb blob store* — which is
why an embedded database is the right tool: nothing sensitive to protect server-side beyond
availability, and nothing for you to provision.

## Stack

| Layer | Choice | Why |
|---|---|---|
| Mobile | Expo (React Native, TypeScript) | One codebase, native iOS + Android |
| Crypto | [TweetNaCl.js](https://github.com/dchest/tweetnacl-js) (audited by Cure53) | X25519 key agreement + XSalsa20-Poly1305 AEAD via `nacl.box` — proven primitives, zero custom crypto |
| Key storage | `expo-secure-store` | iOS Keychain / Android Keystore |
| Backend | Node.js (Express) + embedded SQLite (`better-sqlite3`) | Self-contained: auto-creates its DB and JWT secret; REST + WebSocket realtime |
| Push | Expo Push API (server-side) | Content-free: body is always `"Encrypted message received"` |

## Project structure

```
cipherchat/
├── mobile/                      # Expo app
│   ├── App.tsx                  # root: app lock gate, realtime, push registration
│   └── src/
│       ├── lib/
│       │   ├── crypto.ts        # keygen, encrypt/decrypt, Secure ID derivation, PIN hashing
│       │   ├── keystore.ts      # Keychain/Keystore wrapper + panic wipe
│       │   ├── api.ts           # REST client (auto-discovers the dev server)
│       │   ├── types.ts         # Profile / Contact / Message shapes
│       │   └── notifications.ts # content-free push registration
│       ├── state/               # zustand stores: auth (keys), messages (+WebSocket), settings
│       ├── screens/             # Onboarding, Auth, GenerateId, ChatList, Chat,
│       │                        # AddContact, Settings, SecuritySettings,
│       │                        # PanicSettings, Lock
│       ├── components/          # MessageBubble (decode + 10 s countdown), ui kit
│       └── navigation/          # auth stack / key setup / app stack switching
├── server/                      # zero-config backend
│   ├── src/
│   │   ├── index.js             # Express app + startup banner with LAN URLs
│   │   ├── db.js                # embedded SQLite schema (auto-created in data/)
│   │   ├── auth.js              # scrypt password hashing, JWT sessions
│   │   ├── routes.js            # REST API (authorization checks per endpoint)
│   │   ├── realtime.js          # WebSocket hub (/ws) for live delivery
│   │   └── push.js              # "Encrypted message received" via Expo Push
│   └── data/                    # created at first start: cipherchat.db + jwt-secret (gitignored)
├── README.md
└── SECURITY.md                  # threat model, guarantees, limitations
```

## Testing walkthrough

1. **Start the server** (`cd cipherchat/server && npm install && npm start`). First start creates
   `data/cipherchat.db` and a JWT secret automatically. It prints the LAN URL phones will use.
2. **Start the app** (`cd cipherchat/mobile && npm install && npx expo start`), then either:
   - scan the QR code with the **Expo Go** app on a phone (same Wi-Fi as your computer), or
   - press `i` / `a` for an iOS simulator / Android emulator.

   No `.env` needed: the app derives the server address from the Expo dev host. (To point at a
   deployed server instead, set `EXPO_PUBLIC_API_URL` — see `.env.example`.)
3. **Two identities**: run it on two devices (e.g. your phone + a simulator, or two phones).
   Sign up with any two emails — accounts are instant, no confirmation emails.
4. Each device taps **Generate Secure ID**, then on one: **＋ → Add contact** → enter the other's
   Secure ID or email, or scan its QR code.
5. Send a message. It leaves the device already encrypted; the recipient sees ciphertext, taps
   **⟨ DECODE ⟩**, reads it for 10 seconds, then it re-conceals. Also try **Auto Decode**
   (Settings), a **🔥 one-time message**, the **app lock**, and — last, it's destructive — the
   **panic PIN**.

## Database schema (SQLite, auto-created)

| Table | Columns | Notes |
|---|---|---|
| `users` | `id, email, password_hash, secure_id, public_key, push_token, created_at` | Public identity material + scrypt password hash |
| `contacts` | `id, owner_id, contact_id, alias, created_at` | Private per-user address book |
| `messages` | `id, sender_id, recipient_id, ciphertext, nonce, one_time, delivered_at, read_at, created_at` | **Only encrypted blobs + routing metadata** |

Every endpoint checks ownership: messages are only ever returned to their two endpoints, contact
lists only to their owner, and discovery is an exact-match lookup (Secure ID / email / public
key) — no browsing or enumeration.

## Authentication & key flow

1. **Sign up / log in** with email + password (scrypt-hashed server-side, 30-day JWT session
   stored in the device's secure storage).
2. **Key generation (on device)**: `nacl.box.keyPair()` → X25519 key pair.
   - Private key → `expo-secure-store` (iOS Keychain / Android Keystore,
     `WHEN_UNLOCKED_THIS_DEVICE_ONLY`). It is never transmitted, displayed, or backed up.
   - Public key → published to the server, shareable freely.
3. **Secure ID** = base32 of SHA-512(public key), formatted `CC-XXXX-XXXX-XXXX-XXXX` —
   a human-shareable handle derived from, and bound to, the key.
4. **Send**: `nacl.box(plaintext, nonce, recipientPublicKey, senderPrivateKey)` on-device;
   only `{ciphertext, nonce}` goes to the server, which relays it live over WebSocket.
5. **Decode**: `nacl.box.open(...)` on-device; plaintext lives in component state for ≤ 10 s.

## Push notifications & native features

Expo Go covers everything except push notifications and Android's hard screenshot block. For
those, build a dev client: `npx expo run:android` / `npx expo run:ios`. Push works out of the
box once the app registers its Expo push token — the server sends the fixed text
`"Encrypted message received"` whenever the recipient isn't connected live.

## Deploying beyond your laptop

The server is a single Node process — run it on any VPS/container host, put HTTPS in front of it
(Caddy/nginx/a platform that terminates TLS), and set `EXPO_PUBLIC_API_URL` in `mobile/.env`.
The SQLite file in `server/data/` is the entire persistent state; back it up by copying it.
**Use HTTPS for anything beyond local testing** — see SECURITY.md.

## Extending (the architecture is ready for it)

- **Voice notes / images / media**: encrypt the file bytes with a random symmetric key
  (`nacl.secretbox`), wrap that key with `nacl.box` per recipient, store the blob server-side.
  The message row gains a `media_url` + wrapped key — the server still sees only noise.
- **Disappearing media**: reuse the one-time-burn path (`burnMessage`) with a TTL column.
- **Forward secrecy / groups**: swap the static `nacl.box` layer for a Signal-style double
  ratchet (e.g. libsignal) behind the same `crypto.ts` interface. See SECURITY.md.
- **Scale**: if one machine ever isn't enough, the storage layer in `db.js` is ~60 lines of SQL —
  porting it to Postgres is mechanical, and nothing else changes.

Read [SECURITY.md](./SECURITY.md) before trusting this with anything sensitive — it documents
the exact guarantees **and the exact limitations**.
