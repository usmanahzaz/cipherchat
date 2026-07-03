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
| Protocol | **Double Ratchet + X3DH** (Signal's published algorithm) | Forward secrecy: every message uses a one-time key destroyed after use. Post-compromise security: conversations self-heal after a key theft |
| Primitives | [TweetNaCl.js](https://github.com/dchest/tweetnacl-js) + [@noble/hashes](https://github.com/paulmillr/noble-hashes) (both Cure53-audited) | X25519, Ed25519, XSalsa20-Poly1305, HKDF/HMAC-SHA-512 — proven implementations, zero custom primitives |
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
│       │   ├── ratchet.ts       # Double Ratchet + X3DH (forward secrecy, self-healing)
│       │   ├── sessions.ts      # per-peer session management + persistence
│       │   ├── vault.ts         # encrypted-at-rest local store (decoded msgs, sessions)
│       │   ├── crypto.ts        # Secure ID derivation, PIN hashing
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
2. **Identity generation (on device)**: an X25519 identity key, an Ed25519 signing key, and a
   signed prekey (`ratchet.ts`). All private halves go to `expo-secure-store`
   (`WHEN_UNLOCKED_THIS_DEVICE_ONLY`) and are never transmitted, displayed, or backed up. Only
   the public bundle is published.
3. **Secure ID** = base32 of SHA-512(identity public key), formatted `CC-XXXX-XXXX-XXXX-XXXX`.
4. **Session setup (X3DH)**: the sender fetches the recipient's bundle, verifies the prekey
   signature, and derives a shared root key from three Diffie-Hellman exchanges.
5. **Send (Double Ratchet)**: each message is encrypted under a fresh one-time key from an
   advancing HMAC chain; the key is destroyed immediately after use. Fresh X25519 randomness
   is mixed in every round-trip, so stolen state locks itself out ("self-healing").
6. **Decode**: first decode consumes the transport key; the plaintext is shown for ≤ 10 s and
   kept only in the device's **encrypted local vault** (XSalsa20-Poly1305, key in Keychain/
   Keystore) so Decode works again later. One-time messages are never vaulted — after their
   single reveal, no key exists anywhere that can display them again.

## Push notifications & native features

Expo Go covers everything except push notifications and Android's hard screenshot block. For
those, build a dev client: `npx expo run:android` / `npx expo run:ios`. Push works out of the
box once the app registers its Expo push token — the server sends the fixed text
`"Encrypted message received"` whenever the recipient isn't connected live.

## Deploying beyond your laptop (Railway)

The server ships with a `Dockerfile` and `railway.json`, so deployment is a few clicks:

1. Sign in at [railway.com](https://railway.com) with GitHub → **New Project → Deploy from
   GitHub repo** → pick this repository.
2. In the service **Settings → Source**, set **Root Directory** to `cipherchat/server`
   (Railway then finds the Dockerfile automatically).
3. **Storage/Volumes → Add volume**, mount path `/data` — this is where the SQLite database
   lives so it survives redeploys. (The Dockerfile already sets `CIPHERCHAT_DATA_DIR=/data`.)
4. **Settings → Networking → Generate Domain** — Railway gives you an HTTPS URL like
   `https://cipherchat-production-xxxx.up.railway.app`.
5. Point the app at it: create `cipherchat/mobile/.env` containing
   `EXPO_PUBLIC_API_URL=https://your-domain.up.railway.app`, restart `npx expo start`.

Any other container host (Render, Fly.io, a VPS with Caddy) works the same way: run the
Dockerfile, persist `/data`, terminate TLS. The SQLite file is the entire server state — back it
up by copying it. **HTTPS is mandatory beyond local testing** — see SECURITY.md.

## Extending (the architecture is ready for it)

- **Voice notes / images / media**: encrypt the file bytes with a random symmetric key
  (`nacl.secretbox`), wrap that key with `nacl.box` per recipient, store the blob server-side.
  The message row gains a `media_url` + wrapped key — the server still sees only noise.
- **Disappearing media**: reuse the one-time-burn path (`burnMessage`) with a TTL column.
- **Groups / multi-device**: the per-peer session layer in `sessions.ts` is the extension
  point (sender-keys for groups; per-device sessions for multi-device).
- **Independent audit / libsignal**: the ratchet follows Signal's published spec on audited
  primitives, but it is our implementation — swap in libsignal via a native bridge or
  commission an audit before high-stakes use. See SECURITY.md.
- **Scale**: if one machine ever isn't enough, the storage layer in `db.js` is ~60 lines of SQL —
  porting it to Postgres is mechanical, and nothing else changes.

Read [SECURITY.md](./SECURITY.md) before trusting this with anything sensitive — it documents
the exact guarantees **and the exact limitations**.
