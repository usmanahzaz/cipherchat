# CipherChat

A privacy-first, end-to-end encrypted messenger for iOS and Android. Every message renders as
ciphertext until the recipient taps **Decode** — and ten seconds later it conceals itself again.

```
┌─────────────────────────────────────────────────────────────────┐
│  sender device            server (Supabase)     recipient device│
│  ─────────────            ─────────────────     ────────────────│
│  plaintext                                                      │
│     │ nacl.box                                                  │
│     ▼ (X25519 + XSalsa20-Poly1305)                              │
│  ciphertext ──────────▶  encrypted blob  ──────▶ ciphertext     │
│                          (never readable)          │ Decode     │
│                                                    ▼            │
│                                            plaintext (≤ 10 s,   │
│                                            memory only)         │
└─────────────────────────────────────────────────────────────────┘
```

## Stack

| Layer | Choice | Why |
|---|---|---|
| Mobile | Expo (React Native, TypeScript) | One codebase, native iOS + Android |
| Crypto | [TweetNaCl.js](https://github.com/dchest/tweetnacl-js) (audited by Cure53) | X25519 key agreement + XSalsa20-Poly1305 AEAD via `nacl.box` — proven primitives, zero custom crypto |
| Key storage | `expo-secure-store` | iOS Keychain / Android Keystore |
| Backend | Supabase | Postgres + Row Level Security, email auth, realtime, Edge Functions |
| Push | Expo Push + Supabase Edge Function | Content-free: body is always `"Encrypted message received"` |

## Project structure

```
cipherchat/
├── mobile/                      # Expo app
│   ├── App.tsx                  # root: app lock gate, realtime, push registration
│   └── src/
│       ├── lib/
│       │   ├── crypto.ts        # keygen, encrypt/decrypt, Secure ID derivation, PIN hashing
│       │   ├── keystore.ts      # Keychain/Keystore wrapper + panic wipe
│       │   ├── supabase.ts      # client + row types
│       │   └── notifications.ts # content-free push registration
│       ├── state/               # zustand stores: auth (keys), messages, settings
│       ├── screens/             # Onboarding, Auth, GenerateId, ChatList, Chat,
│       │                        # AddContact, Settings, SecuritySettings,
│       │                        # PanicSettings, Lock
│       ├── components/          # MessageBubble (decode + 10 s countdown), ui kit
│       └── navigation/          # auth stack / key setup / app stack switching
├── supabase/
│   ├── schema.sql               # tables, RLS policies, lookup RPC, realtime
│   └── functions/notify-message # Edge Function: "Encrypted message received"
├── README.md
└── SECURITY.md                  # threat model, guarantees, limitations
```

## Setup

### 1. Backend (Supabase)

1. Create a project at [supabase.com](https://supabase.com).
2. Run `supabase/schema.sql` in the SQL editor (or `supabase db push`).
3. **Auth → Providers → Email**: enabled by default. For fastest local testing you can disable
   "Confirm email"; keep it on for anything real.
4. Push notifications (optional for MVP):
   ```sh
   supabase functions deploy notify-message --no-verify-jwt
   ```
   Then add a Database Webhook (Dashboard → Database → Webhooks): table `messages`,
   event `INSERT`, target the `notify-message` function.

### 2. Mobile app

```sh
cd cipherchat/mobile
npm install
cp .env.example .env        # fill in your Supabase URL + anon key
npx expo start              # Expo Go: quickest way to run on a device
```

For full native features (secure keystore hardware backing, FLAG_SECURE screenshot blocking,
push notifications), build a dev client instead of Expo Go:

```sh
npx expo run:ios            # or: npx expo run:android
```

### 3. Try it end-to-end

1. Sign up on two devices (or a device + simulator) with two emails.
2. Each device generates its Secure ID (`CC-XXXX-XXXX-XXXX-XXXX`).
3. On device A: **＋ → Add contact**, enter device B's Secure ID or email, or scan its QR.
4. Send a message. It leaves device A already encrypted; device B sees ciphertext, taps
   **⟨ DECODE ⟩**, reads it for 10 seconds, then it re-conceals.
5. Toggle **Auto Decode** in Settings, try a **🔥 one-time** message (it burns after its single
   reveal), set up the app lock, then arm a **panic PIN** and watch it destroy everything.

## Database schema

| Table | Columns | Notes |
|---|---|---|
| `profiles` | `id, email, secure_id, public_key, push_token, created_at` | Public identity material only |
| `contacts` | `id, owner_id, contact_id, alias, created_at` | Private per-user address book |
| `messages` | `id, sender_id, recipient_id, ciphertext, nonce, one_time, delivered_at, read_at, created_at` | **Only encrypted blobs + routing metadata** |

RLS: profiles are self-only (discovery goes through the exact-match `lookup_profile()` RPC);
contacts are owner-only; messages are visible only to their two endpoints, and a trigger blocks
any update that touches ciphertext.

## Authentication & key flow

1. **Sign up / log in** with email + password (Supabase Auth).
2. **Key generation (on device)**: `nacl.box.keyPair()` → X25519 key pair.
   - Private key → `expo-secure-store` (iOS Keychain / Android Keystore,
     `WHEN_UNLOCKED_THIS_DEVICE_ONLY`). It is never transmitted, displayed, or backed up.
   - Public key → uploaded to `profiles`, shareable freely.
3. **Secure ID** = base32 of SHA-512(public key), formatted `CC-XXXX-XXXX-XXXX-XXXX` —
   a human-shareable handle derived from, and bound to, the key.
4. **Send**: `nacl.box(plaintext, nonce, recipientPublicKey, senderPrivateKey)` on-device;
   only `{ciphertext, nonce}` goes to the server.
5. **Decode**: `nacl.box.open(...)` on-device; plaintext lives in component state for ≤ 10 s.

## Extending (the architecture is ready for it)

- **Voice notes / images / media**: encrypt the file bytes with a random symmetric key
  (`nacl.secretbox`), wrap that key with `nacl.box` per recipient, upload the blob to Supabase
  Storage. The message row gains a `media_url` + wrapped key — the server still sees only noise.
- **Disappearing media**: reuse the one-time-burn path (`burnMessage`) with a TTL column.
- **Forward secrecy / groups**: swap the static `nacl.box` layer for a Signal-style double
  ratchet (e.g. libsignal) behind the same `crypto.ts` interface. See SECURITY.md.

Read [SECURITY.md](./SECURITY.md) before trusting this with anything sensitive — it documents
the exact guarantees **and the exact limitations**.
