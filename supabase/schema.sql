-- =============================================================================
-- CipherChat — Supabase schema
--
-- Zero-knowledge by construction: the `messages` table holds only ciphertext
-- and nonces produced on-device with X25519 + XSalsa20-Poly1305 (nacl.box).
-- No column anywhere stores plaintext, and no server-side code can decrypt.
--
-- Apply with:  supabase db push   (or paste into the SQL editor)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- profiles: one row per user. Public identity material only.
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users (id) on delete cascade,
  email       text not null unique,
  secure_id   text not null unique,        -- CC-XXXX-XXXX-XXXX-XXXX, derived from public_key
  public_key  text not null,               -- base64 X25519 public key (safe to share)
  push_token  text,                        -- Expo push token; notifications carry no content
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- contacts: each user's private address book.
-- ---------------------------------------------------------------------------
create table if not exists public.contacts (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null references public.profiles (id) on delete cascade,
  contact_id  uuid not null references public.profiles (id) on delete cascade,
  alias       text,
  created_at  timestamptz not null default now(),
  unique (owner_id, contact_id)
);

-- ---------------------------------------------------------------------------
-- messages: encrypted blobs + routing/delivery metadata. Nothing readable.
-- ---------------------------------------------------------------------------
create table if not exists public.messages (
  id            uuid primary key default gen_random_uuid(),
  sender_id     uuid not null references public.profiles (id) on delete cascade,
  recipient_id  uuid not null references public.profiles (id) on delete cascade,
  ciphertext    text not null,             -- base64 nacl.box output (opaque)
  nonce         text not null,             -- base64 24-byte nonce
  one_time      boolean not null default false,
  delivered_at  timestamptz,
  read_at       timestamptz,
  created_at    timestamptz not null default now()
);

create index if not exists messages_thread_idx
  on public.messages (sender_id, recipient_id, created_at);
create index if not exists messages_inbox_idx
  on public.messages (recipient_id, created_at);

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.contacts enable row level security;
alter table public.messages enable row level security;

-- profiles: users manage their own row. No public SELECT — discovery goes
-- exclusively through the exact-match lookup_profile() RPC below.
create policy "profiles: read own"
  on public.profiles for select
  using (auth.uid() = id);

create policy "profiles: insert own"
  on public.profiles for insert
  with check (auth.uid() = id);

create policy "profiles: update own"
  on public.profiles for update
  using (auth.uid() = id);

-- contacts: owner-only.
create policy "contacts: read own"
  on public.contacts for select
  using (auth.uid() = owner_id);

create policy "contacts: insert own"
  on public.contacts for insert
  with check (auth.uid() = owner_id);

create policy "contacts: delete own"
  on public.contacts for delete
  using (auth.uid() = owner_id);

-- messages: visible only to the two endpoints. Sender inserts as themself.
-- Either endpoint may delete (one-time burn / panic cleanup). Recipient may
-- update only delivery metadata (enforced by trigger below).
create policy "messages: endpoints read"
  on public.messages for select
  using (auth.uid() = sender_id or auth.uid() = recipient_id);

create policy "messages: sender inserts"
  on public.messages for insert
  with check (auth.uid() = sender_id);

create policy "messages: recipient updates status"
  on public.messages for update
  using (auth.uid() = recipient_id);

create policy "messages: endpoints delete"
  on public.messages for delete
  using (auth.uid() = sender_id or auth.uid() = recipient_id);

-- Recipients may only touch delivery metadata — never the ciphertext.
create or replace function public.messages_guard_update()
returns trigger
language plpgsql
as $$
begin
  if new.ciphertext is distinct from old.ciphertext
     or new.nonce is distinct from old.nonce
     or new.sender_id is distinct from old.sender_id
     or new.recipient_id is distinct from old.recipient_id
     or new.one_time is distinct from old.one_time
     or new.created_at is distinct from old.created_at then
    raise exception 'only delivery metadata may be updated';
  end if;
  return new;
end;
$$;

drop trigger if exists messages_guard_update on public.messages;
create trigger messages_guard_update
  before update on public.messages
  for each row execute function public.messages_guard_update();

-- ---------------------------------------------------------------------------
-- Contact discovery: exact-match only, no browsing/enumeration.
-- SECURITY DEFINER so it can see profiles without a public SELECT policy;
-- it returns a row only on an exact secure_id / email / public_key match,
-- and never exposes push tokens.
-- ---------------------------------------------------------------------------
create or replace function public.lookup_profile(identifier text)
returns table (id uuid, email text, secure_id text, public_key text)
language sql
security definer
set search_path = public
stable
as $$
  select p.id, p.email, p.secure_id, p.public_key
  from public.profiles p
  where auth.uid() is not null
    and (
      p.secure_id = upper(identifier)
      or lower(p.email) = lower(identifier)
      or p.public_key = identifier
    )
  limit 1;
$$;

revoke all on function public.lookup_profile(text) from anon;
grant execute on function public.lookup_profile(text) to authenticated;

-- ---------------------------------------------------------------------------
-- Realtime: clients subscribe to INSERT/DELETE on messages (RLS applies).
-- ---------------------------------------------------------------------------
alter publication supabase_realtime add table public.messages;

-- ---------------------------------------------------------------------------
-- Push notification webhook → Edge Function (content-free notifications).
-- Requires the function deployed as `notify-message` (see functions/).
-- Create via Dashboard → Database → Webhooks, or uncomment below and set
-- your project ref:
--
-- create trigger on_message_created
--   after insert on public.messages
--   for each row
--   execute function supabase_functions.http_request(
--     'https://YOUR-PROJECT-REF.supabase.co/functions/v1/notify-message',
--     'POST',
--     '{"Content-Type":"application/json"}',
--     '{}',
--     '1000'
--   );
