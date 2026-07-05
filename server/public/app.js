/**
 * CipherChat web client. Same zero-knowledge model as the mobile app:
 * identity keys are generated in the browser, messages are Double-Ratchet
 * encrypted before leaving it, and decoded text self-conceals after 10 s.
 * Session state and decoded-message cache live in localStorage (see
 * SECURITY.md for how the web client's storage guarantees differ from the
 * app's Keychain/Keystore).
 */
import {
  bundleFromIdentity,
  createInboundSession,
  createOutboundSession,
  decrypt,
  encrypt,
  generateIdentity,
  parseEnvelope,
  secureIdFromPublicKey,
  verifyBundle,
} from './ratchet.js';

const VISIBLE_SECONDS = 10;
const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// Local storage (namespaced per signed-in user)
// ---------------------------------------------------------------------------
const store = {
  token: () => localStorage.getItem('cc.token'),
  setToken: (t) => (t ? localStorage.setItem('cc.token', t) : localStorage.removeItem('cc.token')),
  userKey: (name) => `cc.${state.profile?.id ?? 'anon'}.${name}`,
  getJson(name, fallback) {
    try {
      const raw = localStorage.getItem(store.userKey(name));
      return raw ? JSON.parse(raw) : fallback;
    } catch {
      return fallback;
    }
  },
  setJson(name, value) {
    localStorage.setItem(store.userKey(name), JSON.stringify(value));
  },
};

const state = {
  profile: null,
  identity: null,
  contacts: [],
  peer: null, // selected contact profile
  thread: [], // messages for selected peer
  revealed: new Map(), // messageId -> { text, phase, left, timer }
  failed: new Set(),
  ws: null,
};

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------
async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(store.token() ? { Authorization: `Bearer ${store.token()}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
  return json;
}

// ---------------------------------------------------------------------------
// Sessions (per-peer Double Ratchet state, persisted after every operation)
// ---------------------------------------------------------------------------
function loadSessions(peerId) {
  return store.getJson(`sessions.${peerId}`, { sessions: {} });
}
function saveSessions(peerId, data) {
  store.setJson(`sessions.${peerId}`, data);
}

async function encryptFor(peer, plaintext) {
  const data = loadSessions(peer.id);
  let session = Object.values(data.sessions)
    .filter((s) => s.cks !== null)
    .sort((a, b) => a.sid.localeCompare(b.sid))[0];
  if (!session) {
    const bundle = {
      identity_key: peer.public_key,
      signing_key: peer.sign_public_key,
      signed_prekey: peer.signed_prekey,
      prekey_signature: peer.prekey_signature,
    };
    if (!verifyBundle(bundle)) throw new Error("Contact's security keys failed verification.");
    session = await createOutboundSession(state.identity, bundle);
    data.sessions[session.sid] = session;
  }
  const envelope = await encrypt(session, plaintext);
  data.sessions[session.sid] = session;
  saveSessions(peer.id, data);
  return envelope;
}

async function decryptFrom(peer, raw) {
  const parsed = parseEnvelope(raw);
  if (!parsed) return null;
  const data = loadSessions(peer.id);
  let session = data.sessions[parsed.header.sid] ?? null;
  if (!session && parsed.header.init) {
    if (parsed.header.init.ik !== peer.public_key) return null;
    session = await createInboundSession(state.identity, parsed.header.init);
  }
  if (!session) return null;
  const result = await decrypt(session, raw);
  if (!result) return null;
  data.sessions[parsed.header.sid] = result.session;
  saveSessions(peer.id, data);
  return result.plaintext;
}

// Vault: the sender's own plaintext, kept only until its single self-view.
const vault = {
  get: (id) => store.getJson(`vault.${id}`, null),
  put: (id, text) => store.setJson(`vault.${id}`, text),
  del: (id) => localStorage.removeItem(store.userKey(`vault.${id}`)),
};

// Tombstones: where a message once stood. Persisted so departed messages
// keep their place in the conversation forever.
function loadTombs(peerId) {
  return store.getJson(`tombs.${peerId}`, []);
}
function addTombstone(peerId, id, createdAt, mine) {
  const tombs = loadTombs(peerId);
  if (tombs.some((t) => t.id === id)) return;
  tombs.push({ id, created_at: createdAt, mine });
  store.setJson(`tombs.${peerId}`, tombs.slice(-500));
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------
function show(name) {
  for (const s of document.querySelectorAll('.screen')) s.classList.remove('active');
  $(`screen-${name}`).classList.add('active');
}

// ---- auth ----
let authMode = 'signup';
let pendingEmail = '';

/** Auth POST that returns { status, json } without throwing, so we can react
 *  to 403-needs-verification etc. */
async function authPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

$('auth-toggle').onclick = () => {
  authMode = authMode === 'signup' ? 'login' : 'signup';
  $('auth-submit').textContent = authMode === 'signup' ? 'Create account' : 'Log in';
  $('auth-toggle').textContent =
    authMode === 'signup' ? 'Have an account? Log in' : 'New here? Create account';
};

function showVerify(email, devCode) {
  pendingEmail = email;
  $('verify-email').textContent = email;
  $('verify-code').value = '';
  $('verify-error').textContent = '';
  if (devCode) {
    $('dev-code').textContent = devCode;
    $('dev-banner').style.display = '';
  } else {
    $('dev-banner').style.display = 'none';
  }
  show('verify');
}

$('auth-submit').onclick = async () => {
  const email = $('auth-email').value.trim();
  const password = $('auth-password').value;
  $('auth-error').textContent = '';
  if (!email || password.length < 8) {
    $('auth-error').textContent = 'Enter your email and a password of at least 8 characters.';
    return;
  }
  $('auth-submit').disabled = true;
  try {
    const { status, json } = await authPost(`/auth/${authMode}`, { email, password });
    if (json.needsVerification) {
      showVerify(email, json.dev_code); // signup, or login of an unverified account
    } else if (status >= 400) {
      $('auth-error').textContent = json.error || 'Something went wrong.';
    } else {
      await finishLogin(json.token, json.profile);
    }
  } catch (e) {
    $('auth-error').textContent = e.message;
  } finally {
    $('auth-submit').disabled = false;
  }
};

$('verify-submit').onclick = async () => {
  $('verify-error').textContent = '';
  const { status, json } = await authPost('/auth/verify', {
    email: pendingEmail,
    code: $('verify-code').value.trim(),
  });
  if (status >= 400) {
    $('verify-error').textContent = json.error || 'Invalid code.';
    return;
  }
  await finishLogin(json.token, json.profile);
};

$('verify-resend').onclick = async () => {
  const { json } = await authPost('/auth/resend', { email: pendingEmail });
  if (json.dev_code) {
    $('dev-code').textContent = json.dev_code;
    $('dev-banner').style.display = '';
  }
  $('verify-error').textContent = 'A new code has been sent.';
};

$('verify-back').onclick = () => show('auth');

// ---- forgot / reset password ----
let forgotStep = 1;
$('auth-forgot').onclick = () => {
  forgotStep = 1;
  $('forgot-step2').style.display = 'none';
  $('forgot-dev-banner').style.display = 'none';
  $('forgot-submit').textContent = 'Send reset code';
  $('forgot-error').textContent = '';
  show('forgot');
};
$('forgot-back').onclick = () => show('auth');

$('forgot-submit').onclick = async () => {
  $('forgot-error').textContent = '';
  const email = $('forgot-email').value.trim();
  if (forgotStep === 1) {
    if (!email) return;
    const { json } = await authPost('/auth/forgot', { email });
    forgotStep = 2;
    $('forgot-step2').style.display = '';
    $('forgot-submit').textContent = 'Reset password';
    if (json.dev_code) {
      $('forgot-dev-code').textContent = json.dev_code;
      $('forgot-dev-banner').style.display = '';
    }
    $('forgot-error').textContent = 'If that email has an account, a code was sent.';
  } else {
    const { status, json } = await authPost('/auth/reset', {
      email,
      code: $('forgot-code').value.trim(),
      new_password: $('forgot-password').value,
    });
    if (status >= 400) {
      $('forgot-error').textContent = json.error || 'Reset failed.';
      return;
    }
    $('auth-error').textContent = 'Password reset. Please log in.';
    authMode = 'login';
    $('auth-submit').textContent = 'Log in';
    show('auth');
  }
};

async function finishLogin(token, profile) {
  store.setToken(token);
  state.profile = profile;
  await ensureKeys();
  await enterApp();
}

/** Generate identity in-browser and publish the public bundle (idempotent). */
async function ensureKeys() {
  let identity = store.getJson('identity', null);
  if (!identity) {
    identity = generateIdentity();
    store.setJson('identity', identity);
  }
  state.identity = identity;
  if (!state.profile.public_key || state.profile.public_key !== identity.identityPublic) {
    const bundle = bundleFromIdentity(identity);
    const { profile } = await api('/me/keys', {
      method: 'POST',
      body: {
        public_key: bundle.identity_key,
        secure_id: secureIdFromPublicKey(bundle.identity_key),
        sign_public_key: bundle.signing_key,
        signed_prekey: bundle.signed_prekey,
        prekey_signature: bundle.prekey_signature,
      },
    });
    state.profile = profile;
  }
}

async function enterApp() {
  $('my-id').textContent = state.profile.secure_id;
  await refreshContacts();
  connectWs();
  show('list');
}

// ---- chat list + contact requests ----
async function refreshContacts() {
  const [{ contacts, outgoing }, { requests }] = await Promise.all([
    api('/contacts'),
    api('/contact-requests'),
  ]);
  state.contacts = contacts;

  // Incoming requests: "do you want to accept encrypted messages from…?"
  const reqEl = $('requests');
  reqEl.innerHTML = '';
  for (const r of requests) {
    const card = document.createElement('div');
    card.className = 'request-card';
    card.innerHTML = `
      <div class="request-title mono">⟨!⟩ CONTACT REQUEST</div>
      <div class="request-who mono">${escapeHtml(r.profile.secure_id ?? 'Unknown ID')}</div>
      <div class="request-sub">This code wants to exchange end-to-end encrypted messages with you. Accept?</div>
      <div class="request-actions">
        <button class="req-accept">Accept</button>
        <button class="req-decline ghost">Decline</button>
      </div>`;
    card.querySelector('.req-accept').onclick = async () => {
      await api(`/contact-requests/${r.id}/accept`, { method: 'POST' }).catch((e) => alert(e.message));
      refreshContacts();
    };
    card.querySelector('.req-decline').onclick = async () => {
      await api(`/contact-requests/${r.id}/decline`, { method: 'POST' }).catch(() => {});
      refreshContacts();
    };
    reqEl.appendChild(card);
  }

  const el = $('contacts');
  el.innerHTML = '';
  if (!contacts.length && !outgoing.length && !requests.length) {
    el.innerHTML =
      '<div class="empty">No contacts yet.<br/>Tap ＋ Add and enter a Secure ID code.<br/><br/>They must accept your request before you can message them.</div>';
    return;
  }
  for (const c of contacts) {
    const label = c.alias || c.profile.secure_id || '?';
    const row = document.createElement('div');
    row.className = 'contact-row';
    row.innerHTML = `
      <div class="avatar">${escapeHtml(label[0].toUpperCase())}</div>
      <div style="min-width:0">
        <div class="contact-name">${escapeHtml(c.alias || 'Secure contact')}</div>
        <div class="contact-sub mono">${escapeHtml(c.profile.secure_id ?? '')}</div>
      </div>`;
    row.onclick = () => openChat(c);
    el.appendChild(row);
  }
  for (const c of outgoing) {
    const row = document.createElement('div');
    row.className = 'contact-row pending-row';
    row.innerHTML = `
      <div class="avatar">⏳</div>
      <div style="min-width:0">
        <div class="contact-name mono">${escapeHtml(c.alias || c.profile.secure_id || '?')}</div>
        <div class="contact-sub">request sent — awaiting their acceptance</div>
      </div>`;
    el.appendChild(row);
  }
}

$('btn-add').onclick = () => {
  $('add-error').textContent = '';
  $('add-identifier').value = '';
  $('add-alias').value = '';
  show('add');
};
$('btn-me').onclick = () => show('me');
$('me-back').onclick = () => show('list');
$('add-back').onclick = () => show('list');
$('copy-id').onclick = async () => {
  try {
    await navigator.clipboard.writeText(state.profile.secure_id);
    $('copy-id').textContent = 'Copied ✓';
    setTimeout(() => ($('copy-id').textContent = 'Copy Secure ID'), 1500);
  } catch {
    /* clipboard unavailable */
  }
};
$('btn-logout').onclick = () => {
  state.ws?.close();
  store.setToken(null);
  show('auth');
};

$('add-submit').onclick = async () => {
  $('add-error').textContent = '';
  try {
    const { profile } = await api('/lookup', {
      method: 'POST',
      body: { identifier: $('add-identifier').value.trim() },
    });
    if (profile.id === state.profile.id) throw new Error('That is your own ID.');
    await api('/contacts', {
      method: 'POST',
      body: { contact_id: profile.id, alias: $('add-alias').value.trim() || undefined },
    });
    await refreshContacts();
    show('list');
  } catch (e) {
    $('add-error').textContent = e.message;
  }
};

// ---- chat ----
async function openChat(contact) {
  state.peer = contact.profile;
  state.peerAlias = contact.alias || contact.profile.secure_id;
  $('chat-name').textContent = state.peerAlias;
  $('chat-sub').textContent = `${contact.profile.secure_id} · E2E encrypted`;
  state.thread = [];
  renderThread();
  show('chat');
  const { messages } = await api(`/messages/${contact.profile.id}`);
  state.thread = messages;
  renderThread();
  api('/messages/delivered', { method: 'POST', body: { peer_id: contact.profile.id } }).catch(() => {});
}

$('chat-back').onclick = () => {
  state.peer = null;
  refreshContacts();
  show('list');
};

$('send').onclick = sendDraft;
$('draft').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendDraft();
  }
});

async function sendDraft() {
  const text = $('draft').value.trim();
  if (!text || !state.peer) return;
  $('draft').value = '';
  try {
    const envelope = await encryptFor(state.peer, text);
    const { message } = await api('/messages', {
      method: 'POST',
      body: { recipient_id: state.peer.id, ciphertext: envelope, nonce: 'v2', one_time: true },
    });
    // Sender keeps their plaintext only until their own single self-view.
    vault.put(message.id, text);
    state.thread.push(message);
    renderThread();
  } catch (e) {
    alert(e.message);
  }
}

function renderThread() {
  const el = $('msgs');
  el.innerHTML = '';
  if (!state.peer) return;
  const tombs = loadTombs(state.peer.id);
  const tombIds = new Set(tombs.map((t) => t.id));
  const items = [
    ...state.thread.filter((m) => !tombIds.has(m.id)).map((m) => ({ tomb: false, m, at: m.created_at })),
    ...tombs.map((t) => ({ tomb: true, t, at: t.created_at })),
  ].sort((a, b) => String(a.at).localeCompare(String(b.at)));
  for (const item of items) {
    el.appendChild(item.tomb ? renderTombstone(item.t) : renderBubble(item.m));
  }
  el.scrollTop = el.scrollHeight;
}

function renderTombstone(t) {
  const div = document.createElement('div');
  div.className = `bubble tombstone${t.mine ? ' mine' : ''}`;
  div.innerHTML = '<div class="tomb-text">🕊 this message has departed — read once, gone for eternity</div>';
  const time = new Date(t.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  div.insertAdjacentHTML('beforeend', `<div class="time">${time}</div>`);
  return div;
}

function renderBubble(m) {
  const mine = m.sender_id === state.profile.id;
  const div = document.createElement('div');
  div.className = `bubble${mine ? ' mine' : ''}`;
  div.dataset.id = m.id;

  const revealed = state.revealed.get(m.id);
  if (revealed && revealed.phase === 'scramble') {
    div.innerHTML = `
      <div class="decrypting-label mono">▓▒░ DECRYPTING…</div>
      <div class="plain-text scrambling mono">${escapeHtml(scrambleText(revealed.text, 0))}</div>`;
  } else if (revealed) {
    div.innerHTML = `
      <div class="plain-text">${escapeHtml(revealed.text)}</div>
      <div class="meta"><div class="countdown mono">${'●'.repeat(revealed.left)}${'○'.repeat(VISIBLE_SECONDS - revealed.left)} ${revealed.left}s</div></div>`;
  } else {
    const preview = m.ciphertext.replace(/[^A-Za-z0-9]/g, '').slice(-96).match(/.{1,4}/g)?.join(' ') ?? '';
    const failNote = state.failed.has(m.id)
      ? `<span class="fail">${mine ? 'not stored in this browser' : 'already read or invalid'}</span>`
      : '<button class="decode-btn mono">⟨ DECODE ⟩</button>';
    const delBtn = mine ? '<button class="del-btn" title="Delete for both sides">✕ delete</button>' : '';
    div.innerHTML = `
      <div class="cipher-text mono">${escapeHtml(preview)}</div>
      <div class="meta"><span class="one-time">🔥 read-once</span>${delBtn}${failNote}</div>`;
    div.querySelector('.decode-btn')?.addEventListener('click', () => decode(m));
    div.querySelector('.del-btn')?.addEventListener('click', () => senderDelete(m));
  }
  const time = new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  div.insertAdjacentHTML('beforeend', `<div class="time">${time}${mine ? (m.delivered_at ? ' ✓✓' : ' ✓') : ''}</div>`);
  return div;
}

async function decode(m) {
  if (state.revealed.has(m.id)) return;
  const mine = m.sender_id === state.profile.id;
  let text = null;
  if (mine) {
    text = vault.get(m.id); // sender's single self-view
  } else {
    text = await decryptFrom(state.peer, m.ciphertext); // consumes the key
  }
  if (text === null) {
    state.failed.add(m.id);
    renderThread();
    return;
  }
  startScramble(m, text);
}

const SCRAMBLE_CHARS = 'ABCDEF0123456789#$%&@?!<>[]{}=+*/\\';

function scrambleText(text, progress) {
  const cut = Math.floor(progress * text.length);
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    out += i < cut || ch === ' ' || ch === '\n'
      ? ch
      : SCRAMBLE_CHARS[(Math.random() * SCRAMBLE_CHARS.length) | 0];
  }
  return out;
}

/** Hacking-style decryption: noise resolves into the message — hesitant at
 *  first, then accelerating as the "crack" lands — with live progress. After
 *  the 10-second read window the message departs, forever. Longer messages
 *  take proportionally longer to break. */
function startScramble(m, text) {
  const entry = { text, phase: 'scramble', left: VISIBLE_SECONDS, timer: null };
  state.revealed.set(m.id, entry);
  renderThread();
  const duration = Math.min(5200, 2600 + text.length * 45);
  const t0 = performance.now();
  const anim = setInterval(() => {
    const t = Math.min(1, (performance.now() - t0) / duration);
    const p = Math.pow(t, 2.2); // slow, struggling start → sudden breakthrough
    const bubble = document.querySelector(`.bubble[data-id="${CSS.escape(m.id)}"]`);
    const node = bubble?.querySelector('.plain-text');
    const label = bubble?.querySelector('.decrypting-label');
    if (node) node.textContent = scrambleText(text, p);
    if (label) label.textContent = `▓▒░ DECRYPTING… ${String(Math.floor(p * 100)).padStart(2, '0')}%`;
    if (t >= 1) {
      clearInterval(anim);
      entry.phase = 'shown';
      renderThread();
      entry.timer = setInterval(() => {
        entry.left -= 1;
        if (entry.left <= 0) {
          clearInterval(entry.timer);
          destroy(m);
        } else {
          renderThread();
        }
      }, 1000);
    }
  }, 55);
}

/** Sender recall: delete an unread sent message for both sides. */
function senderDelete(m) {
  const el = document.querySelector(`.bubble[data-id="${CSS.escape(m.id)}"]`);
  el?.classList.add('dissolving');
  setTimeout(() => {
    vault.del(m.id);
    addTombstone(state.peer.id, m.id, m.created_at, true);
    state.thread = state.thread.filter((x) => x.id !== m.id);
    // Server delete notifies the recipient, whose copy tombstones too.
    api(`/messages/${m.id}`, { method: 'DELETE' }).catch(() => {});
    renderThread();
  }, 680);
}

/** Eternal peace: dissolve, leave a tombstone in place, erase everywhere. */
function destroy(m) {
  const mine = m.sender_id === state.profile.id;
  const el = document.querySelector(`.bubble[data-id="${CSS.escape(m.id)}"]`);
  el?.classList.add('dissolving');
  setTimeout(() => {
    state.revealed.delete(m.id);
    vault.del(m.id);
    addTombstone(state.peer.id, m.id, m.created_at, mine);
    state.thread = state.thread.filter((x) => x.id !== m.id);
    // The recipient's read erases the blob for everyone; a sender's
    // self-view only tombstones their own copy (recipient can still read).
    if (!mine) api(`/messages/${m.id}`, { method: 'DELETE' }).catch(() => {});
    renderThread();
  }, 680);
}

// ---------------------------------------------------------------------------
// Realtime
// ---------------------------------------------------------------------------
function connectWs() {
  state.ws?.close();
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(store.token())}`);
  ws.onmessage = (evt) => {
    let event;
    try {
      event = JSON.parse(evt.data);
    } catch {
      return;
    }
    if (event.type === 'message:new') {
      const msg = event.message;
      if (state.peer && msg.sender_id === state.peer.id) {
        state.thread.push(msg);
        renderThread();
        api('/messages/delivered', { method: 'POST', body: { peer_id: state.peer.id } }).catch(() => {});
      }
    } else if (
      event.type === 'contact:request' ||
      event.type === 'contact:accepted' ||
      event.type === 'contact:declined'
    ) {
      // Live handshake updates: a new request card appears, or a pending
      // contact becomes messageable.
      refreshContacts();
    } else if (event.type === 'message:deleted') {
      // The peer read our message — it departs on our side too, leaving its
      // tombstone in place.
      vault.del(event.id);
      const known = state.thread.find((m) => m.id === event.id);
      addTombstone(
        event.peer_id,
        event.id,
        known?.created_at ?? new Date().toISOString(),
        known ? known.sender_id === state.profile.id : true,
      );
      state.thread = state.thread.filter((m) => m.id !== event.id);
      if (state.peer) renderThread();
    } else if (event.type === 'messages:delivered') {
      for (const m of state.thread) {
        if (m.recipient_id === event.peer_id && !m.delivered_at) m.delivered_at = event.delivered_at;
      }
      if (state.peer) renderThread();
    }
  };
  ws.onclose = () => {
    if (store.token()) setTimeout(connectWs, 2000);
  };
  state.ws = ws;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
(async () => {
  if (!store.token()) return;
  try {
    const { profile } = await api('/me');
    state.profile = profile;
    await ensureKeys();
    await enterApp();
  } catch {
    store.setToken(null);
  }
})();
