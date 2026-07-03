/**
 * Content-free push notifications via Expo's push API. The body is always
 * the fixed string "Encrypted message received" — no sender, no preview,
 * no ciphertext, no data payload.
 */
export async function sendContentFreePush(pushToken) {
  if (!pushToken) return;
  try {
    await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: pushToken,
        title: 'CipherChat',
        body: 'Encrypted message received',
        priority: 'default',
        channelId: 'messages',
      }),
    });
  } catch {
    // Push is best-effort; realtime + polling still deliver the message.
  }
}
