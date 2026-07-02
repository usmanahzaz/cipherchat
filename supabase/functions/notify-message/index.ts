// CipherChat — content-free push notifications.
//
// Triggered by a database webhook on INSERT into public.messages. Looks up
// the recipient's Expo push token and sends the fixed string
// "Encrypted message received" — no sender, no preview, no ciphertext.
//
// Deploy:  supabase functions deploy notify-message --no-verify-jwt
// (The webhook calls it server-to-server; it uses the service role key from
//  function secrets, which can read push_token but can never decrypt anything.)

import { createClient } from 'jsr:@supabase/supabase-js@2';

interface WebhookPayload {
  type: 'INSERT';
  table: string;
  record: {
    id: string;
    recipient_id: string;
  };
}

Deno.serve(async (req) => {
  try {
    const payload = (await req.json()) as WebhookPayload;
    if (payload.type !== 'INSERT' || payload.table !== 'messages') {
      return new Response('ignored', { status: 200 });
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    const { data: profile } = await supabase
      .from('profiles')
      .select('push_token')
      .eq('id', payload.record.recipient_id)
      .maybeSingle();

    if (!profile?.push_token) return new Response('no token', { status: 200 });

    await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: profile.push_token,
        title: 'CipherChat',
        body: 'Encrypted message received',
        // No data payload: nothing sensitive ever transits the push pipeline.
        priority: 'default',
        channelId: 'messages',
      }),
    });

    return new Response('ok', { status: 200 });
  } catch (e) {
    return new Response(`error: ${e}`, { status: 500 });
  }
});
