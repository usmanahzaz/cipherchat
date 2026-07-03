import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { decryptFrom } from '../lib/sessions';
import { vault } from '../lib/vault';
import type { Message, PeerProfile } from '../lib/types';
import { colors, spacing, type } from '../theme';

const VISIBLE_SECONDS = 10;

interface Props {
  message: Message;
  mine: boolean;
  peer: PeerProfile;
  autoDecode: boolean;
  /** Called when a one-time message finishes its single reveal. */
  onBurn: (message: Message) => void;
}

/**
 * Renders ciphertext by default. "Decode" decrypts locally; the plaintext
 * lives only in this component's state and is destroyed after 10 seconds,
 * reverting the bubble to its encrypted display.
 *
 * Transport decryption (Double Ratchet) consumes the message key forever, so
 * first decode stores the plaintext in the device's encrypted vault for
 * later re-display — EXCEPT one-time messages, which are never vaulted: after
 * their single reveal no key exists anywhere that can show them again.
 *
 * Plaintext is rendered with selectable={false} so it cannot be selected or
 * copied through the standard text-selection UI.
 */
export function MessageBubble({ message, mine, peer, autoDecode, onBurn }: Props) {
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const [failed, setFailed] = useState(false);
  const [burned, setBurned] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const decodingRef = useRef(false);
  const revealedOnceRef = useRef(false);

  const clearTimer = () => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  const conceal = useCallback(() => {
    clearTimer();
    setPlaintext(null);
    setSecondsLeft(0);
    if (message.one_time && !mine && revealedOnceRef.current) {
      setBurned(true);
      onBurn(message);
    }
  }, [message, mine, onBurn]);

  const decode = useCallback(async () => {
    if (plaintext !== null || burned || decodingRef.current) return;
    decodingRef.current = true;
    try {
      // 1. Already decoded once → encrypted local vault.
      let text = await vault.getMessage(message.id);
      // 2. First decode of an incoming message → ratchet (consumes the key).
      if (text === null && !mine) {
        text = await decryptFrom(peer.id, peer.public_key, message.ciphertext);
        if (text !== null && !message.one_time) await vault.putMessage(message.id, text);
      }
      if (text === null) {
        setFailed(true);
        return;
      }
      revealedOnceRef.current = true;
      setPlaintext(text);
      setSecondsLeft(VISIBLE_SECONDS);
    } finally {
      decodingRef.current = false;
    }
  }, [plaintext, burned, mine, message, peer]);

  // Countdown: reveal for exactly VISIBLE_SECONDS, then wipe from state.
  useEffect(() => {
    if (plaintext === null) return;
    timerRef.current = setInterval(() => {
      setSecondsLeft((s) => {
        if (s <= 1) {
          conceal();
          return 0;
        }
        return s - 1;
      });
    }, 1000);
    return clearTimer;
  }, [plaintext, conceal]);

  useEffect(() => {
    if (autoDecode && !mine && plaintext === null && !burned && !failed) decode();
    // Run once per message when auto-decode is on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoDecode]);

  useEffect(() => clearTimer, []);

  const cipherPreview = formatCipher(message.ciphertext);
  const decoded = plaintext !== null;

  return (
    <View style={[styles.wrap, mine ? styles.wrapMine : styles.wrapTheirs]}>
      <View style={[styles.bubble, mine ? styles.mine : styles.theirs]}>
        {burned ? (
          <Text style={styles.burned}>⌫ one-time message destroyed</Text>
        ) : decoded ? (
          <>
            <Text selectable={false} style={styles.plain}>
              {plaintext}
            </Text>
            <View style={styles.metaRow}>
              <Text style={styles.countdown}>
                {'●'.repeat(secondsLeft)}
                {'○'.repeat(VISIBLE_SECONDS - secondsLeft)} {secondsLeft}s
              </Text>
            </View>
          </>
        ) : (
          <>
            <Text selectable={false} style={styles.cipher} numberOfLines={3}>
              {cipherPreview}
            </Text>
            <View style={styles.metaRow}>
              {message.one_time && <Text style={styles.oneTime}>🔥 one-time</Text>}
              {failed ? (
                <Text style={styles.failedText}>
                  {mine ? 'not stored on this device' : 'undecryptable (key consumed or invalid)'}
                </Text>
              ) : (
                <Pressable onPress={decode} hitSlop={8}>
                  <Text style={styles.decodeBtn}>⟨ DECODE ⟩</Text>
                </Pressable>
              )}
            </View>
          </>
        )}
        <Text style={styles.time}>
          {new Date(message.created_at).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
          })}
          {mine ? (message.delivered_at ? '  ✓✓' : '  ✓') : ''}
        </Text>
      </View>
    </View>
  );
}

/** Groups the envelope's ciphertext into blocks so it reads as "code". */
function formatCipher(ciphertext: string): string {
  const body = ciphertext.replace(/[^A-Za-z0-9]/g, '').slice(-96);
  return body.match(/.{1,4}/g)?.join(' ') ?? body;
}

const styles = StyleSheet.create({
  wrap: { marginVertical: 3, paddingHorizontal: spacing.md, flexDirection: 'row' },
  wrapMine: { justifyContent: 'flex-end' },
  wrapTheirs: { justifyContent: 'flex-start' },
  bubble: {
    maxWidth: '82%',
    borderRadius: 14,
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderWidth: 1,
  },
  mine: { backgroundColor: colors.bubbleMine, borderColor: colors.accentDim },
  theirs: { backgroundColor: colors.bubbleTheirs, borderColor: colors.border },
  cipher: {
    color: colors.cipher,
    fontFamily: type.mono,
    fontSize: 12,
    letterSpacing: 0.5,
  },
  plain: { color: colors.text, fontSize: type.body },
  metaRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 6,
    gap: spacing.sm,
  },
  decodeBtn: { color: colors.accent, fontFamily: type.mono, fontSize: 12, fontWeight: '700' },
  countdown: { color: colors.accent, fontFamily: type.mono, fontSize: 11 },
  oneTime: { color: colors.danger, fontSize: 11 },
  failedText: { color: colors.danger, fontSize: 11 },
  burned: { color: colors.textDim, fontStyle: 'italic', fontSize: type.small },
  time: { color: colors.textDim, fontSize: 10, marginTop: 4, alignSelf: 'flex-end' },
});
