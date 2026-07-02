import React, { useCallback, useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import { hashPin } from '../lib/crypto';
import { getPanicHash, getPin } from '../lib/keystore';
import { useAuth } from '../state/auth';
import { useMessages } from '../state/messages';
import { useSettings } from '../state/settings';
import { colors, spacing, type } from '../theme';

const PIN_LENGTH_MAX = 8;

/**
 * Full-screen gate shown when app lock is enabled. A correct PIN (or
 * biometric) unlocks. The panic PIN is checked FIRST and triggers a silent
 * full wipe — visually indistinguishable from a failed unlock followed by a
 * fresh install state.
 */
export function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [entry, setEntry] = useState('');
  const [shake, setShake] = useState(false);
  const biometricsEnabled = useSettings((s) => s.biometricsEnabled);
  const panicWipe = useAuth((s) => s.panicWipe);
  const resetMessages = useMessages((s) => s.reset);

  const tryBiometrics = useCallback(async () => {
    const res = await LocalAuthentication.authenticateAsync({
      promptMessage: 'Unlock CipherChat',
      cancelLabel: 'Use PIN',
      disableDeviceFallback: true,
    });
    if (res.success) onUnlock();
  }, [onUnlock]);

  useEffect(() => {
    if (biometricsEnabled) tryBiometrics();
  }, [biometricsEnabled, tryBiometrics]);

  const submit = useCallback(
    async (candidate: string) => {
      const stored = await getPin();
      if (!stored) {
        onUnlock(); // lock removed while screen was up
        return;
      }
      const digest = hashPin(candidate, stored.salt);

      const panic = await getPanicHash();
      if (panic && digest === panic) {
        resetMessages();
        await panicWipe();
        return; // root navigator falls back to onboarding
      }
      if (digest === stored.hash) {
        onUnlock();
        return;
      }
      setEntry('');
      setShake(true);
      setTimeout(() => setShake(false), 400);
    },
    [onUnlock, panicWipe, resetMessages],
  );

  const press = (digit: string) => {
    if (entry.length >= PIN_LENGTH_MAX) return;
    const next = entry + digit;
    setEntry(next);
  };

  return (
    <View style={styles.screen}>
      <Text style={styles.logo}>⟨CC⟩</Text>
      <Text style={styles.prompt}>Enter PIN</Text>
      <View style={styles.dots}>
        <Text style={[styles.dotText, shake && { color: colors.danger }]}>
          {'●'.repeat(entry.length) || '─'}
        </Text>
      </View>
      <View style={styles.pad}>
        {['1', '2', '3', '4', '5', '6', '7', '8', '9', 'bio', '0', 'del'].map((k) => (
          <Pressable
            key={k}
            style={({ pressed }) => [styles.key, pressed && { opacity: 0.5 }]}
            onPress={() => {
              if (k === 'del') setEntry((e) => e.slice(0, -1));
              else if (k === 'bio') biometricsEnabled && tryBiometrics();
              else press(k);
            }}
          >
            <Text style={styles.keyText}>
              {k === 'del' ? '⌫' : k === 'bio' ? (biometricsEnabled ? '☉' : '') : k}
            </Text>
          </Pressable>
        ))}
      </View>
      <Pressable
        onPress={() => entry.length >= 4 && submit(entry)}
        style={[styles.enter, entry.length < 4 && { opacity: 0.3 }]}
      >
        <Text style={styles.enterText}>UNLOCK</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: colors.bg,
    alignItems: 'center',
    justifyContent: 'center',
    padding: spacing.xl,
  },
  logo: { color: colors.accent, fontFamily: type.mono, fontSize: 32, marginBottom: spacing.sm },
  prompt: { color: colors.textDim, marginBottom: spacing.lg },
  dots: { height: 32, justifyContent: 'center', marginBottom: spacing.lg },
  dotText: { color: colors.accent, fontSize: 20, letterSpacing: 6 },
  pad: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    width: 264,
    justifyContent: 'center',
  },
  key: {
    width: 72,
    height: 72,
    margin: 8,
    borderRadius: 36,
    backgroundColor: colors.surface,
    alignItems: 'center',
    justifyContent: 'center',
  },
  keyText: { color: colors.text, fontSize: 24 },
  enter: {
    marginTop: spacing.lg,
    borderColor: colors.accent,
    borderWidth: 1,
    borderRadius: 24,
    paddingHorizontal: 36,
    paddingVertical: 12,
  },
  enterText: { color: colors.accent, fontFamily: type.mono, fontWeight: '700', letterSpacing: 2 },
});
