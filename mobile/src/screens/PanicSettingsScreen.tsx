import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { Button, ErrorText, Input, Screen, Subtitle, Title } from '../components/ui';
import { hashPin } from '../lib/crypto';
import { clearPanicHash, getPanicHash, getPin, savePanicHash } from '../lib/keystore';
import { useSettings } from '../state/settings';
import { colors, spacing, type } from '../theme';

/**
 * Panic PIN: a decoy PIN entered at the lock screen that, instead of
 * unlocking, silently destroys the private key, all secure material, and all
 * local state — making every stored ciphertext permanently unreadable.
 * The panic hash is salted with the same salt as the unlock PIN so the lock
 * screen can check both with one entry.
 */
export function PanicSettingsScreen() {
  const settings = useSettings();
  const [pin, setPin] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [armed, setArmed] = useState(false);
  const [hasLockPin, setHasLockPin] = useState(false);

  useEffect(() => {
    getPanicHash().then((h) => setArmed(!!h));
    getPin().then((p) => setHasLockPin(!!p));
  }, []);

  const arm = async () => {
    setError(null);
    const lockPin = await getPin();
    if (!lockPin) {
      setError('Set up an app-lock PIN first (Settings → App lock).');
      return;
    }
    if (!/^\d{4,8}$/.test(pin)) {
      setError('Panic PIN must be 4–8 digits.');
      return;
    }
    if (pin !== confirm) {
      setError('PINs do not match.');
      return;
    }
    const candidate = hashPin(pin, lockPin.salt);
    if (candidate === lockPin.hash) {
      setError('Panic PIN must be different from your unlock PIN.');
      return;
    }
    await savePanicHash(candidate);
    await settings.set({ panicEnabled: true });
    setArmed(true);
    setPin('');
    setConfirm('');
  };

  const disarm = async () => {
    await clearPanicHash();
    await settings.set({ panicEnabled: false });
    setArmed(false);
  };

  return (
    <Screen>
      <Title>Panic mode</Title>
      <Subtitle>
        If you are ever forced to unlock the app, enter your panic PIN instead. CipherChat will
        open to a wiped state: your private key and all local data are destroyed instantly, and
        every stored message becomes permanently unreadable — even to you.
      </Subtitle>

      <View style={styles.warnBox}>
        <Text style={styles.warnText}>
          ⚠ This cannot be undone. There is no key backup by design.
        </Text>
      </View>

      {armed ? (
        <>
          <View style={styles.row}>
            <Text style={styles.rowLabel}>Panic PIN armed</Text>
            <Text style={styles.armed}>ARMED</Text>
          </View>
          <Button label="Disarm panic PIN" variant="danger" onPress={disarm} />
        </>
      ) : (
        <>
          {!hasLockPin && (
            <Text style={styles.prereq}>Requires app lock to be enabled first.</Text>
          )}
          <Input
            placeholder="panic PIN (4–8 digits)"
            keyboardType="number-pad"
            secureTextEntry
            maxLength={8}
            value={pin}
            onChangeText={setPin}
          />
          <Input
            placeholder="confirm panic PIN"
            keyboardType="number-pad"
            secureTextEntry
            maxLength={8}
            value={confirm}
            onChangeText={setConfirm}
          />
          <ErrorText>{error}</ErrorText>
          <Button label="Arm panic PIN" onPress={arm} disabled={!hasLockPin} />
        </>
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  warnBox: {
    backgroundColor: '#2A1215',
    borderColor: colors.danger,
    borderWidth: 1,
    borderRadius: 12,
    padding: spacing.md,
    marginBottom: spacing.lg,
  },
  warnText: { color: colors.danger, fontSize: type.small, lineHeight: 19 },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: spacing.md,
  },
  rowLabel: { color: colors.text, fontSize: type.body },
  armed: { color: colors.danger, fontFamily: type.mono, fontWeight: '700' },
  prereq: { color: colors.textDim, fontSize: type.small, marginBottom: spacing.sm },
});
