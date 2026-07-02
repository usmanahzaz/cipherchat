import React, { useEffect, useState } from 'react';
import { StyleSheet, Switch, Text, View } from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import { Button, ErrorText, Input, Screen, Subtitle, Title } from '../components/ui';
import { hashPin, newSalt } from '../lib/crypto';
import { clearPin, getPin, savePin } from '../lib/keystore';
import { useSettings } from '../state/settings';
import { colors, spacing, type } from '../theme';

export function SecuritySettingsScreen() {
  const settings = useSettings();
  const [pin, setPin] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [hasPin, setHasPin] = useState(false);
  const [biometricsAvailable, setBiometricsAvailable] = useState(false);

  useEffect(() => {
    getPin().then((p) => setHasPin(!!p));
    LocalAuthentication.hasHardwareAsync().then(async (hw) => {
      const enrolled = hw && (await LocalAuthentication.isEnrolledAsync());
      setBiometricsAvailable(!!enrolled);
    });
  }, []);

  const setUpPin = async () => {
    setError(null);
    if (!/^\d{4,8}$/.test(pin)) {
      setError('PIN must be 4–8 digits.');
      return;
    }
    if (pin !== confirm) {
      setError('PINs do not match.');
      return;
    }
    const salt = newSalt();
    await savePin(hashPin(pin, salt), salt);
    await settings.set({ appLockEnabled: true });
    setHasPin(true);
    setPin('');
    setConfirm('');
  };

  const disableLock = async () => {
    await clearPin();
    await settings.set({ appLockEnabled: false, biometricsEnabled: false });
    setHasPin(false);
  };

  return (
    <Screen>
      <Title>App lock</Title>
      <Subtitle>
        Require a PIN (and optionally biometrics) every time CipherChat opens or returns from the
        background.
      </Subtitle>

      {hasPin ? (
        <>
          <View style={styles.row}>
            <Text style={styles.rowLabel}>App lock enabled</Text>
            <Text style={styles.on}>ON</Text>
          </View>
          {biometricsAvailable && (
            <View style={styles.row}>
              <Text style={styles.rowLabel}>Unlock with Face ID / fingerprint</Text>
              <Switch
                value={settings.biometricsEnabled}
                onValueChange={(v) => settings.set({ biometricsEnabled: v })}
                trackColor={{ true: colors.accentDim }}
                thumbColor={settings.biometricsEnabled ? colors.accent : colors.textDim}
              />
            </View>
          )}
          <Button label="Disable app lock" variant="danger" onPress={disableLock} />
        </>
      ) : (
        <>
          <Input
            placeholder="new PIN (4–8 digits)"
            keyboardType="number-pad"
            secureTextEntry
            maxLength={8}
            value={pin}
            onChangeText={setPin}
          />
          <Input
            placeholder="confirm PIN"
            keyboardType="number-pad"
            secureTextEntry
            maxLength={8}
            value={confirm}
            onChangeText={setConfirm}
          />
          <ErrorText>{error}</ErrorText>
          <Button label="Enable app lock" onPress={setUpPin} />
        </>
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: spacing.md,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: colors.border,
  },
  rowLabel: { color: colors.text, fontSize: type.body, flex: 1 },
  on: { color: colors.accent, fontFamily: type.mono, fontWeight: '700' },
});
