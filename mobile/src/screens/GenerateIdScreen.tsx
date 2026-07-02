import React, { useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { Button, ErrorText, Screen, Subtitle, Title } from '../components/ui';
import { useAuth } from '../state/auth';
import { colors, spacing, type } from '../theme';

/**
 * Shown after sign-up (or after login on a device with no keys). Generates
 * the X25519 key pair locally, stores the private key in Keychain/Keystore,
 * and publishes the public key + derived Secure ID.
 */
export function GenerateIdScreen() {
  const { provisionKeys, profile } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const generate = async () => {
    setBusy(true);
    setError(null);
    const err = await provisionKeys();
    setBusy(false);
    if (err) setError(err);
    else setDone(true);
  };

  if (done && profile) {
    return (
      <Screen>
        <View style={styles.center}>
          <Title>Your Secure ID</Title>
          <View style={styles.idCard}>
            <Text selectable style={styles.secureId}>
              {profile.secure_id}
            </Text>
          </View>
          <Subtitle>
            Share this ID (or your email) so others can add you. Your private key was stored in
            this device's secure enclave and never leaves it.
          </Subtitle>
        </View>
        {/* Root navigator switches to the app once needsKeySetup flips. */}
      </Screen>
    );
  }

  return (
    <Screen>
      <View style={styles.center}>
        <Text style={styles.keyGlyph}>⚿</Text>
        <Title>Generate your identity</Title>
        <Subtitle>
          CipherChat will create an X25519 key pair on this device. The public half becomes your
          shareable Secure ID. The private half is written to the {`\n`}iOS Keychain / Android
          Keystore and is never uploaded, backed up, or displayed.
        </Subtitle>
        <ErrorText>{error}</ErrorText>
      </View>
      <Button label="Generate Secure ID" onPress={generate} loading={busy} />
    </Screen>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, justifyContent: 'center' },
  keyGlyph: { color: colors.accent, fontSize: 48, marginBottom: spacing.md },
  idCard: {
    backgroundColor: colors.surface,
    borderColor: colors.accentDim,
    borderWidth: 1,
    borderRadius: 12,
    padding: spacing.md,
    marginVertical: spacing.md,
  },
  secureId: {
    color: colors.accent,
    fontFamily: type.mono,
    fontSize: 18,
    textAlign: 'center',
  },
});
