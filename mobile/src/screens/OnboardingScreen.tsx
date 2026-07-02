import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { Button, Screen, Subtitle, Title } from '../components/ui';
import { colors, spacing, type } from '../theme';
import type { AuthStackParamList } from '../navigation';

type Props = NativeStackScreenProps<AuthStackParamList, 'Onboarding'>;

export function OnboardingScreen({ navigation }: Props) {
  return (
    <Screen>
      <View style={styles.hero}>
        <Text style={styles.logo}>⟨CC⟩</Text>
        <Title>CipherChat</Title>
        <Subtitle>Private by mathematics, not by promise.</Subtitle>
        {[
          ['🔐', 'End-to-end encrypted. Keys are generated on your device and the private key never leaves it.'],
          ['👁', 'Messages render as ciphertext. Decode to read — plaintext self-conceals after 10 seconds.'],
          ['🛰', 'The server stores only encrypted blobs. It cannot read anything, ever.'],
          ['🧨', 'Panic PIN instantly destroys your keys, making every message permanently unreadable.'],
        ].map(([icon, text]) => (
          <View key={icon} style={styles.feature}>
            <Text style={styles.featureIcon}>{icon}</Text>
            <Text style={styles.featureText}>{text}</Text>
          </View>
        ))}
      </View>
      <Button label="Create account" onPress={() => navigation.navigate('Auth', { mode: 'signup' })} />
      <Button
        label="I already have an account"
        variant="ghost"
        onPress={() => navigation.navigate('Auth', { mode: 'login' })}
      />
    </Screen>
  );
}

const styles = StyleSheet.create({
  hero: { flex: 1, justifyContent: 'center' },
  logo: {
    color: colors.accent,
    fontFamily: type.mono,
    fontSize: 40,
    marginBottom: spacing.md,
  },
  feature: { flexDirection: 'row', marginVertical: spacing.sm, gap: spacing.sm },
  featureIcon: { fontSize: 18, width: 28 },
  featureText: { color: colors.textDim, flex: 1, fontSize: type.small, lineHeight: 19 },
});
