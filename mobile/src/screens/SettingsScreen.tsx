import React from 'react';
import { Pressable, ScrollView, StyleSheet, Switch, Text, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { Button, Screen, Title } from '../components/ui';
import { useAuth } from '../state/auth';
import { useMessages } from '../state/messages';
import { useSettings } from '../state/settings';
import { colors, spacing, type } from '../theme';
import type { AppStackParamList } from '../navigation';

type Props = NativeStackScreenProps<AppStackParamList, 'Settings'>;

export function SettingsScreen({ navigation }: Props) {
  const { profile, signOut } = useAuth();
  const settings = useSettings();
  const resetMessages = useMessages((s) => s.reset);

  return (
    <Screen>
      <ScrollView showsVerticalScrollIndicator={false}>
        <Title>Settings</Title>

        {profile && (
          <View style={styles.card}>
            <Text style={styles.cardLabel}>IDENTITY</Text>
            <Text style={styles.email}>{profile.email}</Text>
            <Text selectable style={styles.secureId}>
              {profile.secure_id}
            </Text>
          </View>
        )}

        <View style={styles.card}>
          <Text style={styles.cardLabel}>MESSAGES</Text>
          <View style={styles.settingRow}>
            <View style={styles.settingBody}>
              <Text style={styles.settingName}>Auto Decode</Text>
              <Text style={styles.settingHint}>
                Decrypt incoming messages automatically. Each still self-conceals after 10 seconds.
              </Text>
            </View>
            <Switch
              value={settings.autoDecode}
              onValueChange={(v) => settings.set({ autoDecode: v })}
              trackColor={{ true: colors.accentDim }}
              thumbColor={settings.autoDecode ? colors.accent : colors.textDim}
            />
          </View>
        </View>

        <View style={styles.card}>
          <Text style={styles.cardLabel}>SECURITY</Text>
          <Pressable style={styles.linkRow} onPress={() => navigation.navigate('SecuritySettings')}>
            <Text style={styles.settingName}>App lock (PIN & biometrics)</Text>
            <Text style={styles.chev}>›</Text>
          </Pressable>
          <Pressable style={styles.linkRow} onPress={() => navigation.navigate('PanicSettings')}>
            <Text style={[styles.settingName, { color: colors.danger }]}>Panic mode</Text>
            <Text style={styles.chev}>›</Text>
          </Pressable>
        </View>

        <Button
          label="Log out"
          variant="ghost"
          onPress={async () => {
            resetMessages();
            await signOut();
          }}
        />
        <Text style={styles.footnote}>
          Logging out keeps your keys on this device so history remains decodable when you return.
          Panic mode destroys them.
        </Text>
      </ScrollView>
    </Screen>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.surface,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 14,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  cardLabel: {
    color: colors.textDim,
    fontFamily: type.mono,
    fontSize: 10,
    letterSpacing: 1.5,
    marginBottom: spacing.sm,
  },
  email: { color: colors.text, fontSize: type.body, fontWeight: '600' },
  secureId: { color: colors.accent, fontFamily: type.mono, fontSize: 13, marginTop: 4 },
  settingRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.md },
  settingBody: { flex: 1 },
  settingName: { color: colors.text, fontSize: type.body },
  settingHint: { color: colors.textDim, fontSize: 12, marginTop: 2, lineHeight: 17 },
  linkRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: spacing.sm,
  },
  chev: { color: colors.textDim, fontSize: 20 },
  footnote: {
    color: colors.textDim,
    fontSize: 12,
    textAlign: 'center',
    marginTop: spacing.sm,
    lineHeight: 17,
  },
});
