import React, { useCallback } from 'react';
import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { Screen } from '../components/ui';
import { useMessages } from '../state/messages';
import { colors, spacing, type } from '../theme';
import type { AppStackParamList } from '../navigation';

type Props = NativeStackScreenProps<AppStackParamList, 'ChatList'>;

export function ChatListScreen({ navigation }: Props) {
  const { contacts, loadContacts } = useMessages();

  useFocusEffect(
    useCallback(() => {
      loadContacts();
    }, [loadContacts]),
  );

  return (
    <Screen pad={false}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>⟨CC⟩ Chats</Text>
        <View style={styles.headerActions}>
          <Pressable onPress={() => navigation.navigate('AddContact')} hitSlop={8}>
            <Text style={styles.headerBtn}>＋</Text>
          </Pressable>
          <Pressable onPress={() => navigation.navigate('Settings')} hitSlop={8}>
            <Text style={styles.headerBtn}>⚙</Text>
          </Pressable>
        </View>
      </View>
      <FlatList
        data={contacts}
        keyExtractor={(c) => c.id}
        contentContainerStyle={contacts.length === 0 && styles.emptyWrap}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyGlyph}>⟨ ⟩</Text>
            <Text style={styles.emptyText}>
              No contacts yet.{'\n'}Add someone by Secure ID, email, public key, or QR code.
            </Text>
            <Pressable onPress={() => navigation.navigate('AddContact')}>
              <Text style={styles.emptyAction}>Add a contact →</Text>
            </Pressable>
          </View>
        }
        renderItem={({ item }) => (
          <Pressable
            style={({ pressed }) => [styles.rowItem, pressed && { opacity: 0.7 }]}
            onPress={() => navigation.navigate('Chat', { contact: item })}
          >
            <View style={styles.avatar}>
              <Text style={styles.avatarText}>
                {(item.alias ?? item.profile.email)[0]?.toUpperCase()}
              </Text>
            </View>
            <View style={styles.rowBody}>
              <Text style={styles.rowName}>{item.alias ?? item.profile.email}</Text>
              <Text style={styles.rowSub} numberOfLines={1}>
                {item.profile.secure_id}
              </Text>
            </View>
            <Text style={styles.chev}>›</Text>
          </Pressable>
        )}
      />
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  headerTitle: { color: colors.accent, fontFamily: type.mono, fontSize: 20, fontWeight: '700' },
  headerActions: { flexDirection: 'row', gap: spacing.lg },
  headerBtn: { color: colors.text, fontSize: 22 },
  emptyWrap: { flexGrow: 1, justifyContent: 'center' },
  empty: { alignItems: 'center', padding: spacing.xl },
  emptyGlyph: { color: colors.border, fontFamily: type.mono, fontSize: 44, marginBottom: spacing.md },
  emptyText: { color: colors.textDim, textAlign: 'center', lineHeight: 21 },
  emptyAction: { color: colors.accent, marginTop: spacing.md, fontWeight: '600' },
  rowItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: spacing.md,
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: colors.border,
    gap: spacing.md,
  },
  avatar: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: colors.surfaceAlt,
    borderWidth: 1,
    borderColor: colors.accentDim,
    alignItems: 'center',
    justifyContent: 'center',
  },
  avatarText: { color: colors.accent, fontSize: 18, fontWeight: '700' },
  rowBody: { flex: 1 },
  rowName: { color: colors.text, fontSize: type.body, fontWeight: '600' },
  rowSub: { color: colors.textDim, fontFamily: type.mono, fontSize: 11, marginTop: 2 },
  chev: { color: colors.textDim, fontSize: 22 },
});
