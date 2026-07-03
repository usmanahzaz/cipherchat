import React, { useCallback, useEffect, useRef, useState } from 'react';
import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native';
import { usePreventScreenCapture } from 'expo-screen-capture';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { MessageBubble } from '../components/MessageBubble';
import { Input, Screen } from '../components/ui';
import type { Message } from '../lib/types';
import { useAuth } from '../state/auth';
import { useMessages } from '../state/messages';
import { useSettings } from '../state/settings';
import { colors, spacing, type } from '../theme';
import type { AppStackParamList } from '../navigation';

type Props = NativeStackScreenProps<AppStackParamList, 'Chat'>;

export function ChatScreen({ route, navigation }: Props) {
  // Blocks screenshots on Android (FLAG_SECURE) and screen recording on iOS
  // while this screen is focused. See SECURITY.md for platform limits.
  usePreventScreenCapture();

  const { contact } = route.params;
  const peer = contact.profile;
  const { userId, keyPair } = useAuth();
  const autoDecode = useSettings((s) => s.autoDecode);
  const { threads, loadThread, sendMessage, burnMessage, markDelivered } = useMessages();
  const [draft, setDraft] = useState('');
  const [oneTime, setOneTime] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const listRef = useRef<FlatList<Message>>(null);

  const messages = threads[peer.id] ?? [];

  useEffect(() => {
    loadThread(peer.id).then(() => markDelivered(peer.id));
  }, [peer.id, loadThread, markDelivered]);

  // New incoming realtime messages for this open thread → mark delivered.
  useEffect(() => {
    const undelivered = messages.some((m) => m.sender_id === peer.id && !m.delivered_at);
    if (undelivered) markDelivered(peer.id);
  }, [messages, peer.id, markDelivered]);

  const send = useCallback(async () => {
    const text = draft.trim();
    if (!text) return;
    setDraft('');
    const err = await sendMessage(peer, text, oneTime);
    setSendError(err);
    if (!err) setOneTime(false);
  }, [draft, peer, oneTime, sendMessage]);

  if (!userId || !keyPair) return null;

  return (
    <Screen pad={false}>
      <View style={styles.header}>
        <Pressable onPress={() => navigation.goBack()} hitSlop={8}>
          <Text style={styles.back}>‹</Text>
        </Pressable>
        <View style={styles.headerBody}>
          <Text style={styles.headerName}>{contact.alias ?? peer.email}</Text>
          <Text style={styles.headerSub} numberOfLines={1}>
            {peer.secure_id} · E2E encrypted
          </Text>
        </View>
      </View>

      <FlatList
        ref={listRef}
        data={messages}
        keyExtractor={(m) => m.id}
        onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: false })}
        renderItem={({ item }) => (
          <MessageBubble
            message={item}
            mine={item.sender_id === userId}
            peerPublicKey={peer.public_key}
            mySecretKey={keyPair.secretKey}
            autoDecode={autoDecode}
            onBurn={burnMessage}
          />
        )}
        contentContainerStyle={{ paddingVertical: spacing.sm }}
      />

      {sendError && <Text style={styles.sendError}>{sendError}</Text>}
      <View style={styles.composer}>
        <Pressable onPress={() => setOneTime((v) => !v)} hitSlop={8} style={styles.oneTimeBtn}>
          <Text style={[styles.oneTimeIcon, oneTime && { color: colors.danger }]}>🔥</Text>
        </Pressable>
        <Input
          placeholder={oneTime ? 'One-time message…' : 'Encrypted message…'}
          value={draft}
          onChangeText={setDraft}
          multiline
          style={styles.inputFlex}
        />
        <Pressable onPress={send} hitSlop={8} style={styles.sendBtn}>
          <Text style={styles.sendIcon}>➤</Text>
        </Pressable>
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    gap: spacing.md,
  },
  back: { color: colors.text, fontSize: 30, marginTop: -4 },
  headerBody: { flex: 1 },
  headerName: { color: colors.text, fontSize: type.body, fontWeight: '700' },
  headerSub: { color: colors.textDim, fontFamily: type.mono, fontSize: 10, marginTop: 2 },
  sendError: { color: colors.danger, paddingHorizontal: spacing.md, fontSize: type.small },
  composer: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    padding: spacing.sm,
    borderTopWidth: 1,
    borderTopColor: colors.border,
    gap: spacing.sm,
  },
  oneTimeBtn: { paddingBottom: 14, paddingLeft: 4 },
  oneTimeIcon: { fontSize: 18, color: colors.textDim, opacity: 0.9 },
  inputFlex: { flex: 1, maxHeight: 120 },
  sendBtn: {
    backgroundColor: colors.accent,
    borderRadius: 20,
    width: 40,
    height: 40,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 6,
  },
  sendIcon: { color: colors.bg, fontSize: 16 },
});
