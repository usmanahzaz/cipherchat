import React, { useState } from 'react';
import { Modal, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import QRCode from 'react-native-qrcode-svg';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { Button, ErrorText, Input, Screen, Subtitle, Title } from '../components/ui';
import { useAuth } from '../state/auth';
import { useMessages } from '../state/messages';
import { colors, spacing, type } from '../theme';
import type { AppStackParamList } from '../navigation';

type Props = NativeStackScreenProps<AppStackParamList, 'AddContact'>;

/** QR payload: "cipherchat:v1:<secure_id>" — resolved via the same exact-match lookup. */
const QR_PREFIX = 'cipherchat:v1:';

export function AddContactScreen({ navigation }: Props) {
  const { profile } = useAuth();
  const { addContact } = useMessages();
  const [identifier, setIdentifier] = useState('');
  const [alias, setAlias] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [permission, requestPermission] = useCameraPermissions();

  const submit = async (value?: string) => {
    const id = (value ?? identifier).trim();
    if (!id) return;
    setBusy(true);
    setError(null);
    const err = await addContact(id, alias.trim() || undefined);
    setBusy(false);
    if (err) setError(err);
    else navigation.goBack();
  };

  const openScanner = async () => {
    if (!permission?.granted) {
      const res = await requestPermission();
      if (!res.granted) {
        setError('Camera permission is required to scan QR codes.');
        return;
      }
    }
    setScanning(true);
  };

  return (
    <Screen>
      <ScrollView showsVerticalScrollIndicator={false}>
        <Title>Add contact</Title>
        <Subtitle>Enter their Secure ID, email, or full public key — or scan their QR code.</Subtitle>
        <Input
          placeholder="CC-XXXX-XXXX-XXXX-XXXX  ·  email  ·  public key"
          value={identifier}
          onChangeText={setIdentifier}
          autoCorrect={false}
        />
        <Input placeholder="alias (optional)" value={alias} onChangeText={setAlias} />
        <ErrorText>{error}</ErrorText>
        <Button label="Add contact" onPress={() => submit()} loading={busy} />
        <Button label="Scan QR code" variant="ghost" onPress={openScanner} />

        {profile?.secure_id && (
          <View style={styles.myCard}>
            <Text style={styles.myCardLabel}>YOUR QR — let others scan it</Text>
            <View style={styles.qrWrap}>
              <QRCode
                value={`${QR_PREFIX}${profile.secure_id}`}
                size={168}
                backgroundColor={colors.surface}
                color={colors.accent}
              />
            </View>
            <Text selectable style={styles.myId}>
              {profile.secure_id}
            </Text>
            <Text selectable style={styles.myKey} numberOfLines={2}>
              pub: {profile.public_key}
            </Text>
          </View>
        )}
      </ScrollView>

      <Modal visible={scanning} animationType="slide" onRequestClose={() => setScanning(false)}>
        <View style={styles.scanner}>
          <CameraView
            style={StyleSheet.absoluteFill}
            barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            onBarcodeScanned={({ data }) => {
              if (typeof data === 'string' && data.startsWith(QR_PREFIX)) {
                setScanning(false);
                const scanned = data.slice(QR_PREFIX.length);
                setIdentifier(scanned);
                submit(scanned);
              }
            }}
          />
          <Pressable style={styles.scannerClose} onPress={() => setScanning(false)}>
            <Text style={styles.scannerCloseText}>✕ Cancel</Text>
          </Pressable>
        </View>
      </Modal>
    </Screen>
  );
}

const styles = StyleSheet.create({
  myCard: {
    marginTop: spacing.xl,
    backgroundColor: colors.surface,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 14,
    padding: spacing.md,
    alignItems: 'center',
  },
  myCardLabel: {
    color: colors.textDim,
    fontFamily: type.mono,
    fontSize: 10,
    letterSpacing: 1.5,
    marginBottom: spacing.md,
  },
  qrWrap: { padding: spacing.sm, backgroundColor: colors.surface },
  myId: { color: colors.accent, fontFamily: type.mono, fontSize: 14, marginTop: spacing.md },
  myKey: { color: colors.textDim, fontFamily: type.mono, fontSize: 10, marginTop: spacing.xs },
  scanner: { flex: 1, backgroundColor: '#000' },
  scannerClose: {
    position: 'absolute',
    bottom: 48,
    alignSelf: 'center',
    backgroundColor: 'rgba(0,0,0,0.7)',
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderRadius: 20,
  },
  scannerCloseText: { color: '#fff', fontSize: 16 },
});
