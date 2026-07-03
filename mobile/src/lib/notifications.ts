/**
 * Push notifications intentionally carry zero message content. The server
 * (server/src/push.js) sends only the fixed string
 * "Encrypted message received" — no sender, no preview, no ciphertext.
 */
import * as Notifications from 'expo-notifications';
import * as Device from 'expo-device';
import { Platform } from 'react-native';
import { api } from './api';

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowBanner: true,
    shouldShowList: true,
    shouldPlaySound: false,
    shouldSetBadge: false,
  }),
});

export async function registerPushToken(): Promise<void> {
  try {
    if (!Device.isDevice) return; // emulators cannot receive push
    const { status } = await Notifications.requestPermissionsAsync();
    if (status !== 'granted') return;

    if (Platform.OS === 'android') {
      await Notifications.setNotificationChannelAsync('messages', {
        name: 'Messages',
        importance: Notifications.AndroidImportance.DEFAULT,
        // Never show content on the lock screen.
        lockscreenVisibility: Notifications.AndroidNotificationVisibility.SECRET,
      });
    }

    const token = (await Notifications.getExpoPushTokenAsync()).data;
    await api.setPushToken(token);
  } catch {
    // Push is best-effort; messaging works without it.
  }
}
