/**
 * Push notifications intentionally carry zero message content. The Edge
 * Function (supabase/functions/notify-message) sends only the fixed string
 * "Encrypted message received" — no sender, no preview, no ciphertext.
 */
import * as Notifications from 'expo-notifications';
import * as Device from 'expo-device';
import { Platform } from 'react-native';
import { supabase } from './supabase';

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: false,
    shouldSetBadge: false,
  }),
});

export async function registerPushToken(userId: string): Promise<void> {
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
    await supabase.from('profiles').update({ push_token: token }).eq('id', userId);
  } catch {
    // Push is best-effort; messaging works without it.
  }
}
