import 'react-native-get-random-values';
import 'react-native-url-polyfill/auto';
import React, { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, AppState, StyleSheet, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { RootNavigator } from './src/navigation';
import { LockScreen } from './src/screens/LockScreen';
import { registerPushToken } from './src/lib/notifications';
import { useAuth } from './src/state/auth';
import { useMessages } from './src/state/messages';
import { useSettings } from './src/state/settings';
import { colors } from './src/theme';

export default function App() {
  const { initialized, userId, needsKeySetup, init } = useAuth();
  const settings = useSettings();
  const { subscribe, unsubscribe, loadContacts } = useMessages();
  const [locked, setLocked] = useState(false);
  const lockArmedRef = useRef(false);

  useEffect(() => {
    settings.load().then(init);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Arm the lock once settings are known; re-lock when app goes to background.
  useEffect(() => {
    if (!settings.loaded) return;
    if (settings.appLockEnabled && !lockArmedRef.current) {
      lockArmedRef.current = true;
      setLocked(true);
    }
    const sub = AppState.addEventListener('change', (state) => {
      if (state === 'background' && useSettings.getState().appLockEnabled) setLocked(true);
    });
    return () => sub.remove();
  }, [settings.loaded, settings.appLockEnabled]);

  // Signed-in with keys → open realtime inbox + register push.
  useEffect(() => {
    if (userId && !needsKeySetup) {
      loadContacts();
      subscribe();
      registerPushToken(userId);
      return unsubscribe;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, needsKeySetup]);

  if (!initialized || !settings.loaded) {
    return (
      <View style={styles.splash}>
        <ActivityIndicator color={colors.accent} />
      </View>
    );
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      {locked && settings.appLockEnabled ? (
        <LockScreen onUnlock={() => setLocked(false)} />
      ) : (
        <RootNavigator />
      )}
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  splash: { flex: 1, backgroundColor: colors.bg, alignItems: 'center', justifyContent: 'center' },
});
