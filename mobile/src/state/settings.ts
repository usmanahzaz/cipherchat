import { create } from 'zustand';
import AsyncStorage from '@react-native-async-storage/async-storage';

/**
 * Non-secret preferences live in AsyncStorage. Anything secret (PIN hashes,
 * panic hash, private key) lives in the Keychain/Keystore via keystore.ts.
 */
interface SettingsState {
  loaded: boolean;
  autoDecode: boolean;
  appLockEnabled: boolean;
  biometricsEnabled: boolean;
  panicEnabled: boolean;

  load: () => Promise<void>;
  set: (patch: Partial<Omit<SettingsState, 'loaded' | 'load' | 'set'>>) => Promise<void>;
}

const STORAGE_KEY = 'cc.settings';

export const useSettings = create<SettingsState>((set, get) => ({
  loaded: false,
  autoDecode: false,
  appLockEnabled: false,
  biometricsEnabled: false,
  panicEnabled: false,

  load: async () => {
    try {
      const raw = await AsyncStorage.getItem(STORAGE_KEY);
      if (raw) set({ ...JSON.parse(raw), loaded: true });
      else set({ loaded: true });
    } catch {
      set({ loaded: true });
    }
  },

  set: async (patch) => {
    set(patch);
    const { autoDecode, appLockEnabled, biometricsEnabled, panicEnabled } = get();
    await AsyncStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ autoDecode, appLockEnabled, biometricsEnabled, panicEnabled }),
    );
  },
}));
