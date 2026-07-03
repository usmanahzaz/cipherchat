import React from 'react';
import { DarkTheme, NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import type { Contact } from '../lib/types';
import { AddContactScreen } from '../screens/AddContactScreen';
import { AuthScreen } from '../screens/AuthScreen';
import { ChatListScreen } from '../screens/ChatListScreen';
import { ChatScreen } from '../screens/ChatScreen';
import { GenerateIdScreen } from '../screens/GenerateIdScreen';
import { OnboardingScreen } from '../screens/OnboardingScreen';
import { PanicSettingsScreen } from '../screens/PanicSettingsScreen';
import { SecuritySettingsScreen } from '../screens/SecuritySettingsScreen';
import { SettingsScreen } from '../screens/SettingsScreen';
import { useAuth } from '../state/auth';
import { colors } from '../theme';

export type AuthStackParamList = {
  Onboarding: undefined;
  Auth: { mode: 'signup' | 'login' };
};

export type AppStackParamList = {
  ChatList: undefined;
  Chat: { contact: Contact };
  AddContact: undefined;
  Settings: undefined;
  SecuritySettings: undefined;
  PanicSettings: undefined;
};

const AuthStack = createNativeStackNavigator<AuthStackParamList>();
const AppStack = createNativeStackNavigator<AppStackParamList>();

const theme = {
  ...DarkTheme,
  colors: {
    ...DarkTheme.colors,
    background: colors.bg,
    card: colors.surface,
    text: colors.text,
    border: colors.border,
    primary: colors.accent,
  },
};

const screenOptions = { headerShown: false, contentStyle: { backgroundColor: colors.bg } };

export function RootNavigator() {
  const { userId, needsKeySetup } = useAuth();

  return (
    <NavigationContainer theme={theme}>
      {!userId ? (
        <AuthStack.Navigator screenOptions={screenOptions}>
          <AuthStack.Screen name="Onboarding" component={OnboardingScreen} />
          <AuthStack.Screen name="Auth" component={AuthScreen} />
        </AuthStack.Navigator>
      ) : needsKeySetup ? (
        <GenerateIdScreen />
      ) : (
        <AppStack.Navigator screenOptions={screenOptions}>
          <AppStack.Screen name="ChatList" component={ChatListScreen} />
          <AppStack.Screen name="Chat" component={ChatScreen} />
          <AppStack.Screen name="AddContact" component={AddContactScreen} />
          <AppStack.Screen name="Settings" component={SettingsScreen} />
          <AppStack.Screen name="SecuritySettings" component={SecuritySettingsScreen} />
          <AppStack.Screen name="PanicSettings" component={PanicSettingsScreen} />
        </AppStack.Navigator>
      )}
    </NavigationContainer>
  );
}
