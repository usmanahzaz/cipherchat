import React, { useState } from 'react';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { Button, ErrorText, Input, Screen, Subtitle, Title } from '../components/ui';
import { useAuth } from '../state/auth';
import type { AuthStackParamList } from '../navigation';

type Props = NativeStackScreenProps<AuthStackParamList, 'Auth'>;

export function AuthScreen({ route }: Props) {
  const [mode, setMode] = useState<'signup' | 'login'>(route.params.mode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { signUp, signIn } = useAuth();

  const submit = async () => {
    if (!email || password.length < 8) {
      setError('Enter your email and a password of at least 8 characters.');
      return;
    }
    setBusy(true);
    setError(null);
    const err = mode === 'signup' ? await signUp(email, password) : await signIn(email, password);
    setBusy(false);
    if (err) setError(err);
    // On success the root navigator switches automatically via auth state.
  };

  return (
    <Screen>
      <Title>{mode === 'signup' ? 'Create account' : 'Welcome back'}</Title>
      <Subtitle>
        {mode === 'signup'
          ? 'Your email is used only for sign-in and contact discovery. Your messages are never readable by us.'
          : 'Log in to continue. Your keys stay on this device.'}
      </Subtitle>
      <Input
        placeholder="email@example.com"
        keyboardType="email-address"
        autoComplete="email"
        value={email}
        onChangeText={setEmail}
      />
      <Input
        placeholder="password (min 8 characters)"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />
      <ErrorText>{error}</ErrorText>
      <Button
        label={mode === 'signup' ? 'Sign up' : 'Log in'}
        onPress={submit}
        loading={busy}
      />
      <Button
        label={mode === 'signup' ? 'Have an account? Log in' : 'New here? Create account'}
        variant="ghost"
        onPress={() => setMode(mode === 'signup' ? 'login' : 'signup')}
      />
    </Screen>
  );
}
