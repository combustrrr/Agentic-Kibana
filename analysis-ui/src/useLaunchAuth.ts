import { useEffect, useRef, useState } from 'react';

export function useLaunchAuth(endpoint?: string) {
  const [session, setSession] = useState<{ token: string; login: string }>();
  const [error, setError] = useState('');
  const popup = useRef<Window | null>(null);
  const nonce = useRef('');
  const origin = (() => { try { const u = new URL(endpoint || ''); return u.protocol === 'https:' && u.pathname === '/' && !u.search && !u.hash && !u.username && !u.password ? u.origin : undefined; } catch { return undefined; } })();
  useEffect(() => {
    setSession(undefined);
    const receive = (event: MessageEvent) => {
      if (!origin || event.origin !== origin || event.source !== popup.current || !nonce.current || event.data?.type !== 'analysis-auth' || event.data.nonce !== nonce.current) return;
      if (typeof event.data.token !== 'string' || typeof event.data.login !== 'string') return;
      setSession({ token: event.data.token, login: event.data.login }); nonce.current = ''; popup.current = null; setError('');
    };
    window.addEventListener('message', receive);
    return () => { window.removeEventListener('message', receive); popup.current?.close(); popup.current = null; nonce.current = ''; };
  }, [origin]);
  const signIn = () => {
    if (!origin) return;
    nonce.current = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
    popup.current?.close();
    popup.current = window.open(`${origin}/auth/login?nonce=${nonce.current}`, 'analysis-github-auth', 'popup,width=640,height=760');
    setError(popup.current ? '' : 'Allow the GitHub sign-in popup, then try again.');
  };
  async function api<T>(path: string, body?: unknown): Promise<T> {
    if (!origin || !session) throw new Error('Sign in to start analysis.');
    const response = await fetch(`${origin}/api/${path}`, { method: body ? 'POST' : 'GET', cache: 'no-store', credentials: 'omit',
      headers: { Authorization: `Bearer ${session.token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const result = await response.json();
    if (!response.ok) { if (response.status === 401) setSession(undefined); throw new Error(result.error || 'Analysis request failed.'); }
    return result as T;
  }
  return { available: !!origin, session, error, signIn, signOut: () => setSession(undefined), api };
}
