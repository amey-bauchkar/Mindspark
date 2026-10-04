import React, { useEffect, useState } from 'react';
import { KeyRound } from 'lucide-react';
import { AUTH_EVENT, getApiKey, setApiKey } from '../lib/apiAuth';
import { API_BASE } from '../lib/api';

/**
 * Asks for the Warrant API key when the server requires one (WARRANT_API_KEY / WARRANT_READ_KEY)
 * and none is stored, or when the stored key is rejected.
 */
export function ApiKeyGate() {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [value, setValue] = useState('');

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then(r => r.json())
      .then(h => {
        if (h.auth_required && !getApiKey()) {
          setReason('This Warrant server requires an API key.');
          setOpen(true);
        }
      })
      .catch(() => {});
    const onAuth = (e: Event) => {
      const status = (e as CustomEvent).detail?.status;
      setReason(status === 403
        ? 'Your key is read-only. Enter a full-access key to make changes.'
        : getApiKey() ? 'The stored API key was rejected.' : 'This Warrant server requires an API key.');
      setOpen(true);
    };
    window.addEventListener(AUTH_EVENT, onAuth);
    return () => window.removeEventListener(AUTH_EVENT, onAuth);
  }, []);

  if (!open) return null;

  const save = (e: React.FormEvent) => {
    e.preventDefault();
    setApiKey(value);
    window.location.reload();
  };

  return (
    <div className="drawer-overlay" role="dialog" aria-modal="true" aria-labelledby="api-key-title"
         style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200 }}>
      <form onSubmit={save} className="card" style={{ maxWidth: 420, width: 'calc(100% - 32px)' }}>
        <h2 id="api-key-title" className="watch-panel-title"><KeyRound size={16} aria-hidden /> API key required</h2>
        <p className="watch-meta" style={{ marginBottom: 'var(--space-3)' }}>
          {reason} Ask your Warrant administrator for a key. It is stored only in this browser.
        </p>
        <input
          className="input"
          type="password"
          autoFocus
          autoComplete="off"
          aria-label="API key"
          value={value}
          onChange={e => setValue(e.target.value)}
          style={{ width: '100%' }}
        />
        <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end', marginTop: 'var(--space-3)' }}>
          {getApiKey() && (
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => { setApiKey(''); window.location.reload(); }}>
              Forget stored key
            </button>
          )}
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>Cancel</button>
          <button type="submit" className="btn btn-primary btn-sm" disabled={!value.trim()}>Save key</button>
        </div>
      </form>
    </div>
  );
}

export default ApiKeyGate;
