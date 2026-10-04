/**
 * Optional API-key access for deployments that set WARRANT_API_KEY / WARRANT_READ_KEY.
 *
 * The key is entered once by the user (never bundled), kept in this browser, and attached as
 * `X-Warrant-Key` to every same-origin /api request — including plain export links, which are
 * fetched with the header and downloaded. A 401/403 raises a `warrant:auth-required` event so the
 * UI can ask for (another) key.
 */
const STORAGE_KEY = 'warrant:api-key';
export const AUTH_EVENT = 'warrant:auth-required';

export function getApiKey(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

export function setApiKey(key: string): void {
  try {
    if (key.trim()) localStorage.setItem(STORAGE_KEY, key.trim());
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage unavailable: the key lasts until the page is reloaded
  }
}

import { API_BASE as apiBase } from './apiBase';

function isApiUrl(url: URL): boolean {
  if (url.origin === window.location.origin && url.pathname.startsWith('/api/')) return true;
  if (apiBase) {
    try {
      const base = new URL(apiBase, window.location.href);
      if (url.origin === base.origin && url.pathname.startsWith(base.pathname)) return true;
    } catch {
      // invalid URL, ignore
    }
  }
  return false;
}

let installed = false;

export function installApiAuth(): void {
  if (installed || typeof window === 'undefined') return;
  installed = true;
  const originalFetch = window.fetch.bind(window);

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = input instanceof Request ? input.url : String(input);
    let url: URL;
    try {
      url = new URL(raw, window.location.href);
    } catch {
      return originalFetch(input, init);
    }
    if (!isApiUrl(url)) return originalFetch(input, init);

    const key = getApiKey();
    let res: Response;
    if (key) {
      const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
      headers.set('X-Warrant-Key', key);
      res = await originalFetch(input, { ...init, headers });
    } else {
      res = await originalFetch(input, init);
    }
    if ((res.status === 401 || res.status === 403) && url.pathname !== '/api/health') {
      window.dispatchEvent(new CustomEvent(AUTH_EVENT, { detail: { status: res.status } }));
    }
    return res;
  };

  // Plain <a href="/api/..."> links (exports) cannot carry a header: fetch + download instead.
  document.addEventListener(
    'click',
    async (e) => {
      const a = (e.target as HTMLElement | null)?.closest?.('a[href]') as HTMLAnchorElement | null;
      if (!a || !getApiKey()) return;
      let url: URL;
      try {
        url = new URL(a.href, window.location.href);
      } catch {
        return;
      }
      if (!isApiUrl(url)) return;
      e.preventDefault();
      const res = await window.fetch(url.toString());
      if (!res.ok) return;
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      const disposition = res.headers.get('content-disposition') || '';
      const name = /filename="?([^";]+)"?/.exec(disposition)?.[1];
      const link = document.createElement('a');
      link.href = objectUrl;
      if (a.hasAttribute('download') || name) link.download = name || a.getAttribute('download') || '';
      else link.target = a.target || '_blank';
      link.rel = 'noopener';
      link.click();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
    },
    true,
  );
}
