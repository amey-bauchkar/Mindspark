/**
 * Base URL of the Warrant API.
 *
 * Default "/api": same origin (Vite dev proxy locally, vercel.json rewrite to Render in production).
 * VITE_API_BASE_URL may point straight at the backend; it is accepted with or without the
 * trailing "/api" (e.g. "https://warrant-backend.onrender.com" or ".../api").
 */
function normalise(raw: string | undefined): string {
  const value = (raw || '').trim().replace(/\/+$/, '');
  if (!value) return '/api';
  return /\/api$/.test(value) ? value : `${value}/api`;
}

export const API_BASE = normalise(import.meta.env.VITE_API_BASE_URL);
