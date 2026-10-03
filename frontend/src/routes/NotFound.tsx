import React from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

export default function NotFound() {
  return (
    <div
      className="container"
      style={{ paddingTop: 'var(--space-16)', paddingBottom: 'var(--space-16)', textAlign: 'center' }}
    >
      <Shield size={56} style={{ color: 'var(--color-border)', margin: '0 auto var(--space-6)' }} aria-hidden />
      <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, marginBottom: 'var(--space-3)' }}>
        Page not found
      </h1>
      <p style={{ color: 'var(--color-muted)', marginBottom: 'var(--space-6)' }}>
        The page you're looking for doesn't exist.
      </p>
      <Link to="/" className="btn btn-primary">Back to home</Link>
    </div>
  );
}
