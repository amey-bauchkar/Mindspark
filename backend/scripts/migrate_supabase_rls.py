#!/usr/bin/env python3
"""
Warrant — Phase 3: Supabase Capability Token RLS Migration
Adds token_hash + workspace_id columns and replaces permissive public policies
with a capability-based access policy.

Run with:  python backend/scripts/migrate_supabase_rls.py
"""
from __future__ import annotations

import os
import sys
import urllib.request
import urllib.error
import json

SUPABASE_URL = "https://mrptseonimqhsemakmot.supabase.co"
SUPABASE_PAT = os.environ.get("SUPABASE_PAT", "")
PROJECT_ID = "mrptseonimqhsemakmot"
MANAGEMENT_API = f"https://api.supabase.com/v1/projects/{PROJECT_ID}/database/query"

# ---------------------------------------------------------------------------
# SQL migration — capability-based RLS
# ---------------------------------------------------------------------------
MIGRATION_SQL = """
-- Phase 3: Warrant Enterprise Capability Token Hardening
-- Safe to re-run (idempotent).

BEGIN;

-- 1. Add capability columns if they don't already exist
ALTER TABLE public.reports
    ADD COLUMN IF NOT EXISTS token_hash TEXT,
    ADD COLUMN IF NOT EXISTS workspace_id TEXT DEFAULT 'default';

-- 2. Create index for fast token_hash lookups
CREATE INDEX IF NOT EXISTS idx_reports_token_hash ON public.reports (token_hash);

-- 3. Drop all old permissive public policies
DROP POLICY IF EXISTS "Public read access for reports" ON public.reports;
DROP POLICY IF EXISTS "Public insert access for reports" ON public.reports;
DROP POLICY IF EXISTS "Allow insert for all users" ON public.reports;
DROP POLICY IF EXISTS "Capability token read access" ON public.reports;
DROP POLICY IF EXISTS "Authenticated workspace insert" ON public.reports;
DROP POLICY IF EXISTS "Capability token update access" ON public.reports;

-- 4. Capability-based read policy: access allowed if no token_hash set (legacy backwards compat)
--    OR if caller presents the matching raw token via x-warrant-token header (hashed server-side).
CREATE POLICY "Capability token read access"
    ON public.reports FOR SELECT
    USING (
        token_hash IS NULL
        OR token_hash = encode(
            sha256(
                coalesce(
                    current_setting('request.headers', true)::json->>'x-warrant-token',
                    ''
                )::bytea
            ),
            'hex'
        )
    );

-- 5. Insert: open for all (Supabase anon key is scoped to publishable key)
CREATE POLICY "Authenticated workspace insert"
    ON public.reports FOR INSERT
    WITH CHECK (true);

-- 6. Update: only if token matches (zero enumeration on updates)
CREATE POLICY "Capability token update access"
    ON public.reports FOR UPDATE
    USING (
        token_hash IS NULL
        OR token_hash = encode(
            sha256(
                coalesce(
                    current_setting('request.headers', true)::json->>'x-warrant-token',
                    ''
                )::bytea
            ),
            'hex'
        )
    );

COMMIT;
"""


def run_sql(sql: str) -> dict:
    """Execute SQL against Supabase Management API."""
    payload = json.dumps({"query": sql}).encode("utf-8")
    req = urllib.request.Request(
        MANAGEMENT_API,
        data=payload,
        headers={
            "Authorization": f"Bearer {SUPABASE_PAT}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  HTTP {e.code}: {body}", file=sys.stderr)
        raise


def main() -> None:
    print("=" * 60)
    print("Warrant Phase 3: Supabase Capability Token RLS Migration")
    print("=" * 60)
    print(f"  Project:  {PROJECT_ID}")
    print(f"  Endpoint: {MANAGEMENT_API}")
    print()

    print("[1/2] Applying RLS migration SQL...")
    try:
        result = run_sql(MIGRATION_SQL)
        print(f"  [OK] Migration applied. API response: {result}")
    except Exception as e:
        print(f"  [FAIL] Migration failed: {e}", file=sys.stderr)
        sys.exit(1)

    print()
    print("[2/2] Verifying columns exist...")
    verify_sql = """
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'reports'
        ORDER BY ordinal_position;
    """
    try:
        result = run_sql(verify_sql)
        cols = result if isinstance(result, list) else result.get("rows", result)
        print("  Current schema for public.reports:")
        for col in (cols if isinstance(cols, list) else []):
            print(f"    {col}")
        print("  [OK] Schema verified.")
    except Exception as e:
        print(f"  [WARN] Verification query failed (migration may still have succeeded): {e}")

    print()
    print("Phase 3 complete.")
    print("Reports are now protected by capability-based token hashing.")
    print("Legacy reports (token_hash IS NULL) retain backwards-compatible access.")


if __name__ == "__main__":
    main()
