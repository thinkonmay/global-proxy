-- Global Postgres bootstrap for the post-migration mock.
-- Creates the PostgREST role chain + the backbone tables (job, outbox).
-- Idempotent: the supabase/postgres image may already define some roles.

-- 1. PostgREST role chain (authenticator switches into anon / service_role per JWT)
DO $$ BEGIN CREATE ROLE anon          NOLOGIN;                       EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN;                       EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE service_role  NOLOGIN BYPASSRLS;             EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'peakthinkmaypassword';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
-- supabase/postgres pre-creates `authenticator` with a different password, so the
-- CREATE above is skipped — force login + our password unconditionally. Keep this
-- value in sync with POSTGRES_PASSWORD / PGRST_DB_URI in the compose file.
ALTER ROLE authenticator WITH LOGIN PASSWORD 'peakthinkmaypassword';
GRANT anon, authenticated, service_role TO authenticator;

-- Studio's "default" project connects pg-meta as `supabase_admin`@`db` (Supabase
-- defaults). POSTGRES_USER=thinkmay overrides the bootstrap superuser, so the
-- image never creates supabase_admin → Studio's /query 28P01. Recreate it (the
-- `db` host alias is set on the postgres service in compose).
DO $$ BEGIN
  CREATE ROLE supabase_admin SUPERUSER CREATEDB CREATEROLE LOGIN REPLICATION BYPASSRLS PASSWORD 'peakthinkmaypassword';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
ALTER ROLE supabase_admin WITH SUPERUSER LOGIN PASSWORD 'peakthinkmaypassword';

-- 2. Worker state: the at-most-once ledger. Gateway never touches it — it only
-- publishes; the worker registers + records every message here.
CREATE TABLE IF NOT EXISTS processed_message (
  id         text PRIMARY KEY,                       -- message id = idempotency key
  status     text        NOT NULL DEFAULT 'pending', -- pending | done | error (observability)
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- register_message: the consume commitment. Returns 'acquired' only on a fresh
-- insert (run the side-effect); 'skip' when the id already exists in any status
-- (duplicate or crash redelivery — never rerun). Dedup by existence = at most once.
CREATE OR REPLACE FUNCTION register_message(p_id text)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO processed_message (id) VALUES (p_id) ON CONFLICT (id) DO NOTHING;
  IF FOUND THEN
    RETURN 'acquired';
  END IF;
  RETURN 'skip';
END $$;

-- mark_done / mark_error record the single attempt's outcome (observability only;
-- neither makes the id re-runnable).
CREATE OR REPLACE FUNCTION mark_done(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'done',  updated_at = now() WHERE id = p_id;
$$;
CREATE OR REPLACE FUNCTION mark_error(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'error', updated_at = now() WHERE id = p_id;
$$;

-- 3. Grants. MOCK-ONLY: anon may read status; service_role drives the worker RPCs.
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT SELECT                 ON processed_message TO anon;
GRANT SELECT, INSERT, UPDATE ON processed_message TO service_role;
GRANT EXECUTE ON FUNCTION register_message(text), mark_done(text), mark_error(text) TO service_role;
