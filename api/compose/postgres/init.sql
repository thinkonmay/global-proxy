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

-- 2. Jobs backbone (gateway enqueues via PostgREST; worker records outcome via PostgREST PATCH)
CREATE TABLE IF NOT EXISTS job (
  id          bigserial PRIMARY KEY,
  command     text        NOT NULL,
  arguments   jsonb       NOT NULL DEFAULT '{}'::jsonb,
  cluster     bigint,
  created_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  result      jsonb,
  success     boolean
);

-- 3. Transactional outbox (durability authority for jobs/payments; relay reads this)
CREATE TABLE IF NOT EXISTS outbox (
  id            bigserial PRIMARY KEY,
  topic         text        NOT NULL,
  payload       jsonb       NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  dispatched_at timestamptz                         -- NULL = pending; poller backstop
);
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox (created_at) WHERE dispatched_at IS NULL;

-- 4. Grants. MOCK-ONLY: anon may read job status; service_role writes everything.
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT SELECT                         ON job, outbox TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON job, outbox TO service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO service_role;
