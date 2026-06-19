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

-- 2. Worker state: one table merging the idempotency ledger and the processing
-- lock. Gateway never touches it — it only publishes; the worker owns all state.
CREATE TABLE IF NOT EXISTS processed_message (
  id           text PRIMARY KEY,                  -- message id = idempotency key
  status       text        NOT NULL DEFAULT 'pending', -- pending | done | error
  locked_until timestamptz NOT NULL DEFAULT now(),  -- lease; < now() = free
  attempts     int         NOT NULL DEFAULT 0,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

-- claim_message: atomic idempotency-check + lock-acquire in one transaction.
-- Returns 'done' (already processed, skip), 'locked' (held by another worker),
-- or 'acquired' (lease taken, run the side-effect).
CREATE OR REPLACE FUNCTION claim_message(p_id text, p_lease_secs int)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE existing text;
BEGIN
  INSERT INTO processed_message (id, status, locked_until, attempts)
    VALUES (p_id, 'pending', now() + make_interval(secs => p_lease_secs), 1)
  ON CONFLICT (id) DO UPDATE
    SET locked_until = now() + make_interval(secs => p_lease_secs),
        attempts     = processed_message.attempts + 1,
        updated_at   = now()
    WHERE processed_message.status <> 'done'
      AND processed_message.locked_until < now();
  IF FOUND THEN
    RETURN 'acquired';
  END IF;
  SELECT status INTO existing FROM processed_message WHERE id = p_id;
  IF existing = 'done' THEN RETURN 'done'; END IF;
  RETURN 'locked';
END $$;

-- mark_done: status='done' alone blocks re-claim. mark_error: expire the lease
-- (locked_until = now()) so the message is immediately re-acquirable.
CREATE OR REPLACE FUNCTION mark_done(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'done',  updated_at = now() WHERE id = p_id;
$$;
CREATE OR REPLACE FUNCTION mark_error(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'error', locked_until = now(), updated_at = now() WHERE id = p_id;
$$;

-- 3. Grants. MOCK-ONLY: anon may read status; service_role drives the worker RPCs.
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT SELECT                 ON processed_message TO anon;
GRANT SELECT, INSERT, UPDATE ON processed_message TO service_role;
GRANT EXECUTE ON FUNCTION claim_message(text, int), mark_done(text), mark_error(text) TO service_role;
