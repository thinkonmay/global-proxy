-- Test fixture for idempotency integration tests (register_message / mark_*).
-- Production schema: volumes/supabase/db/init/41_idempotency.sql

CREATE TABLE IF NOT EXISTS processed_message (
  id         text PRIMARY KEY,
  status     text        NOT NULL DEFAULT 'pending',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION register_message(p_id text)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO processed_message (id) VALUES (p_id) ON CONFLICT (id) DO NOTHING;
  IF FOUND THEN
    RETURN 'acquired';
  END IF;
  RETURN 'skip';
END $$;

CREATE OR REPLACE FUNCTION mark_done(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'done',  updated_at = now() WHERE id = p_id;
$$;

CREATE OR REPLACE FUNCTION mark_error(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'error', updated_at = now() WHERE id = p_id;
$$;
