-- Test fixture for idempotency integration tests (register_message / mark_*).
-- Production schema: volumes/supabase/db/init/41_idempotency.sql

CREATE TABLE IF NOT EXISTS processed_message (
  id         text PRIMARY KEY,
  status     text        NOT NULL DEFAULT 'pending',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION register_message(p_id text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  v_status text;
  v_updated timestamptz;
BEGIN
  SELECT status, updated_at INTO v_status, v_updated
  FROM processed_message WHERE id = p_id;

  IF NOT FOUND THEN
    INSERT INTO processed_message (id, status) VALUES (p_id, 'pending');
    RETURN 'acquired';
  END IF;

  IF v_status = 'done' THEN
    RETURN 'skip';
  END IF;

  IF v_status = 'pending' AND v_updated > now() - interval '2 minutes' THEN
    RETURN 'skip';
  END IF;

  UPDATE processed_message
  SET status = 'pending', updated_at = now()
  WHERE id = p_id;
  RETURN 'acquired';
END $$;

CREATE OR REPLACE FUNCTION mark_done(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'done',  updated_at = now() WHERE id = p_id;
$$;

CREATE OR REPLACE FUNCTION mark_error(p_id text) RETURNS void LANGUAGE sql AS $$
  UPDATE processed_message SET status = 'error', updated_at = now() WHERE id = p_id;
$$;
