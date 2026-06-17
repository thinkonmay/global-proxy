-- +goose Up
-- +goose StatementBegin
CREATE TABLE job (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    command     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    running_at  TIMESTAMPTZ,
    result      JSONB,
    success     BOOLEAN,
    arguments   JSONB       NOT NULL,
    cluster     BIGINT,
    finished_at TIMESTAMPTZ
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE job;
-- +goose StatementEnd
