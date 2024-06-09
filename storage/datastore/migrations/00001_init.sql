-- +goose Up
-- +goose StatementBegin
PRAGMA jourrnal = wal;

CREATE TABLE IF NOT EXISTS Person(
    id           TEXT NOT NULL PRIMARY KEY,
    handle       TEXT NOT NULL,
    password     BLOB NOT NULL,
    salt         BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    display_name TEXT,
    email        TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ppl_email_idx ON Person(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ppl_handle_idx ON Person(handle);

CREATE TABLE IF NOT EXISTS sessions (
	token  TEXT PRIMARY KEY,
	data   BLOB NOT NULL,
	expiry REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expiry);

CREATE TABLE IF NOT EXISTS RegistrationToken (
    pid     TEXT NOT NULL PRIMARY KEY,
    email   TEXT NOT NULL,
    token   TEXT NOT NULL,
    expires TEXT NOT NULL,
    refresh TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS tok_email_idx ON RegistrationToken(email);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS tok_email_idx;
DROP TABLE IF EXISTS RegistrationToken;
DROP INDEX IF EXISTS sessions_expiry_idx;
DROP TABLE IF EXISTS sessions;
DROP INDEX IF EXISTS ppl_email_idx;
DROP INDEX IF EXISTS ppl_display_idx;
DROP TABLE IF EXISTS Person;
-- +goose StatementEnd

