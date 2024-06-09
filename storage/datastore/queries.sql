
-- name: GetPerson :one
SELECT  * FROM Person WHERE id = ? LIMIT 1;

-- name: GetPersonByEmail :one
SELECT * FROM Person WHERE email = ? LIMIT 1;

-- name: GetPersonByHandle :one
SELECT * FROM Person WHERE handle = ? LIMIT 1;

-- name: SetPersonEmail :one
UPDATE Person SET email = ? WHERE id = ? RETURNING *;

-- name: IsVerified :one
SELECT 1 = 1 from Person WHERE handle = ? AND email IS NOT NULL;

-- name: IsRegistered :one
SELECT 1 = 1 FROM Person WHERE handle = ? LIMIT 1;

-- name: IsEmailRegistered :one
SELECT 1 = 1 FROM Person WHERE email = ? LIMIT 1;

-- name: SetRegistrationToken :exec
INSERT INTO RegistrationToken (pid, email, token, expires, refresh)
       VALUES (?, ?, ?, ?, ?)
ON CONFLICT DO UPDATE SET
    email = excluded.email,
    token = excluded.token,
    expires = excluded.expires,
    refresh = excluded.refresh;

-- name: GetToken :one
SELECT * FROM RegistrationToken WHERE pid = ? AND expires > ?;

-- name: DeleteToken :exec
DELETE FROM RegistrationToken WHERE pid = ?;

-- name: DeleteExpiredTokens :exec
DELETE from RegistrationToken WHERE expires >= ?;

-- name: CreateUser :exec
INSERT INTO Person(id, handle, created_at, password, salt)
       VALUES (?, ?, ?, ?,?);
