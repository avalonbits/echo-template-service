// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package datastore

import (
	"database/sql"
)

type Person struct {
	ID          string
	Handle      string
	Password    []byte
	Salt        []byte
	CreatedAt   string
	DisplayName sql.NullString
	Email       sql.NullString
}

type RegistrationToken struct {
	Pid     string
	Email   string
	Token   string
	Expires string
	Refresh string
}

type Session struct {
	Token  string
	Data   []byte
	Expiry float64
}