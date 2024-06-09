package datastore

import (
	"embed"

	"github.com/avalonbits/{{project}}/storage"
)

//go:embed migrations/*
var Migrations embed.FS

func Factory(tx storage.DBTX) *Queries {
	return New(tx)
}
