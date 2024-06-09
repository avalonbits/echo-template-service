package datastore

import (
	"embed"

	"github.com/avalonbits/echo-template-service/storage"
)

//go:embed migrations/*
var Migrations embed.FS

func Factory(tx storage.DBTX) *Queries {
	return New(tx)
}
