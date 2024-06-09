package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sync"

	"github.com/pressly/goose/v3"

	_ "github.com/mattn/go-sqlite3"
)

type DBTX interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type DB[Queries any] struct {
	factory func(tx DBTX) *Queries
	rddb    *sql.DB

	mu   *sync.Mutex
	wrdb *sql.DB
}

const (
	readDSN  = "%s?_journal=wal&_sync=1&_busy_timeout=5000&_cache_size=10000&_txlock=deferred"
	writeDSN = "%s?_journal=wal&_sync=1&_busy_timeout=5000&_cache_size=10000&_txlock=immediate"
)

func TestDB[Queries any](migrations embed.FS, factory func(tx DBTX) *Queries) *DB[Queries] {
	db, err := sql.Open("sqlite3", fmt.Sprintf(writeDSN, ":memory:"))
	if err != nil {
		panic(err)
	}
	goose.SetBaseFS(migrations)
	if err := goose.SetDialect("sqlite"); err != nil {
		db.Close()
		panic(err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		db.Close()
		panic(err)
	}
	return &DB[Queries]{factory: factory, rddb: db, mu: &sync.Mutex{}, wrdb: db}
}

func GetDB[Queries any](
	dbName string, migrations embed.FS, factory func(tx DBTX) *Queries) (*DB[Queries], error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf(writeDSN, dbName))
	if err != nil {
		return nil, err
	}

	goose.SetBaseFS(migrations)
	if err := goose.SetDialect("sqlite"); err != nil {
		db.Close()
		return nil, err
	}

	if err := goose.Up(db, "migrations"); err != nil {
		db.Close()
		return nil, err
	}
	db.Close()

	wrdb, err := sql.Open("sqlite3", fmt.Sprintf(writeDSN, dbName))
	if err != nil {
		return nil, err
	}
	wrdb.SetMaxOpenConns(1)

	rddb, err := sql.Open("sqlite3", fmt.Sprintf(readDSN, dbName))
	if err != nil {
		wrdb.Close()
		return nil, err
	}
	return &DB[Queries]{factory: factory, rddb: rddb, mu: &sync.Mutex{}, wrdb: wrdb}, nil
}

func (db *DB[Queries]) RDBMS() *sql.DB {
	return db.wrdb
}

func (db *DB[Queries]) Close() error {
	return errors.Join(db.rddb.Close(), db.wrdb.Close())
}

func (db *DB[Queries]) Read(ctx context.Context, f func(queries *Queries) error) error {
	return db.transaction(ctx, db.rddb, f)
}

func (db *DB[Queries]) Write(ctx context.Context, f func(queries *Queries) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.transaction(ctx, db.wrdb, f)
}

func (db *DB[Queries]) transaction(ctx context.Context, rdbms *sql.DB, f func(queries *Queries) error) error {
	tx, err := rdbms.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error creating transaction: %w", err)
	}

	if err := f(db.factory(tx)); err != nil {
		rbErr := tx.Rollback()
		if rbErr != nil {
			err = errors.Join(err, rbErr)
		}
		return err
	}
	return tx.Commit()
}

func NoRows(err error) bool {
	return err != nil && errors.Is(err, sql.ErrNoRows)
}
