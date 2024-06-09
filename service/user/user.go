package user

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/avalonbits/{{project}}/storage"
	"github.com/avalonbits/{{project}}/storage/datastore"
	"github.com/oklog/ulid"
	"golang.org/x/crypto/argon2"
)

type Service struct {
	db          *storage.DB[datastore.Queries]
	personCache *sync.Map
}

func New(db *storage.DB[datastore.Queries]) *Service {
	return &Service{
		db:          db,
		personCache: &sync.Map{},
	}
}

type Person struct {
	ID     string
	Handle string
	Name   string
	Email  string
}

func (s *Service) GetUser(ctx context.Context, uid string) (Person, error) {
	if v, ok := s.personCache.Load(uid); ok {
		return v.(Person), nil
	}

	var p datastore.Person
	err := s.db.Read(ctx, func(queries *datastore.Queries) error {
		var err error
		p, err = queries.GetPerson(ctx, uid)
		return err
	})
	return s.personFromDB(p), err
}

func (s *Service) personFromDB(p datastore.Person) Person {
	res := Person{
		ID:     p.ID,
		Handle: p.Handle,
		Name:   p.DisplayName.String,
		Email:  p.Email.String,
	}
	v, _ := s.personCache.LoadOrStore(p.ID, res)
	return v.(Person)
}

func (s *Service) Signin(ctx context.Context, handle, password string) (Person, error) {
	var p datastore.Person
	err := s.db.Read(ctx, func(queries *datastore.Queries) error {
		var err error
		p, err = queries.GetPersonByHandle(ctx, handle)
		if err != nil {
			if storage.NoRows(err) {
				return fmt.Errorf("invalid user")
			}
			return err
		}
		return nil
	})
	if err != nil {
		return Person{}, err
	}

	if !check(password, p.Password, p.Salt) {
		return Person{}, fmt.Errorf("invalid password")
	}

	return s.personFromDB(p), nil
}

func (s *Service) Signup(ctx context.Context, handle, password string) (string, error) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	uid, err := ulid.New(uint64(now.UnixMilli()), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("error creatingg user id: %w", err)
	}

	return uid.String(), s.db.Write(ctx, func(queries *datastore.Queries) error {
		_, err := queries.IsRegistered(ctx, handle)
		if err == nil {
			return fmt.Errorf("username already in use")
		}
		if !storage.NoRows(err) {
			return err
		}

		passHash, salt, err := hashPassword(password)
		if err != nil {
			return err
		}

		return queries.CreateUser(ctx, datastore.CreateUserParams{
			ID:        uid.String(),
			Handle:    handle,
			CreatedAt: nowStr,
			Password:  passHash,
			Salt:      salt,
		})
	})
}

func (s *Service) ValidateToken(ctx context.Context, uid, tk string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return s.db.Read(ctx, func(queries *datastore.Queries) error {
		regTk, err := queries.GetToken(ctx, datastore.GetTokenParams{
			Pid:     uid,
			Expires: now,
		})
		if regTk.Token != tk {
			return fmt.Errorf("invalid token")
		}
		if err != nil {
			return err
		}

		// Token validated, remove it from table and update user email.
		if err := queries.DeleteToken(ctx, uid); err != nil {
			return err
		}
		u, err := queries.SetPersonEmail(ctx, datastore.SetPersonEmailParams{
			Email: sql.NullString{String: regTk.Email, Valid: true},
			ID:    uid,
		})
		if err != nil {
			return err
		}
		s.personCache.Store(u.ID, Person{
			ID:     u.ID,
			Handle: u.Handle,
			Name:   u.DisplayName.String,
			Email:  u.Email.String,
		})
		return nil
	})
}

func hashPassword(str string) ([]byte, []byte, error) {
	salt := make([]byte, 64)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}

	if n != 64 {
		return nil, nil, errors.New("read less bytes than required for salt")
	}
	return hash(str, salt), salt, nil
}

func check(str string, passHash, salt []byte) bool {
	gotHash := hash(str, salt)
	return bytes.Equal(passHash, gotHash)
}

func hash(str string, salt []byte) []byte {
	// We want to use at most half the cpus available annd no more than 4.
	threads := min(4, max(1, uint8(runtime.NumCPU()/2)))

	return argon2.IDKey([]byte(str), salt, 4, 32*1024, threads, 64)
}
