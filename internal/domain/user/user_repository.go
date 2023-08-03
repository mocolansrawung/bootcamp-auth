package user

import (
	"database/sql"

	"github.com/evermos/boilerplate-go/infras"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/logger"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"
)

var (
	userQueries = struct {
		selectUser string
		insertUser string
	}{
		selectUser: `
			SELECT
				id,
				username,
				password,
				role, 
				created_at,
				created_by,
				updated_at,
				updated_by,
				deleted_at,
				deleted_by
			FROM users
		`,
		insertUser: `
			INSERT INTO users (
				id,
				username,
				name,
				password,
				role,
				created_at,
				created_by,
				updated_at,
				updated_by,
				deleted_at,
				deleted_by
			) VALUES (
				:id,
				:username,
				:name,
				:password,
				:role,
				:created_at,
				:created_by,
				:updated_at,
				:updated_by,
				:deleted_at,
				:deleted_by
			)
		`,
	}
)

type UserRepository interface {
	CreateUser(user User) (err error)
	ResolveByUsername(username string) (user User, err error)
}

type UserRepositoryMySQL struct {
	DB *infras.MySQLConn
}

func ProvideUserRepositoryMySQL(db *infras.MySQLConn) *UserRepositoryMySQL {
	s := new(UserRepositoryMySQL)
	s.DB = db

	return s
}

// CreateUser creates a new User
func (r *UserRepositoryMySQL) CreateUser(user User) (err error) {
	exists, err := r.ExistsByID(user.ID)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}

	if exists {
		err = failure.Conflict("create", "userId", "already exists")
		logger.ErrorWithStack(err)
		return
	}

	exists, err = r.ExistByUsername(user.Username)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}

	if exists {
		err = failure.Conflict("create", "username", "already exists")
		logger.ErrorWithStack(err)
		return
	}

	return r.DB.WithTransaction(func(tx *sqlx.Tx, e chan error) {
		if err := r.txCreate(tx, user); err != nil {
			e <- err
			return
		}

		e <- nil
	})
}

// Resolve a User by Username
func (r *UserRepositoryMySQL) ResolveByUsername(username string) (user User, err error) {
	err = r.DB.Read.Get(
		&user,
		userQueries.selectUser+" WHERE username = ?",
		username)

	if err != nil && err == sql.ErrNoRows {
		err = failure.NotFound("user")
		logger.ErrorWithStack(err)
		return
	}

	return
}

func (r *UserRepositoryMySQL) ExistsByID(id uuid.UUID) (exists bool, err error) {
	err = r.DB.Read.Get(
		&exists,
		"SELECT COUNT(id) FROM users WHERE id = ?",
		id.String())

	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}

func (r *UserRepositoryMySQL) ExistByUsername(username string) (exists bool, err error) {
	err = r.DB.Read.Get(
		&exists,
		"SELECT COUNT(username) FROM users WHERE username = ?",
		username)

	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}

// Internal Functions
func (r *UserRepositoryMySQL) txCreate(tx *sqlx.Tx, user User) (err error) {
	stmt, err := tx.PrepareNamed(userQueries.insertUser)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user)
	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}
