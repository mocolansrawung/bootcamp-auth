package user

import (
	"encoding/json"
	"time"

	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/nuuid"
	"github.com/gofrs/uuid"
	"github.com/guregu/null"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        uuid.UUID   `db:"id" validate:"required"`
	Username  string      `db:"username" validate:"required"`
	Name      string      `db:"name" validate:"required"`
	Password  string      `db:"password" validate:"required"`
	Role      string      `db:"role" validate:"required"`
	CreatedAt time.Time   `db:"created_at" validate:"required"`
	CreatedBy uuid.UUID   `db:"created_by" validate:"required"`
	UpdatedAt null.Time   `db:"updated_at"`
	UpdatedBy nuuid.NUUID `db:"updated_by"`
	DeletedAt null.Time   `db:"deleted_at"`
	DeletedBy nuuid.NUUID `db:"deleted_by"`
}

func (u *User) IsDeleted() (deleted bool) {
	return u.DeletedAt.Valid && u.DeletedBy.Valid
}

func (u User) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.ToResponseFormat())
}

// Register Request Format
func (u User) NewUserFromRequestFormat(req UserRequestFormat) (newUser User, err error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		failure.InternalError(err)
		return
	}

	hashedPassword := string(bytes)
	userID, _ := uuid.NewV4()

	newUser = User{
		ID:        userID,
		Username:  req.Username,
		Name:      req.Name,
		Password:  hashedPassword,
		Role:      req.Role,
		CreatedAt: time.Now(),
		CreatedBy: userID,
	}

	err = newUser.Validate()

	return
}

func (u *User) Validate() (err error) {
	validator := shared.GetValidator()
	return validator.Struct(u)
}

func (u User) ToResponseFormat() UserResponseFormat {
	accessToken, _ := shared.GenerateJWT(u.ID, u.Username, u.Role)

	resp := UserResponseFormat{
		ID:          u.ID,
		Username:    u.Username,
		Name:        u.Name,
		Role:        u.Role,
		AccessToken: accessToken,
		CreatedBy:   u.CreatedBy,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		UpdatedBy:   u.UpdatedBy.Ptr(),
		DeletedAt:   u.DeletedAt,
		DeletedBy:   u.DeletedBy.Ptr(),
	}

	return resp
}

type UserRequestFormat struct {
	Username string `json:"username" validate:"required"`
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required"`
	Role     string `json:"role" validate:"required"`
}

type UserResponseFormat struct {
	ID          uuid.UUID  `json:"id"`
	Username    string     `json:"username"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	AccessToken string     `json:"accessToken"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedBy   uuid.UUID  `json:"createdBy"`
	UpdatedAt   null.Time  `json:"updatedAt"`
	UpdatedBy   *uuid.UUID `json:"updatedBy"`
	DeletedAt   null.Time  `json:"deletedAt,omitempty"`
	DeletedBy   *uuid.UUID `json:"deletedBy,omitempty"`
}

// Login
type UserLogin struct {
	ID       uuid.UUID `db:"id"`
	Username string    `db:"username" validate:"required"`
	Password string    `db:"password" validate:"required"`
	Role     string    `db:"role"`
}

func (ul UserLogin) MarshalJSON() ([]byte, error) {
	return json.Marshal(ul.ToResponseFormat())
}

func (ul UserLogin) LoginUserFromRequestFormat(req LoginRequestFormat) (newLogin UserLogin, err error) {
	newLogin = UserLogin{
		Username: req.Username,
		Password: req.Password,
	}

	err = newLogin.Validate()

	return
}

func (ul *UserLogin) Validate() (err error) {
	validator := shared.GetValidator()
	return validator.Struct(ul)
}

func (ul UserLogin) ToResponseFormat() LoginResponseFormat {
	accessToken, _ := shared.GenerateJWT(ul.ID, ul.Username, ul.Role)

	resp := LoginResponseFormat{
		AccessToken: accessToken,
	}

	return resp
}

type LoginRequestFormat struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginResponseFormat struct {
	AccessToken string `json:"accessToken"`
}
