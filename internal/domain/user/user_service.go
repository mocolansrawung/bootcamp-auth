package user

import (
	"github.com/evermos/boilerplate-go/configs"
	"github.com/evermos/boilerplate-go/shared/failure"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	RegisterUser(requestFormat UserRequestFormat) (user User, err error)
	Login(requestFormat LoginRequestFormat) (ul UserLogin, err error)
}

type UserServiceImpl struct {
	UserRepository UserRepository
	Config         *configs.Config
}

func ProvideUserServiceImpl(userRepository UserRepository, config *configs.Config) *UserServiceImpl {
	s := new(UserServiceImpl)
	s.UserRepository = userRepository
	s.Config = config

	return s
}

// Register User
func (s *UserServiceImpl) RegisterUser(requestFormat UserRequestFormat) (user User, err error) {
	user, err = user.NewUserFromRequestFormat(requestFormat)
	if err != nil {
		return
	}

	if err != nil {
		return user, failure.BadRequest(err)
	}

	err = s.UserRepository.CreateUser(user)

	if err != nil {
		return
	}

	return
}

// Login
func (s *UserServiceImpl) Login(requestFormat LoginRequestFormat) (ul UserLogin, err error) {
	login, err := UserLogin{}.LoginUserFromRequestFormat(requestFormat)
	if err != nil {
		return
	}

	user, err := s.UserRepository.ResolveByUsername(login.Username)
	if err != nil {
		return
	}

	if err != nil {
		return ul, failure.NotFound("user")
	}

	isValidPassword := checkPasswordHash(login.Password, user.Password)
	if !isValidPassword {
		return ul, failure.Unauthorized("Invalid credentials")
	}

	ul.ID = user.ID
	ul.Username = user.Username
	ul.Role = user.Role

	return ul, nil
}

// Internal Functions
func checkPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
