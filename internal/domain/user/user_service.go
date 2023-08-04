package user

import (
	"github.com/evermos/boilerplate-go/configs"
	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	RegisterUser(requestFormat UserRequestFormat) (accessToken string, err error)
	Login(requestFormat LoginRequestFormat) (accessToken string, err error)
	ResolveByUsername(username string) (user User, err error)
	Update(id uuid.UUID, requestFormat UserRequestFormat, userID uuid.UUID) (user User, err error)
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

func (s *UserServiceImpl) RegisterUser(requestFormat UserRequestFormat) (accessToken string, err error) {
	var user User
	user, err = user.NewUserFromRequestFormat(requestFormat)
	if err != nil {
		return "", err
	}

	err = s.UserRepository.CreateUser(user)
	if err != nil {
		return "", err
	}

	accessToken, err = s.createToken(user)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *UserServiceImpl) Login(requestFormat LoginRequestFormat) (accessToken string, err error) {
	login, err := UserLogin{}.LoginUserFromRequestFormat(requestFormat)
	if err != nil {
		return "", err
	}

	user, err := s.UserRepository.ResolveByUsername(login.Username)
	if err != nil {
		return "", err
	}

	isValidPassword := checkPasswordHash(login.Password, user.Password)
	if !isValidPassword {
		return "", failure.Unauthorized("Invalid credentials")
	}

	accessToken, err = s.createToken(user)
	if err != nil {
		return "", failure.InternalError(err)
	}

	return accessToken, nil
}

func (s *UserServiceImpl) ResolveByUsername(username string) (user User, err error) {
	user, err = s.UserRepository.ResolveByUsername(username)

	if user.IsDeleted() {
		return user, failure.NotFound("user")
	}

	return
}

func (s *UserServiceImpl) Update(id uuid.UUID, requestFormat UserRequestFormat, userID uuid.UUID) (user User, err error) {
	user, err = s.UserRepository.ResolveByID(id)
	if err != nil {
		return
	}

	err = user.Update(requestFormat, userID)
	if err != nil {
		return
	}

	err = s.UserRepository.Update(user)
	return
}

// Internal Functions
func checkPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (s *UserServiceImpl) createToken(user User) (accessToken string, err error) {
	jwtService := shared.ProvideJWTService(s.Config.App.Secret)
	accessToken, err = jwtService.GenerateJWT(user.ID, user.Username, user.Role)
	if err != nil {
		return
	}

	return
}
