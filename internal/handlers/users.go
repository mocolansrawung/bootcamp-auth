package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/evermos/boilerplate-go/internal/domain/user"
	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/transport/http/middleware"
	"github.com/evermos/boilerplate-go/transport/http/response"
	"github.com/go-chi/chi"
)

type UserHandler struct {
	UserService    user.UserService
	AuthMiddleware *middleware.Authentication
}

func ProvideUserHandler(userService user.UserService) UserHandler {
	return UserHandler{
		UserService: userService,
	}
}

func (h *UserHandler) Router(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Post("/register", h.RegisterUser)
			r.Post("/login", h.LoginUser)
			r.Get("/validate", h.ValidateAuth)
		})
	})
}

func (h *UserHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var requestFormat user.UserRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	err = shared.GetValidator().Struct(requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	user, err := h.UserService.RegisterUser(requestFormat)
	if err != nil {
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusCreated, user)
}

func (h *UserHandler) LoginUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var requestFormat user.LoginRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	err = shared.GetValidator().Struct(requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	ul, err := h.UserService.Login(requestFormat)
	if err != nil {
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusOK, ul)
}

func (h *UserHandler) ValidateAuth(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	user, err := h.UserService.ParseTokenFromAuthHeader(authHeader)
	if err != nil {
		response.WithError(w, failure.Unauthorized("Token not authorized"))
		return
	}

	response.WithJSON(w, http.StatusOK, user)
}
