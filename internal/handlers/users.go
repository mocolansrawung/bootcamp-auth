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
	"github.com/gofrs/uuid"
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

	r.Route("/profile", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(h.AuthMiddleware.ClientCredentialWithJWT)
			r.Get("/", h.GetProfile)
			r.Put("/", h.UpdateProfile)
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
	claims, err := h.UserService.ParseTokenFromAuthHeader(authHeader)
	if err != nil {
		response.WithError(w, failure.Unauthorized("Token not authorized"))
		return
	}

	response.WithJSON(w, http.StatusOK, claims)
}

func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	user, err := h.UserService.ResolveByUsername(username)
	if err != nil {
		response.WithError(w, failure.NotFound("user"))
		return
	}

	response.WithJSON(w, http.StatusOK, user)
}

func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(uuid.UUID)

	decoder := json.NewDecoder(r.Body)
	var requestFormat user.UserRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	user, err := h.UserService.Update(userID, requestFormat, userID)
	if err != nil {
		response.WithError(w, failure.InternalError(err))
		return
	}

	response.WithJSON(w, http.StatusOK, user)
}
