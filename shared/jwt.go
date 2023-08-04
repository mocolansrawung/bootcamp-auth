package shared

import (
	"fmt"

	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
)

type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	jwt.StandardClaims
}

type JWTService struct {
	Secret string
}

func ProvideJWTService(secret string) *JWTService {
	return &JWTService{
		Secret: secret,
	}
}

func (j *JWTService) GenerateJWT(userID uuid.UUID, username string, role string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer:    "bootcamp",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWTService) ValidateJWT(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.Secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %v", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("JWT is not valid")
}
