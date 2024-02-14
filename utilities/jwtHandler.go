package utilities

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("practices")

func CreateToken(objectString string, duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"token_details": objectString,
		"exp":           time.Now().Add(duration).Unix(),
	})

	tokenString, err := token.SignedString(secretKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}
