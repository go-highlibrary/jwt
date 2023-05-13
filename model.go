package jwt

import (
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

// Claims is the struct that represent Claims of JWT.
type Claims struct {
	userID uint
	time   time.Time
	jwt.StandardClaims
	jwt.SigningMethod
}

// NewClaims return new *claims{} with necessary setup claims.
func NewClaims(time time.Time, signingMethod jwt.SigningMethod) *Claims {
	return &Claims{
		time:          time,
		SigningMethod: signingMethod,
	}
}
