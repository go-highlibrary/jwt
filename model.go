package jwt

import jwt "github.com/golang-jwt/jwt/v4"

// Claims is the struct that represent Claims of JWT.
type Claims struct {
	UserID uint
	jwt.StandardClaims
}
