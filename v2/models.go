package jwt

import jwt "github.com/golang-jwt/jwt/v5"

// StdClaims is the struct that represent RegisteredClaims of JWT.
type StdClaims struct {
	UserID uint
	jwt.RegisteredClaims
}

// MapClaims is the struct that represent MapClaims of JWT.
type MapClaims struct {
	UserID uint
	jwt.MapClaims
}
