package jwt

import jwt "github.com/golang-jwt/jwt/v4"

// StdClaims is the struct that represent StdClaims of JWT.
type StdClaims struct {
	UserID uint
	jwt.StandardClaims
}

// MapClaims is the struct that represent Claims of JWT.
type MapClaims struct {
	UserID uint
	jwt.MapClaims
}
