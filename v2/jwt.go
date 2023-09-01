package jwt

import "errors"

// Error constants.
var (
	ErrTokenInvalid = errors.New("invalid token")
	ErrTokenExpired = errors.New("expired token")
)
