package jwt

import (
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

func parseToken(signedToken, secretKey string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(
		signedToken,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("invalid signing algorithm")
			}
			return []byte(secretKey), nil
		},
	)
}

// Generate generate a new token.
func Generate(time time.Time, userID uint, secretKey string) (string, error) {
	// return jwt.NewWithClaims(claims.SigningMethod, claims).SignedString([]byte(claims.SecretKey))
	return jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		&Claims{
			UserID: userID,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Unix(),
			},
		},
	).SignedString([]byte(secretKey))
}

// IsValid fully validate if the passed token is valid.
func IsValid(signedToken, secretKey string) (bool, error) {
	token, err := parseToken(signedToken, secretKey)
	if err != nil {
		return false, err
	}
	if !token.Valid {
		return false, errors.New("invalid token")
	}
	return true, nil
}

// GetUserID get user ID inside a signed token.
func GetUserID(signedToken, secretKey string) (uint, error) {
	token, err := parseToken(signedToken, secretKey)
	if err != nil {
		return -0, err
	}
	return token.Claims.(*Claims).UserID, nil
}
