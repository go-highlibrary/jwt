package jwt

import (
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func stdParseToken(signedToken, secretKey string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(
		signedToken,
		&StdClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("invalid signing algorithm")
			}
			return []byte(secretKey), nil
		},
	)
}

// NewStdToken generate a new token.
func NewStdToken(userID uint, time time.Time, secretKey string) (string, error) {
	// return jwt.NewWithClaims(jwt.SigningMethodHS256, &StdClaims{UserID: userID, StandardClaims: jwt.StandardClaims{ExpiresAt: time.Unix(), Id: uuid.New().String()}}).SignedString([]byte(secretKey))
	return jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		&StdClaims{
			UserID: userID,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Unix(),
				Id:        uuid.New().String(),
			},
		},
	).SignedString([]byte(secretKey))
}

// StdIsValid fully validate if the passed token is valid.
func StdIsValid(signedToken, secretKey string) (bool, error) {
	token, err := stdParseToken(signedToken, secretKey)
	if err != nil {
		return false, err
	}
	if !token.Valid {
		return false, errors.New("invalid token")
	}
	return true, nil
}

// StdGetUserID get user ID inside a signed token.
func StdGetUserID(signedToken, secretKey string) (uint, error) {
	token, err := stdParseToken(signedToken, secretKey)
	if err != nil {
		return -0, err
	}
	return token.Claims.(*StdClaims).UserID, nil
}
