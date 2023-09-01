package jwt

import (
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func stdParseToken(signedToken, secretKey string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&StdClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		},
	)
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, ErrTokenExpired
	} else if err != nil {
		return nil, ErrTokenInvalid
	}
	return token, nil
}

// NewStdToken generate a new token.
func NewStdToken(userID uint, time time.Time, secretKey string) (string, error) {
	// return jwt.NewWithClaims(jwt.SigningMethodHS256, &StdClaims{UserID: userID, StandardClaims: jwt.StandardClaims{ExpiresAt: time.Unix(), Id: uuid.New().String()}}).SignedString([]byte(secretKey))
	return jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		&StdClaims{
			UserID: userID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time),
				ID:        uuid.New().String(),
			},
		},
	).SignedString([]byte(secretKey))
}

// StdIsValid fully validate if the passed token is valid.
func StdIsValid(signedToken, secretKey string) (bool, error) {
	_, err := stdParseToken(signedToken, secretKey)
	if err != nil {
		return false, err
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
