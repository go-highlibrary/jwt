package jwt

import (
	"errors"

	jwt "github.com/golang-jwt/jwt/v4"
)

// Generate generate a new token.
func (claims *Claims) Generate(userID uint, secretKey string) (string, error) {
	// return jwt.NewWithClaims(claims.SigningMethod, claims).SignedString([]byte(claims.SecretKey))
	return jwt.NewWithClaims(
		claims.SigningMethod,
		&Claims{
			userID: userID,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: claims.time.Unix(),
			},
		},
	).SignedString([]byte(secretKey))
}

// IsValid fully validate if the passed token is a valid.
func (claims *Claims) IsValid(signedToken, secretKey string) (bool, error) {
	token, err := parseToken(claims, signedToken, secretKey)
	if err != nil {
		return false, err
	}
	if !token.Valid {
		return false, errors.New("invalid token")
	}
	return true, nil
}

// GetUserID get user ID inside a signed token.
func GetUserID(signingMethod jwt.SigningMethod, signedToken, secretKey string) (uint, error) {
	token, err := parseToken(&Claims{SigningMethod: signingMethod}, signedToken, secretKey)
	if err != nil {
		return -0, err
	}
	return token.Claims.(*Claims).userID, nil
}

func parseToken(claims *Claims, signedToken, secretKey string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(
		signedToken,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != claims.SigningMethod {
				return nil, errors.New("invalid signing algorithm")
			}
			return []byte(secretKey), nil
		},
	)
}
