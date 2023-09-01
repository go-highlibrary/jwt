package jwt

import jwt "github.com/golang-jwt/jwt/v4"

func mapParseToken(signedToken, secretKey string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&MapClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		},
	)
	if err != nil {
		// if errAsserted, ok := err.(*jwt.ValidationError); ok && errors.Is(errAsserted.Inner, jwt.ErrTokenExpired) {
		if errAsserted, ok := err.(*jwt.ValidationError); ok && errAsserted.Errors == jwt.ValidationErrorExpired {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}
	return token, nil
}

// NewMapToken generate a new token.
func NewMapToken(userID uint, claims map[string]any, secretKey string) (string, error) {
	// return jwt.NewWithClaims(jwt.SigningMethodHS256, &MapClaims{UserID: userID, MapClaims: claims}).SignedString([]byte(secretKey))
	return jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		&MapClaims{
			UserID:    userID,
			MapClaims: claims,
		},
	).SignedString([]byte(secretKey))
}

// MapIsValid fully validate if the passed token is valid.
func MapIsValid(signedToken, secretKey string) (bool, error) {
	_, err := mapParseToken(signedToken, secretKey)
	if err != nil {
		return false, err
	}
	return true, nil
}

// MapGetUserID get user ID inside a signed token.
func MapGetUserID(signedToken, secretKey string) (uint, error) {
	token, err := mapParseToken(signedToken, secretKey)
	if err != nil {
		return -0, err
	}
	return token.Claims.(*MapClaims).UserID, nil
}

// MapGetKey get a claim value inside a signed token.
func MapGetKey(key, signedToken, secretKey string) (any, error) {
	token, err := mapParseToken(signedToken, secretKey)
	if err != nil {
		return nil, err
	}
	return token.Claims.(*MapClaims).MapClaims[key], nil
}

// MapRetrieveClaims return the struct claims.
func MapRetrieveClaims(signedToken, secretKey string) (*MapClaims, error) {
	token, err := mapParseToken(signedToken, secretKey)
	if err != nil {
		return nil, err
	}
	return token.Claims.(*MapClaims), nil
}
