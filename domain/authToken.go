package domain

import (
	"github.com/gtaylor314/Banking-Lib/errs"
	"github.com/gtaylor314/Banking-Lib/logger"

	"github.com/golang-jwt/jwt/v4"
)

type AuthToken struct {
	token *jwt.Token
}

// NewAccessToken() returns a completed and signed JWT
func (auth AuthToken) NewAccessToken() (string, *errs.AppError) {
	// SignedString() creates and returns a complete, signed JWT - HMAC_Sample_Secret is defined in claims.go
	signString, err := auth.token.SignedString([]byte(HMAC_Sample_Secret))
	if err != nil {
		logger.Error("error while signing JWT token " + err.Error())
		// return the empty string and an unexpected error
		return "", errs.UnexpectedErr("unexpected error while signing token")
	}
	// if no error, return signed string and no error
	return signString, nil
}

// NewAuthToken() creates a new JWT token using HS256 signing method and the claims passed in - an AuthToken is returned with
// the token field set to the created token
func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token: token}
}
