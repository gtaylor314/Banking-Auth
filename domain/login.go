package domain

import (
	"database/sql"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Login struct {
	Username    string         `db:"username"`
	Customer_ID sql.NullString `db:"customer_id"`
	Accounts    sql.NullString `db:"account_numbers"`
	Role        string         `db:"role"`
}

func (l Login) ClaimsForAccessTokens() AccessTokenClaims {
	// sql.NullString's Valid property is true if the string property is not null, in other words, if there is a customer id
	// and at least one account id (meaning neither string is empty) then the access token is for a user
	if l.Customer_ID.Valid && l.Accounts.Valid {
		return l.claimsForUser()
	}
	return l.claimsForAdmin()
}

func (l Login) claimsForUser() AccessTokenClaims {
	// token claims for a user will include a customer id and at least one account id
	return AccessTokenClaims{
		Customer_ID: l.Customer_ID.String,
		// strings.Split() separates the string l.Accounts.String at the comma and returns the resulting slice of strings
		Accounts: strings.Split(l.Accounts.String, ","),
		Username: l.Username,
		Role:     l.Role,
		// standard time is in epoch time - we use .Unix() to convert the time to Unix time
		StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix()},
	}
}

func (l Login) claimsForAdmin() AccessTokenClaims {
	return AccessTokenClaims{
		Username:       l.Username,
		Role:           l.Role,
		StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix()},
	}
}
